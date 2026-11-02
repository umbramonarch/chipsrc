//! `chipsrc-core` — Multi-language AST extraction, static call-graph,
//! code + hardware cross-reference graph, and Agent Codebase Bundle engine.

pub mod emitter;
pub mod error;
pub mod graph;
pub mod mmio;
pub mod model;
pub mod parser;
pub mod query;
pub mod resolver;
pub mod sanity;
pub mod scanner;
pub mod sharder;

pub use crate::error::{ChipsrcError, Result};
pub use crate::model::*;

use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Inspects a repository's language breakdown, first-party vs. vendor SDK file counts,
/// line counts, and detected architectural layers without writing a bundle to disk.
pub fn inspect_repo(repo_path: &Path, vendor_mode: VendorMode) -> Result<InspectReport> {
    let (scanned_files, fingerprint) =
        scanner::scan_repository(repo_path, vendor_mode, DEFAULT_MAX_FILE_BYTES)?;
    let (source_root, repo_name) = scanner::canonical_repo_root_and_name(repo_path);
    let (blueprint_opt, blueprint_error) = match scanner::load_repo_blueprint_result(repo_path) {
        Ok(opt) => (opt, None),
        Err(err) => (None, Some(err)),
    };
    let (has_blueprint, unclassified_dirs, detected_workspaces, candidate_c_macros) =
        scanner::analyze_onboarding_signals(
            repo_path,
            &scanned_files,
            blueprint_opt.as_ref().map(|(bp, _)| bp),
        );

    let total_files = scanned_files.len();
    let first_party_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::FirstParty)
        .count();
    let vendor_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::VendorSdk)
        .count();
    let test_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::Test)
        .count();
    let total_lines: usize = scanned_files.iter().map(|f| f.line_count).sum();
    let languages = compute_language_stats(&scanned_files);

    let mut layer_set: BTreeSet<ArchLayer> = BTreeSet::new();
    for f in &scanned_files {
        layer_set.insert(f.arch_layer);
    }
    let mut layers_vec: Vec<ArchLayer> = layer_set.into_iter().collect();
    layers_vec.sort_by(|a, b| {
        b.rank()
            .cmp(&a.rank())
            .then_with(|| a.as_str().cmp(b.as_str()))
    });
    let detected_layers = layers_vec
        .into_iter()
        .map(|l| l.as_str().to_string())
        .collect();

    Ok(InspectReport {
        repo_name,
        source_root,
        fingerprint,
        total_files,
        first_party_files,
        vendor_files,
        test_files,
        total_lines,
        languages,
        detected_layers,
        has_blueprint,
        blueprint_error,
        unclassified_dirs,
        detected_workspaces,
        candidate_c_macros,
    })
}

/// Returns `true` when two parsed units for the same file have identical line coordinates
/// and docstrings for every extracted symbol, type, macro, call, and xref (meaning no line
/// numbers or rendered Markdown skeletons shifted).
fn units_have_identical_coordinates(old_u: &ParsedFileUnit, new_u: &ParsedFileUnit) -> bool {
    if old_u.symbols.len() != new_u.symbols.len()
        || old_u.types.len() != new_u.types.len()
        || old_u.macros.len() != new_u.macros.len()
        || old_u.raw_calls.len() != new_u.raw_calls.len()
        || old_u.raw_xrefs.len() != new_u.raw_xrefs.len()
    {
        return false;
    }
    let syms_eq = old_u.symbols.iter().zip(&new_u.symbols).all(|(a, b)| {
        a.symbol_id == b.symbol_id
            && a.start_line == b.start_line
            && a.end_line == b.end_line
            && a.doc_summary == b.doc_summary
    });
    if !syms_eq {
        return false;
    }
    let types_eq = old_u.types.iter().zip(&new_u.types).all(|(a, b)| {
        a.name == b.name
            && a.start_line == b.start_line
            && a.end_line == b.end_line
            && a.doc_summary == b.doc_summary
    });
    if !types_eq {
        return false;
    }
    let macros_eq = old_u
        .macros
        .iter()
        .zip(&new_u.macros)
        .all(|(a, b)| a.name == b.name && a.line == b.line && a.description == b.description);
    if !macros_eq {
        return false;
    }
    let calls_eq = old_u
        .raw_calls
        .iter()
        .zip(&new_u.raw_calls)
        .all(|(a, b)| a.call_line == b.call_line && a.callee_name == b.callee_name);
    if !calls_eq {
        return false;
    }
    old_u
        .raw_xrefs
        .iter()
        .zip(&new_u.raw_xrefs)
        .all(|(a, b)| a.line == b.line && a.target_name == b.target_name)
}

/// Line/strings translation for one dirty file: old line number -> new line number plus the
/// refreshed macro docstring context rendered into `index/xref.tsv`.
struct DirtyFileMaps {
    old_to_new_line: FxHashMap<usize, usize>,
    new_symbol_start_to_old: FxHashMap<(String, usize), usize>,
    macro_contexts: FxHashMap<String, String>,
}

/// Builds line-number translations by zipping every extracted list of the old and new units.
///
/// A structural digest match guarantees the same entities in the same order, so index `i` of
/// every per-file list refers to the same entity. Returns `None` when the two units disagree on
/// list lengths/identities or when one old line maps to conflicting new lines (a non-monotonic
/// restructure the coordinate-shift tier cannot reproduce 1:1).
fn build_dirty_file_maps(old_u: &ParsedFileUnit, new_u: &ParsedFileUnit) -> Option<DirtyFileMaps> {
    if old_u.symbols.len() != new_u.symbols.len()
        || old_u.types.len() != new_u.types.len()
        || old_u.macros.len() != new_u.macros.len()
        || old_u.raw_calls.len() != new_u.raw_calls.len()
        || old_u.raw_xrefs.len() != new_u.raw_xrefs.len()
    {
        return None;
    }

    let mut old_to_new_line: FxHashMap<usize, usize> = FxHashMap::default();
    let mut insert = |old_line: usize, new_line: usize| -> Option<()> {
        match old_to_new_line.entry(old_line) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                if *entry.get() != new_line {
                    None
                } else {
                    Some(())
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(new_line);
                Some(())
            }
        }
    };

    let mut new_symbol_start_to_old: FxHashMap<(String, usize), usize> = FxHashMap::default();
    for (old, new) in old_u.symbols.iter().zip(&new_u.symbols) {
        if old.symbol_id != new.symbol_id {
            return None;
        }
        insert(old.start_line, new.start_line)?;
        insert(old.end_line, new.end_line)?;
        let key = (new.symbol_id.clone(), new.start_line);
        match new_symbol_start_to_old.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                if *entry.get() != old.start_line {
                    return None;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(old.start_line);
            }
        }
    }
    for (old, new) in old_u.types.iter().zip(&new_u.types) {
        if old.type_id != new.type_id {
            return None;
        }
        insert(old.start_line, new.start_line)?;
        insert(old.end_line, new.end_line)?;
    }
    let mut macro_contexts: FxHashMap<String, String> = FxHashMap::default();
    for (old, new) in old_u.macros.iter().zip(&new_u.macros) {
        if old.name != new.name {
            return None;
        }
        insert(old.line, new.line)?;
        macro_contexts.insert(new.name.clone(), render_macro_xref_context(new));
    }
    for (old, new) in old_u.raw_calls.iter().zip(&new_u.raw_calls) {
        insert(old.call_line, new.call_line)?;
    }
    for (old, new) in old_u.raw_xrefs.iter().zip(&new_u.raw_xrefs) {
        insert(old.line, new.line)?;
    }

    Some(DirtyFileMaps {
        old_to_new_line,
        new_symbol_start_to_old,
        macro_contexts,
    })
}

/// Renders the `index/xref.tsv` context column for a macro definition exactly like the resolver.
fn render_macro_xref_context(m: &ExtractedMacro) -> String {
    if m.description.is_empty() {
        m.value_or_args.clone()
    } else if m.value_or_args.is_empty() {
        m.description.clone()
    } else {
        format!("{} ({})", m.value_or_args, m.description)
    }
}

/// Pure eligibility check for the coordinate-shift tier (Tier 3).
///
/// Every dirty file must keep its structural digest, scope, and architecture layer, must not be
/// C/C++ (header-prototype doc transfer can change other files' docstrings), and must stay below
/// the sharder's 1,400-line single-file threshold in both states. Every module group containing a
/// dirty file must stay below the 3,000-line / 8-file group thresholds, and no files may have been
/// added or removed. C/C++ is excluded because `merge_c_family_header_prototypes` can propagate a
/// header docstring into an implementation file that this tier does not rewrite.
fn coordinate_shift_eligible(
    old_dirty_units: &[ParsedFileUnit],
    new_dirty_units: &[ParsedFileUnit],
    all_units: &[ParsedFileUnit],
    manifest: &CacheManifest,
    scanned_file_count: usize,
) -> bool {
    if new_dirty_units.is_empty()
        || old_dirty_units.len() != new_dirty_units.len()
        || manifest.files.len() != scanned_file_count
    {
        return false;
    }

    let mut old_line_counts: FxHashMap<&str, usize> = FxHashMap::default();
    for (old_u, new_u) in old_dirty_units.iter().zip(new_dirty_units) {
        if old_u.scanned.rel_path != new_u.scanned.rel_path
            || old_u.scanned.scope != new_u.scanned.scope
            || old_u.scanned.arch_layer != new_u.scanned.arch_layer
        {
            return false;
        }
        let Some(entry) = manifest.files.get(&new_u.scanned.rel_path) else {
            return false;
        };
        if entry.structural_digest.is_empty()
            || entry.structural_digest != new_u.structural_digest()
        {
            return false;
        }
        if matches!(new_u.scanned.language, LanguageKind::C | LanguageKind::Cpp) {
            return false;
        }
        if old_u.scanned.line_count >= sharder::LARGE_SINGLE_FILE_LINES
            || new_u.scanned.line_count >= sharder::LARGE_SINGLE_FILE_LINES
        {
            return false;
        }
        old_line_counts.insert(new_u.scanned.rel_path.as_str(), old_u.scanned.line_count);
    }

    sharder::coordinate_shift_grouping_stable(all_units, &old_line_counts)
}

/// Parses `index/calls.tsv` back into `ResolvedCallEdge` rows (header included).
fn parse_linked_calls(content: &str, expected_rows: usize) -> Option<Vec<ResolvedCallEdge>> {
    let mut rows = Vec::with_capacity(expected_rows);
    for line in content.lines().skip(1) {
        let mut cols = line.split('\t');
        let caller_id = cols.next()?;
        let caller_name = cols.next()?;
        let callee_name = cols.next()?;
        let callee_id = cols.next()?;
        let file = cols.next()?;
        let line_no: usize = cols.next()?.parse().ok()?;
        let tier = ResolutionTier::parse_label(cols.next()?)?;
        let section_id = cols.next()?;
        if cols.next().is_some() {
            return None;
        }
        rows.push(ResolvedCallEdge {
            caller_id: caller_id.to_string(),
            caller_name: caller_name.to_string(),
            callee_name: callee_name.to_string(),
            callee_id: callee_id.to_string(),
            file: file.to_string(),
            line: line_no,
            tier,
            section_id: section_id.to_string(),
        });
    }
    Some(rows)
}

/// Parses `index/xref.tsv` back into `XrefEntry` rows (header included).
fn parse_linked_xrefs(content: &str, expected_rows: usize) -> Option<Vec<XrefEntry>> {
    let mut rows = Vec::with_capacity(expected_rows);
    for line in content.lines().skip(1) {
        let mut cols = line.split('\t');
        let symbol = cols.next()?;
        let category = cols.next()?;
        let relation = cols.next()?;
        let target = cols.next()?;
        let file = cols.next()?;
        let line_no: usize = cols.next()?.parse().ok()?;
        let section_id = cols.next()?;
        let context = cols.next()?;
        if cols.next().is_some() {
            return None;
        }
        rows.push(XrefEntry {
            symbol: symbol.to_string(),
            category: category.to_string(),
            relation: relation.to_string(),
            target: target.to_string(),
            file: file.to_string(),
            line: line_no,
            section_id: section_id.to_string(),
            context: context.to_string(),
        });
    }
    Some(rows)
}

/// Verifies rows stay in the resolver's deterministic order after line re-coordination, so the
/// reconstructed tables serialize byte-identically to a full relink.
fn calls_strictly_sorted(calls: &[ResolvedCallEdge]) -> bool {
    calls.windows(2).all(|w| {
        let cmp = w[0]
            .file
            .cmp(&w[1].file)
            .then_with(|| w[0].line.cmp(&w[1].line))
            .then_with(|| w[0].caller_id.cmp(&w[1].caller_id))
            .then_with(|| w[0].callee_name.cmp(&w[1].callee_name))
            .then_with(|| w[0].callee_id.cmp(&w[1].callee_id));
        cmp == std::cmp::Ordering::Less
    })
}

fn xrefs_strictly_sorted(xrefs: &[XrefEntry]) -> bool {
    xrefs.windows(2).all(|w| {
        let cmp = w[0]
            .file
            .cmp(&w[1].file)
            .then_with(|| w[0].line.cmp(&w[1].line))
            .then_with(|| w[0].symbol.cmp(&w[1].symbol))
            .then_with(|| w[0].category.cmp(&w[1].category))
            .then_with(|| w[0].relation.cmp(&w[1].relation))
            .then_with(|| w[0].target.cmp(&w[1].target));
        cmp == std::cmp::Ordering::Less
    })
}

/// Re-numbers section ids on god nodes, entrypoints, and the vendor surface after sharding and
/// drops references to symbols the sharder compacted away.
fn synchronize_indexed_sections(
    ranked_symbols: &[RankedSymbol],
    god_nodes: &mut Vec<RankedSymbol>,
    entrypoints: &mut Vec<RankedSymbol>,
    types: &[ExtractedType],
    macros: &[ExtractedMacro],
    vendor_surface: &mut VendorSurfaceSummary,
) {
    let sym_map: rustc_hash::FxHashMap<&str, &RankedSymbol> = ranked_symbols
        .iter()
        .map(|rs| (rs.symbol.symbol_id.as_str(), rs))
        .collect();
    god_nodes.retain_mut(|gn| {
        if let Some(&rs) = sym_map.get(gn.symbol.symbol_id.as_str()) {
            gn.symbol.section_id = rs.symbol.section_id.clone();
            true
        } else {
            false
        }
    });
    entrypoints.retain_mut(|ep| {
        if let Some(&rs) = sym_map.get(ep.symbol.symbol_id.as_str()) {
            ep.symbol.section_id = rs.symbol.section_id.clone();
            true
        } else {
            false
        }
    });

    if !vendor_surface.active_vendor_headers.is_empty()
        || !vendor_surface.active_vendor_symbols.is_empty()
    {
        let retained_vendor_files: BTreeSet<&str> = ranked_symbols
            .iter()
            .filter(|s| s.symbol.scope == FileScope::VendorSdk)
            .map(|s| s.symbol.file.as_str())
            .chain(
                types
                    .iter()
                    .filter(|t| t.scope == FileScope::VendorSdk)
                    .map(|t| t.file.as_str()),
            )
            .chain(
                macros
                    .iter()
                    .filter(|m| m.scope == FileScope::VendorSdk)
                    .map(|m| m.file.as_str()),
            )
            .collect();
        vendor_surface
            .active_vendor_headers
            .retain(|f| retained_vendor_files.contains(f.as_str()));

        let retained_vendor_names: BTreeSet<&str> = ranked_symbols
            .iter()
            .filter(|s| s.symbol.scope == FileScope::VendorSdk)
            .map(|s| s.symbol.name.as_str())
            .chain(
                types
                    .iter()
                    .filter(|t| t.scope == FileScope::VendorSdk)
                    .map(|t| t.name.as_str()),
            )
            .chain(
                macros
                    .iter()
                    .filter(|m| m.scope == FileScope::VendorSdk)
                    .map(|m| m.name.as_str()),
            )
            .collect();
        vendor_surface
            .active_vendor_symbols
            .retain(|n| retained_vendor_names.contains(n.as_str()));
    }
}

/// Builds per-file freshness stamps from the freshly scanned file list.
fn build_file_stamps(scanned_files: &[ScannedFile]) -> Vec<FileStamp> {
    scanned_files
        .iter()
        .map(|f| FileStamp {
            rel_path: f.rel_path.clone(),
            size_bytes: f.size_bytes,
            mtime_secs: f.mtime_secs,
            mtime_nanos: f.mtime_nanos,
            line_count: f.line_count,
            blake3_hash: f.blake3_hash.clone(),
            scope: f.scope,
            arch_layer: f.arch_layer,
        })
        .collect()
}

/// Attempts the coordinate-shift tier (Tier 3): rebuild the linked state persisted in
/// `cache/graph_state.json` 1:1 for line/docstring shifts, then re-run the sharder and emitter
/// without executing `resolve_and_link` or `analyze_graph` (`link_ms` / `graph_ms` stay 0).
///
/// Returns `Ok(None)` whenever the bundle cannot be reconstructed exactly (missing, truncated, or
/// version-mismatched graph state; unparsable index tables; mapping conflicts; shard-shape drift).
/// The caller then falls back to the full structural path, which always yields a `--force`-
/// identical bundle.
#[allow(clippy::too_many_arguments)]
fn try_coordinate_shift_tier(
    config: &ConvertConfig,
    repo_name: &str,
    source_root: &str,
    fingerprint: &str,
    blueprint_hash: &str,
    existing_meta: &BundleMetaFile,
    scanned_files: &[ScannedFile],
    all_units: &[ParsedFileUnit],
    old_dirty_units: &[ParsedFileUnit],
    dirty_units: &[ParsedFileUnit],
    incremental_reused_files: usize,
    incremental_reparsed_files: usize,
    scan_ms: u64,
    parse_ms: u64,
    start: Instant,
) -> Result<Option<ConversionBundle>> {
    let output_dir = &config.output_dir;

    // 1. Load and validate the persisted linked-graph state.
    let Some(graph_state) = emitter::load_graph_state(output_dir) else {
        return Ok(None);
    };
    if graph_state.schema_version != CACHE_SCHEMA_VERSION
        || graph_state.vendor_mode != config.vendor_mode
        || graph_state.symbols.len() != existing_meta.metadata.symbol_count
        || graph_state.god_nodes.len() != existing_meta.metadata.god_node_count
        || graph_state.entrypoints.len() != existing_meta.metadata.entrypoint_count
    {
        return Ok(None);
    }

    // 2. Recover the linked call/xref tables and re-coordinate their line columns.
    let Ok(calls_tsv) = query::load_index_table(output_dir, "calls.tsv") else {
        return Ok(None);
    };
    let Ok(xrefs_tsv) = query::load_index_table(output_dir, "xref.tsv") else {
        return Ok(None);
    };
    let Some(mut calls) = parse_linked_calls(&calls_tsv, existing_meta.metadata.call_edge_count)
    else {
        return Ok(None);
    };
    let Some(mut xrefs) = parse_linked_xrefs(&xrefs_tsv, existing_meta.metadata.xref_count) else {
        return Ok(None);
    };
    if calls.len() != existing_meta.metadata.call_edge_count
        || xrefs.len() != existing_meta.metadata.xref_count
    {
        return Ok(None);
    }

    let mut file_maps: FxHashMap<&str, DirtyFileMaps> = FxHashMap::default();
    for (old_u, new_u) in old_dirty_units.iter().zip(dirty_units) {
        let Some(maps) = build_dirty_file_maps(old_u, new_u) else {
            return Ok(None);
        };
        file_maps.insert(new_u.scanned.rel_path.as_str(), maps);
    }

    for call in &mut calls {
        if let Some(maps) = file_maps.get(call.file.as_str()) {
            let Some(&new_line) = maps.old_to_new_line.get(&call.line) else {
                return Ok(None);
            };
            call.line = new_line;
        }
    }
    for xref in &mut xrefs {
        if let Some(maps) = file_maps.get(xref.file.as_str()) {
            let Some(&new_line) = maps.old_to_new_line.get(&xref.line) else {
                return Ok(None);
            };
            xref.line = new_line;
            if xref.category == "macro_def" {
                let Some(context) = maps.macro_contexts.get(&xref.symbol) else {
                    return Ok(None);
                };
                xref.context.clone_from(context);
            }
        }
    }
    if !calls_strictly_sorted(&calls) || !xrefs_strictly_sorted(&xrefs) {
        return Ok(None);
    }

    // 3. Rebuild symbol/type/macro tables from the authoritative parsed units (the same
    //    deterministic collection used by `resolve_and_link`) and re-attach graph metrics by
    //    `(symbol_id, previous start_line)`.
    let (symbols, mut types, mut macros) = resolver::collect_symbol_tables(all_units);
    let mut annotation_indices: FxHashMap<(&str, usize), usize> = FxHashMap::default();
    for (idx, annotation) in graph_state.symbols.iter().enumerate() {
        if annotation_indices
            .insert((annotation.symbol_id.as_str(), annotation.start_line), idx)
            .is_some()
        {
            return Ok(None);
        }
    }

    let mut used_annotations = vec![false; graph_state.symbols.len()];
    let mut ranked_symbols: Vec<RankedSymbol> = Vec::with_capacity(symbols.len());
    let mut old_start_lines: Vec<usize> = Vec::with_capacity(symbols.len());
    for mut symbol in symbols {
        let old_start_line = match file_maps.get(symbol.file.as_str()) {
            Some(maps) => match maps
                .new_symbol_start_to_old
                .get(&(symbol.symbol_id.clone(), symbol.start_line))
            {
                Some(&old) => old,
                None => return Ok(None),
            },
            None => symbol.start_line,
        };

        let ranked = match annotation_indices
            .get(&(symbol.symbol_id.as_str(), old_start_line))
            .copied()
        {
            Some(idx) => {
                used_annotations[idx] = true;
                let annotation = &graph_state.symbols[idx];
                if annotation.is_entrypoint && symbol.kind == SymbolKind::Function {
                    symbol.kind = SymbolKind::Entrypoint;
                }
                RankedSymbol {
                    symbol,
                    pagerank: annotation.pagerank,
                    hub_score: annotation.hub_score,
                    authority_score: annotation.authority_score,
                    in_degree: annotation.in_degree,
                    out_degree: annotation.out_degree,
                    is_god_node: annotation.is_god_node,
                    is_entrypoint: annotation.is_entrypoint,
                    scc_id: annotation.scc_id,
                }
            }
            // Vendor symbols pruned by the previous bundle's active-surface compaction were not
            // persisted; they carry zero in-degree and are pruned again by the sharder.
            None if symbol.scope == FileScope::VendorSdk
                && config.vendor_mode == VendorMode::Active =>
            {
                RankedSymbol {
                    symbol,
                    pagerank: 0.0,
                    hub_score: 0.0,
                    authority_score: 0.0,
                    in_degree: 0,
                    out_degree: 0,
                    is_god_node: false,
                    is_entrypoint: false,
                    scc_id: None,
                }
            }
            None => return Ok(None),
        };
        old_start_lines.push(old_start_line);
        ranked_symbols.push(ranked);
    }
    if used_annotations.iter().any(|used| !used) {
        return Ok(None);
    }

    let mut ranked_by_old_start: FxHashMap<(&str, usize), usize> = FxHashMap::default();
    for (idx, rs) in ranked_symbols.iter().enumerate() {
        ranked_by_old_start.insert((rs.symbol.symbol_id.as_str(), old_start_lines[idx]), idx);
    }
    let mut god_nodes: Vec<RankedSymbol> = Vec::with_capacity(graph_state.god_nodes.len());
    for node in &graph_state.god_nodes {
        let Some(&idx) = ranked_by_old_start.get(&(node.symbol_id.as_str(), node.start_line))
        else {
            return Ok(None);
        };
        god_nodes.push(ranked_symbols[idx].clone());
    }
    let mut entrypoints: Vec<RankedSymbol> = Vec::with_capacity(graph_state.entrypoints.len());
    for node in &graph_state.entrypoints {
        let Some(&idx) = ranked_by_old_start.get(&(node.symbol_id.as_str(), node.start_line))
        else {
            return Ok(None);
        };
        entrypoints.push(ranked_symbols[idx].clone());
    }

    let mut vendor_surface = graph_state.vendor_surface.clone();
    let layer_edges = graph_state.layer_edges.clone();
    let cycles = graph_state.cycles.clone();

    // 4. Re-run sharding only; link and graph are intentionally skipped.
    let t_shard = Instant::now();
    let (section_summaries, sections) = sharder::build_section_shards(
        repo_name,
        all_units,
        &mut ranked_symbols,
        &mut types,
        &mut macros,
        &mut calls,
        &mut xrefs,
        &vendor_surface,
        config.vendor_mode,
    );
    let shard_ms = t_shard.elapsed().as_millis() as u64;

    synchronize_indexed_sections(
        &ranked_symbols,
        &mut god_nodes,
        &mut entrypoints,
        &types,
        &macros,
        &mut vendor_surface,
    );

    // 5. Any drift in the reconstructed shape means the sharder would emit different shards than
    //    a full rebuild; abandon the tier and let the caller relink.
    if ranked_symbols.len() != existing_meta.metadata.symbol_count
        || types.len() != existing_meta.metadata.type_count
        || calls.len() != existing_meta.metadata.call_edge_count
        || macros.len() != existing_meta.metadata.macro_count
        || xrefs.len() != existing_meta.metadata.xref_count
        || sections.len() != existing_meta.metadata.section_count
        || god_nodes.len() != existing_meta.metadata.god_node_count
        || entrypoints.len() != existing_meta.metadata.entrypoint_count
    {
        return Ok(None);
    }

    let indexes = BundleIndexes {
        sections: section_summaries,
        symbols: ranked_symbols,
        types,
        calls,
        macros,
        xrefs,
        god_nodes,
        entrypoints,
        layer_edges,
        cycles,
        vendor_surface,
    };
    let sanity = sanity::compute_sanity_report(all_units, &indexes, &sections);

    // 6. Rebuild metadata and emit exactly like the structural path (single meta.json write).
    let mut cache_files = BTreeMap::new();
    for unit in all_units {
        cache_files.insert(unit.scanned.rel_path.clone(), unit.clone());
    }
    let cache = IncrementalAstCache {
        schema_version: CACHE_SCHEMA_VERSION.to_string(),
        repo_root: source_root.to_string(),
        vendor_mode: config.vendor_mode,
        fingerprint: fingerprint.to_string(),
        blueprint_hash: blueprint_hash.to_string(),
        files: cache_files,
    };

    let total_files = scanned_files.len();
    let first_party_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::FirstParty)
        .count();
    let vendor_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::VendorSdk)
        .count();
    let test_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::Test)
        .count();
    let total_lines: usize = scanned_files.iter().map(|f| f.line_count).sum();
    let languages = compute_language_stats(scanned_files);

    let t_emit = Instant::now();
    let mut metadata = RepoMetadata {
        repo_name: repo_name.to_string(),
        source_root: source_root.to_string(),
        fingerprint: fingerprint.to_string(),
        vendor_mode: config.vendor_mode,
        total_files,
        first_party_files,
        vendor_files,
        test_files,
        total_lines,
        languages,
        section_count: sections.len(),
        symbol_count: indexes.symbols.len(),
        type_count: indexes.types.len(),
        call_edge_count: indexes.calls.len(),
        macro_count: indexes.macros.len(),
        xref_count: indexes.xrefs.len(),
        god_node_count: indexes.god_nodes.len(),
        entrypoint_count: indexes.entrypoints.len(),
        elapsed_ms: start.elapsed().as_millis() as u64,
        scan_ms,
        parse_ms,
        link_ms: 0,
        graph_ms: 0,
        shard_ms,
        emit_ms: 0,
        incremental_tier: "coordinate_shift".to_string(),
        incremental_reused_files,
        incremental_reparsed_files,
        file_stamps: build_file_stamps(scanned_files),
    };

    let claudeignore_updated =
        emitter::emit_bundle(config, &metadata, &sanity, &sections, &indexes, &cache)?;
    metadata.emit_ms = t_emit.elapsed().as_millis() as u64;
    metadata.elapsed_ms = start.elapsed().as_millis() as u64;

    let meta_file = BundleMetaFile {
        metadata: metadata.clone(),
        sanity: sanity.clone(),
    };
    let meta_json = serde_json::to_string_pretty(&meta_file)?;
    emitter::write_bytes_atomic(
        &output_dir.join("meta.json"),
        format!("{meta_json}\n").as_bytes(),
    )?;

    Ok(Some(ConversionBundle {
        output_dir: config.output_dir.clone(),
        metadata,
        sanity,
        sections,
        indexes,
        cache_hit: false,
        claudeignore_updated,
    }))
}

/// Converts and indexes a source repository into a Hierarchical Agent Codebase Bundle.
///
/// Supports fast-path `<5ms` cache hits via stat-only `stamp_check` when `meta.json` stamps
/// match, structural digest no-op short-circuiting on comment-only edits, and per-file AST
/// shard caching (`cache/manifest.json` + `cache/<blake3>.json`) so only modified files are
/// re-parsed and written on subsequent runs.
pub fn convert_repo(config: &ConvertConfig) -> Result<ConversionBundle> {
    if !config.repo_path.is_dir() {
        return Err(ChipsrcError::InvalidRepoPath(config.repo_path.clone()));
    }
    let lock_wait = if config.auto_sync {
        emitter::LOCK_WAIT_AUTO_SYNC
    } else {
        emitter::LOCK_WAIT_EXPLICIT
    };
    let Some(_bundle_lock) = emitter::acquire_bundle_lock(&config.output_dir, lock_wait)? else {
        return Err(ChipsrcError::BundleLocked {
            bundle: config.output_dir.clone(),
            lock_path: config.output_dir.join("cache").join(".lock"),
            waited_ms: lock_wait.as_millis() as u64,
        });
    };

    let start = Instant::now();
    let t_scan = Instant::now();
    let (source_root, repo_name) = scanner::canonical_repo_root_and_name(&config.repo_path);

    let meta_path = config.output_dir.join("meta.json");
    let single_md_path = config.output_dir.join(format!("{repo_name}.md"));
    let mut existing_meta_opt =
        if !config.force && (!config.single_file || single_md_path.is_file()) {
            scanner::load_meta_file(&config.output_dir).filter(|m| {
                m.metadata.vendor_mode == config.vendor_mode && !m.metadata.file_stamps.is_empty()
            })
        } else {
            None
        };

    // 1. Stat-only fast-path check against `meta.file_stamps` (zero source-file reads when clean)
    let mut pre_scanned: Option<(Vec<ScannedFile>, String)> = None;
    if let Some(mut existing_meta) = existing_meta_opt.clone() {
        // The artifact-integrity gate and the stat walk are independent: run the gate on its own
        // thread so its `cache/manifest.json` parse and `cache/` listing overlap the walk.
        let (sc_opt, complete) = std::thread::scope(|scope| {
            let artifacts = scope.spawn(|| {
                scanner::bundle_artifacts_complete_with(
                    &config.output_dir,
                    scanner::BundleArtifactSources {
                        meta: Some(&existing_meta),
                        manifest: None,
                    },
                )
            });
            let sc = scanner::stamp_check(
                &config.repo_path,
                &existing_meta.metadata,
                config.max_file_bytes,
            );
            let complete = artifacts.join().unwrap_or(false);
            (sc, complete)
        });
        if let Some(sc) = sc_opt {
            if sc.unchanged {
                if complete {
                    let claudeignore_updated =
                        emitter::ensure_claudeignore_entry(&config.repo_path, &config.output_dir)
                            .unwrap_or(false);
                    let elapsed = start.elapsed().as_millis() as u64;
                    existing_meta.metadata.scan_ms = elapsed;
                    existing_meta.metadata.parse_ms = 0;
                    existing_meta.metadata.link_ms = 0;
                    existing_meta.metadata.graph_ms = 0;
                    existing_meta.metadata.shard_ms = 0;
                    existing_meta.metadata.emit_ms = 0;
                    existing_meta.metadata.elapsed_ms = elapsed;
                    existing_meta.metadata.incremental_reparsed_files = 0;
                    existing_meta.metadata.incremental_reused_files =
                        existing_meta.metadata.total_files;
                    existing_meta.metadata.incremental_tier = "cache_hit".to_string();

                    if !sc.touched_mtimes.is_empty() {
                        for stamp in &mut existing_meta.metadata.file_stamps {
                            if let Some(&(new_mtime, new_nanos)) =
                                sc.touched_mtimes.get(&stamp.rel_path)
                            {
                                stamp.mtime_secs = new_mtime;
                                stamp.mtime_nanos = new_nanos;
                            }
                        }
                        if let Ok(json_str) = serde_json::to_string_pretty(&existing_meta) {
                            let _ = emitter::write_bytes_atomic(
                                &meta_path,
                                format!("{json_str}\n").as_bytes(),
                            );
                        }
                    }

                    return Ok(ConversionBundle {
                        output_dir: config.output_dir.clone(),
                        metadata: existing_meta.metadata,
                        sanity: existing_meta.sanity,
                        sections: Vec::new(),
                        indexes: BundleIndexes::default(),
                        cache_hit: true,
                        claudeignore_updated,
                    });
                } else {
                    existing_meta_opt = None;
                }
            }
            if let Some(files) = sc.scanned_files {
                pre_scanned = Some((files, sc.fingerprint));
            }
        }
    }

    // 2. Scan repository (reusing the single-pass `stamp_check` file list when available)
    let (scanned_files, fingerprint) = match pre_scanned {
        Some(res) => res,
        None => {
            scanner::scan_repository(&config.repo_path, config.vendor_mode, config.max_file_bytes)?
        }
    };
    let blueprint_opt = scanner::load_repo_blueprint(&config.repo_path);
    let blueprint_hash = blueprint_opt
        .as_ref()
        .map(|(_, h)| h.clone())
        .unwrap_or_default();
    let scan_ms = t_scan.elapsed().as_millis() as u64;

    // Fallback fingerprint cache hit check (e.g. when `file_stamps` had `line_count == 0` or was touched)
    if let Some(mut existing_meta) = existing_meta_opt.clone() {
        if existing_meta.metadata.fingerprint == fingerprint
            && existing_meta.metadata.vendor_mode == config.vendor_mode
        {
            if scanner::bundle_artifacts_complete(&config.output_dir) {
                let claudeignore_updated =
                    emitter::ensure_claudeignore_entry(&config.repo_path, &config.output_dir)
                        .unwrap_or(false);
                let elapsed = start.elapsed().as_millis() as u64;
                existing_meta.metadata.scan_ms = scan_ms;
                existing_meta.metadata.parse_ms = 0;
                existing_meta.metadata.link_ms = 0;
                existing_meta.metadata.graph_ms = 0;
                existing_meta.metadata.shard_ms = 0;
                existing_meta.metadata.emit_ms = 0;
                existing_meta.metadata.elapsed_ms = elapsed;
                existing_meta.metadata.incremental_reparsed_files = 0;
                existing_meta.metadata.incremental_reused_files =
                    existing_meta.metadata.total_files;
                existing_meta.metadata.incremental_tier = "cache_hit".to_string();

                return Ok(ConversionBundle {
                    output_dir: config.output_dir.clone(),
                    metadata: existing_meta.metadata,
                    sanity: existing_meta.sanity,
                    sections: Vec::new(),
                    indexes: BundleIndexes::default(),
                    cache_hit: true,
                    claudeignore_updated,
                });
            } else {
                existing_meta_opt = None;
            }
        }
    }

    // 3. Incremental AST parse & Structural Digest No-Op Short-Circuit (Bug 7)
    let t_parse = Instant::now();
    let prev_manifest_opt = if existing_meta_opt.is_some() {
        scanner::load_cache_manifest(&config.output_dir)
            .filter(|m| m.blueprint_hash == blueprint_hash && m.vendor_mode == config.vendor_mode)
    } else {
        None
    };

    let (units, incremental_reused_files, incremental_reparsed_files) = if let Some(mut manifest) =
        prev_manifest_opt
    {
        let prev_stamp_map: BTreeMap<&str, &FileStamp> = existing_meta_opt
            .as_ref()
            .map(|m| {
                m.metadata
                    .file_stamps
                    .iter()
                    .map(|s| (s.rel_path.as_str(), s))
                    .collect()
            })
            .unwrap_or_default();

        let mut dirty_files = Vec::new();
        let mut clean_files = Vec::new();
        for f in &scanned_files {
            let expected_shard = CacheShardEntry::shard_rel_path(&f.rel_path, &f.blake3_hash);
            let reusable = manifest.files.get(&f.rel_path).is_some_and(|entry| {
                entry.blake3_hash == f.blake3_hash
                    && entry.shard == expected_shard
                    && prev_stamp_map
                        .get(f.rel_path.as_str())
                        .is_none_or(|s| s.scope == f.scope && s.arch_layer == f.arch_layer)
            });
            if reusable {
                clean_files.push(f.clone());
            } else {
                dirty_files.push(f.clone());
            }
        }

        let (dirty_units, _, reparsed_count) = parser::parse_files_incremental_with_blueprint(
            &dirty_files,
            None,
            blueprint_opt.as_ref().map(|(bp, _)| bp),
        )?;

        // Check Structural Digest No-Op Short-Circuit when no files were added/deleted
        let digest_and_coords_unchanged = !dirty_units.is_empty()
            && existing_meta_opt.is_some()
            && scanned_files.len() == manifest.files.len()
            && dirty_units.iter().all(|u| {
                manifest
                    .files
                    .get(&u.scanned.rel_path)
                    .is_some_and(|entry| {
                        !entry.structural_digest.is_empty()
                            && entry.structural_digest == u.structural_digest()
                            && prev_stamp_map
                                .get(u.scanned.rel_path.as_str())
                                .is_some_and(|s| {
                                    s.scope == u.scanned.scope
                                        && s.arch_layer == u.scanned.arch_layer
                                })
                            && scanner::load_cache_shard(&config.output_dir, &entry.shard)
                                .is_some_and(|old_u| {
                                    old_u.scanned.rel_path == u.scanned.rel_path
                                        && units_have_identical_coordinates(&old_u, u)
                                })
                    })
            });
        let line_counts_unchanged = digest_and_coords_unchanged
            && dirty_units.iter().all(|u| {
                prev_stamp_map
                    .get(u.scanned.rel_path.as_str())
                    .is_some_and(|s| s.line_count == u.scanned.line_count)
            });
        let can_short_circuit = digest_and_coords_unchanged
            && line_counts_unchanged
            && scanner::bundle_artifacts_complete(&config.output_dir);

        if can_short_circuit {
            let parse_ms = t_parse.elapsed().as_millis() as u64;
            let t_emit = Instant::now();
            let mut existing_meta = existing_meta_opt.unwrap();
            let cache_dir = config.output_dir.join("cache");
            let _ = fs::create_dir_all(&cache_dir);

            for u in &dirty_units {
                let new_hash = &u.scanned.blake3_hash;
                let new_shard_key = CacheShardEntry::shard_key(&u.scanned.rel_path, new_hash);
                let new_shard_rel = format!("cache/{new_shard_key}.json");
                let new_shard_path = cache_dir.join(format!("{new_shard_key}.json"));
                if let Ok(bytes) = serde_json::to_vec(u) {
                    let _ = emitter::write_bytes_atomic(&new_shard_path, &bytes);
                }
                if let Some(old_entry) = manifest.files.get_mut(&u.scanned.rel_path) {
                    let old_shard = old_entry.shard.clone();
                    old_entry.blake3_hash = new_hash.clone();
                    old_entry.shard = new_shard_rel.clone();
                    old_entry.structural_digest = u.structural_digest();
                    if old_shard != new_shard_rel
                        && !manifest.files.values().any(|e| e.shard == old_shard)
                    {
                        let _ = fs::remove_file(config.output_dir.join(&old_shard));
                    }
                }
            }
            manifest.fingerprint = fingerprint.clone();
            if let Ok(m_bytes) = serde_json::to_vec(&manifest) {
                let _ = emitter::write_bytes_atomic(&cache_dir.join("manifest.json"), &m_bytes);
            }

            let total_lines: usize = scanned_files.iter().map(|f| f.line_count).sum();
            let languages = compute_language_stats(&scanned_files);
            let file_stamps: Vec<FileStamp> = scanned_files
                .iter()
                .map(|f| FileStamp {
                    rel_path: f.rel_path.clone(),
                    size_bytes: f.size_bytes,
                    mtime_secs: f.mtime_secs,
                    mtime_nanos: f.mtime_nanos,
                    line_count: f.line_count,
                    blake3_hash: f.blake3_hash.clone(),
                    scope: f.scope,
                    arch_layer: f.arch_layer,
                })
                .collect();

            let claudeignore_updated =
                emitter::ensure_claudeignore_entry(&config.repo_path, &config.output_dir)
                    .unwrap_or(false);
            let emit_ms = t_emit.elapsed().as_millis() as u64;
            let elapsed_ms = start.elapsed().as_millis() as u64;

            existing_meta.metadata.fingerprint = fingerprint;
            existing_meta.metadata.total_lines = total_lines;
            existing_meta.metadata.languages = languages;
            existing_meta.metadata.file_stamps = file_stamps;
            existing_meta.metadata.incremental_reused_files = clean_files.len();
            existing_meta.metadata.incremental_reparsed_files = reparsed_count;
            existing_meta.metadata.incremental_tier = "digest_noop".to_string();
            existing_meta.metadata.scan_ms = scan_ms;
            existing_meta.metadata.parse_ms = parse_ms;
            existing_meta.metadata.link_ms = 0;
            existing_meta.metadata.graph_ms = 0;
            existing_meta.metadata.shard_ms = 0;
            existing_meta.metadata.emit_ms = emit_ms;
            existing_meta.metadata.elapsed_ms = elapsed_ms;

            if let Ok(json_str) = serde_json::to_string_pretty(&existing_meta) {
                let _ = emitter::write_bytes_atomic(&meta_path, format!("{json_str}\n").as_bytes());
            }

            return Ok(ConversionBundle {
                output_dir: config.output_dir.clone(),
                metadata: existing_meta.metadata,
                sanity: existing_meta.sanity,
                sections: Vec::new(),
                indexes: BundleIndexes::default(),
                cache_hit: false,
                claudeignore_updated,
            });
        }

        // Load clean shards in parallel; re-parse any missing shard seamlessly
        let bp_ref = blueprint_opt.as_ref().map(|(bp, _)| bp);
        let clean_results: Vec<Result<(ParsedFileUnit, bool)>> = clean_files
            .into_par_iter()
            .map(|file| {
                if let Some(entry) = manifest.files.get(&file.rel_path) {
                    if let Some(mut cached) =
                        scanner::load_cache_shard(&config.output_dir, &entry.shard)
                            .filter(|u| u.scanned.rel_path == file.rel_path)
                    {
                        cached.scanned = file;
                        return Ok((cached, true));
                    }
                }
                let (mut parsed, _, _) = parser::parse_files_incremental_with_blueprint(
                    std::slice::from_ref(&file),
                    None,
                    bp_ref,
                )?;
                Ok((parsed.pop().unwrap(), false))
            })
            .collect();

        let mut all_units = Vec::with_capacity(scanned_files.len());
        let mut reused_count = 0usize;
        let mut actual_reparsed = reparsed_count;
        for res in clean_results {
            let (u, was_reused) = res?;
            if was_reused {
                reused_count += 1;
            } else {
                actual_reparsed += 1;
            }
            all_units.push(u);
        }
        all_units.extend(dirty_units.iter().cloned());
        all_units.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));

        // Tier 3: coordinate-only shift. Every dirty file keeps its structural digest, scope, and
        // architecture layer, while line coordinates or docstrings moved. Re-coordinate the
        // previously linked state instead of re-running resolve_and_link / analyze_graph.
        let parse_ms = t_parse.elapsed().as_millis() as u64;
        if let Some(existing_meta) = existing_meta_opt.as_ref() {
            let mut old_dirty_units: Vec<ParsedFileUnit> = Vec::with_capacity(dirty_units.len());
            let mut old_dirty_complete = true;
            for unit in &dirty_units {
                match manifest
                    .files
                    .get(&unit.scanned.rel_path)
                    .and_then(|entry| scanner::load_cache_shard(&config.output_dir, &entry.shard))
                    .filter(|old| old.scanned.rel_path == unit.scanned.rel_path)
                {
                    Some(old) => old_dirty_units.push(old),
                    None => {
                        old_dirty_complete = false;
                        break;
                    }
                }
            }
            if old_dirty_complete
                && coordinate_shift_eligible(
                    &old_dirty_units,
                    &dirty_units,
                    &all_units,
                    &manifest,
                    scanned_files.len(),
                )
            {
                let attempted = try_coordinate_shift_tier(
                    config,
                    &repo_name,
                    &source_root,
                    &fingerprint,
                    &blueprint_hash,
                    existing_meta,
                    &scanned_files,
                    &all_units,
                    &old_dirty_units,
                    &dirty_units,
                    reused_count,
                    actual_reparsed,
                    scan_ms,
                    parse_ms,
                    start,
                )?;
                if let Some(bundle) = attempted {
                    return Ok(bundle);
                }
            }
        }

        (all_units, reused_count, actual_reparsed)
    } else {
        let existing_cache =
            if existing_meta_opt.is_some() && scanner::has_bundle_cache(&config.output_dir) {
                scanner::load_cache_file(&config.output_dir).filter(|c| {
                    c.blueprint_hash == blueprint_hash && c.vendor_mode == config.vendor_mode
                })
            } else {
                None
            };
        parser::parse_files_incremental_with_blueprint(
            &scanned_files,
            existing_cache,
            blueprint_opt.as_ref().map(|(bp, _)| bp),
        )?
    };
    let parse_ms = t_parse.elapsed().as_millis() as u64;

    // A structural rebuild invalidates the persisted coordinate-shift state; delete it up front so
    // a failed or partial emit can never leave stale graph annotations next to fresh index tables.
    let _ = fs::remove_file(config.output_dir.join("cache").join(GRAPH_STATE_FILE));

    let t_link = Instant::now();
    let (symbols, mut types, mut macros, mut calls, mut xrefs, mut vendor_surface) =
        resolver::resolve_and_link(&units);
    let link_ms = t_link.elapsed().as_millis() as u64;

    let t_graph = Instant::now();
    let (mut ranked_symbols, mut god_nodes, mut entrypoints, layer_edges, cycles) =
        graph::analyze_graph(symbols, &calls, &units);
    let graph_ms = t_graph.elapsed().as_millis() as u64;

    let t_shard = Instant::now();
    let (section_summaries, sections) = sharder::build_section_shards(
        &repo_name,
        &units,
        &mut ranked_symbols,
        &mut types,
        &mut macros,
        &mut calls,
        &mut xrefs,
        &vendor_surface,
        config.vendor_mode,
    );
    let shard_ms = t_shard.elapsed().as_millis() as u64;

    // Synchronize numbered section_ids and post-compaction retention onto god_nodes,
    // entrypoints, and vendor_surface (Bug 9)
    synchronize_indexed_sections(
        &ranked_symbols,
        &mut god_nodes,
        &mut entrypoints,
        &types,
        &macros,
        &mut vendor_surface,
    );

    let indexes = BundleIndexes {
        sections: section_summaries,
        symbols: ranked_symbols,
        types,
        calls,
        macros,
        xrefs,
        god_nodes,
        entrypoints,
        layer_edges,
        cycles,
        vendor_surface,
    };

    let sanity = sanity::compute_sanity_report(&units, &indexes, &sections);

    let total_files = scanned_files.len();
    let first_party_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::FirstParty)
        .count();
    let vendor_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::VendorSdk)
        .count();
    let test_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::Test)
        .count();
    let total_lines: usize = scanned_files.iter().map(|f| f.line_count).sum();
    let languages = compute_language_stats(&scanned_files);

    let file_stamps: Vec<FileStamp> = scanned_files
        .iter()
        .map(|f| FileStamp {
            rel_path: f.rel_path.clone(),
            size_bytes: f.size_bytes,
            mtime_secs: f.mtime_secs,
            mtime_nanos: f.mtime_nanos,
            line_count: f.line_count,
            blake3_hash: f.blake3_hash.clone(),
            scope: f.scope,
            arch_layer: f.arch_layer,
        })
        .collect();

    let mut cache_files = BTreeMap::new();
    for unit in units {
        cache_files.insert(unit.scanned.rel_path.clone(), unit);
    }
    let cache = IncrementalAstCache {
        schema_version: CACHE_SCHEMA_VERSION.to_string(),
        repo_root: source_root.clone(),
        vendor_mode: config.vendor_mode,
        fingerprint: fingerprint.clone(),
        blueprint_hash,
        files: cache_files,
    };

    let t_emit = Instant::now();
    let mut metadata = RepoMetadata {
        repo_name,
        source_root,
        fingerprint,
        vendor_mode: config.vendor_mode,
        total_files,
        first_party_files,
        vendor_files,
        test_files,
        total_lines,
        languages,
        section_count: sections.len(),
        symbol_count: indexes.symbols.len(),
        type_count: indexes.types.len(),
        call_edge_count: indexes.calls.len(),
        macro_count: indexes.macros.len(),
        xref_count: indexes.xrefs.len(),
        god_node_count: indexes.god_nodes.len(),
        entrypoint_count: indexes.entrypoints.len(),
        elapsed_ms: start.elapsed().as_millis() as u64,
        scan_ms,
        parse_ms,
        link_ms,
        graph_ms,
        shard_ms,
        emit_ms: 0,
        incremental_tier: "structural".to_string(),
        incremental_reused_files,
        incremental_reparsed_files,
        file_stamps,
    };

    let claudeignore_updated =
        emitter::emit_bundle(config, &metadata, &sanity, &sections, &indexes, &cache)?;
    metadata.emit_ms = t_emit.elapsed().as_millis() as u64;
    metadata.elapsed_ms = start.elapsed().as_millis() as u64;

    // Persist final emit_ms and elapsed_ms in meta.json (single write per convert)
    let meta_file = BundleMetaFile {
        metadata: metadata.clone(),
        sanity: sanity.clone(),
    };
    let meta_json = serde_json::to_string_pretty(&meta_file)?;
    emitter::write_bytes_atomic(&meta_path, format!("{meta_json}\n").as_bytes())?;

    Ok(ConversionBundle {
        output_dir: config.output_dir.clone(),
        metadata,
        sanity,
        sections,
        indexes,
        cache_hit: false,
        claudeignore_updated,
    })
}

/// Ensures a repository is indexed under `<output_root>/<repo_stem>` and incrementally
/// synchronized via `cache.json`.
pub fn ensure_repo(
    repo_path: &Path,
    output_root: &Path,
    force: bool,
    vendor_mode: VendorMode,
) -> Result<ConversionBundle> {
    let (_, repo_stem) = scanner::canonical_repo_root_and_name(repo_path);
    let output_dir = output_root.join(repo_stem);
    let mut cfg = ConvertConfig::new(repo_path.to_path_buf(), output_dir);
    cfg.force = force;
    cfg.vendor_mode = vendor_mode;
    convert_repo(&cfg)
}

/// Checks all provided `bundles` against their live `source_root` on disk and incrementally
/// refreshes any stale bundles in place. Returns the number of refreshed bundles.
pub fn auto_refresh_bundles(bundles: &[PathBuf]) -> Result<usize> {
    let mut refreshed = 0usize;

    for bundle_dir in bundles {
        let meta_opt = scanner::load_meta_file(bundle_dir);
        // Parse `cache/manifest.json` at most once per bundle per command: the same parsed
        // manifest drives the cache gate, the artifact-integrity gate, and `repo_root` recovery.
        let manifest_opt = scanner::load_cache_manifest(bundle_dir);
        let manifest_any = if manifest_opt.is_none() {
            scanner::load_cache_manifest_any_version(bundle_dir)
        } else {
            None
        };
        let (source_root_str, vendor_mode, repo_name, file_stamps_empty) =
            if let Some(ref mf) = meta_opt {
                (
                    mf.metadata.source_root.clone(),
                    mf.metadata.vendor_mode,
                    mf.metadata.repo_name.clone(),
                    mf.metadata.file_stamps.is_empty(),
                )
            } else if let Some(manifest) = manifest_opt.as_ref().or(manifest_any.as_ref()) {
                let name = bundle_dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("repo")
                    .to_string();
                (manifest.repo_root.clone(), manifest.vendor_mode, name, true)
            } else {
                continue;
            };
        let source_path = Path::new(&source_root_str);
        if !source_path.is_dir() {
            continue;
        }

        // Fast-path: check `meta.file_stamps` directly from `meta.json` (~2 KB) without loading
        // the multi-megabyte `cache.json` when no source files have changed (Issue #41).
        let needs_refresh = if manifest_opt.is_none()
            || file_stamps_empty
            || !scanner::bundle_artifacts_complete_with(
                bundle_dir,
                scanner::BundleArtifactSources {
                    meta: meta_opt.as_ref(),
                    manifest: manifest_opt.as_ref(),
                },
            ) {
            true
        } else if let Some(ref mf) = meta_opt {
            let meta = &mf.metadata;
            if let Some(count) =
                scanner::check_meta_files_changed(source_path, meta, DEFAULT_MAX_FILE_BYTES)
            {
                count > 0
            } else if let Some(mut cache) = scanner::load_cache_file(bundle_dir) {
                if cache.fingerprint.is_empty() {
                    cache.fingerprint = meta.fingerprint.clone();
                }
                scanner::check_files_changed(source_path, &cache, DEFAULT_MAX_FILE_BYTES)
                    .unwrap_or(0)
                    > 0
            } else if let Ok((_, fp)) =
                scanner::scan_repository(source_path, meta.vendor_mode, DEFAULT_MAX_FILE_BYTES)
            {
                fp != meta.fingerprint
            } else {
                false
            }
        } else {
            true
        };

        if needs_refresh {
            let mut cfg = ConvertConfig::new(source_path.to_path_buf(), bundle_dir.clone());
            cfg.vendor_mode = vendor_mode;
            cfg.force = false;
            cfg.auto_sync = true;
            cfg.single_file = bundle_dir.join(format!("{repo_name}.md")).is_file();
            match convert_repo(&cfg) {
                Ok(_) => refreshed += 1,
                Err(ChipsrcError::BundleLocked { .. }) => continue,
                Err(err) => return Err(err),
            }
        }
    }

    Ok(refreshed)
}

fn compute_language_stats(scanned_files: &[ScannedFile]) -> Vec<LanguageStat> {
    let mut map: BTreeMap<&'static str, LanguageStat> = BTreeMap::new();
    for file in scanned_files {
        let key = file.language.as_str();
        let entry = map.entry(key).or_insert_with(|| LanguageStat {
            language: key.to_string(),
            files: 0,
            lines: 0,
            first_party_files: 0,
            vendor_files: 0,
        });
        entry.files += 1;
        entry.lines += file.line_count;
        match file.scope {
            FileScope::FirstParty => entry.first_party_files += 1,
            FileScope::VendorSdk => entry.vendor_files += 1,
            FileScope::Test => {}
        }
    }

    let mut stats: Vec<LanguageStat> = map.into_values().collect();
    stats.sort_by(|a, b| {
        b.files
            .cmp(&a.files)
            .then_with(|| b.lines.cmp(&a.lines))
            .then_with(|| a.language.cmp(&b.language))
    });
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_unit(rel_path: &str, language: LanguageKind, line_count: usize) -> ParsedFileUnit {
        let section_id = rel_path
            .rsplit_once('/')
            .map(|(dir, _)| dir.replace('/', "-"))
            .unwrap_or_else(|| "root".to_string());
        ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: rel_path.to_string(),
                abs_path: PathBuf::from(rel_path),
                language,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Domain,
                size_bytes: line_count as u64 * 20,
                mtime_secs: 1,
                mtime_nanos: 0,
                blake3_hash: format!("{rel_path}-hash"),
                line_count,
            },
            symbols: vec![ExtractedSymbol {
                symbol_id: format!("{rel_path}::target_fn"),
                name: "target_fn".to_string(),
                qualified_name: "target_fn".to_string(),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                file: rel_path.to_string(),
                start_line: 2,
                end_line: 4,
                signature: "def target_fn() -> int".to_string(),
                doc_summary: String::new(),
                enclosing_type: None,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Domain,
                section_id: section_id.clone(),
            }],
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        }
    }

    fn shift_unit(unit: &mut ParsedFileUnit, delta: usize) {
        for symbol in &mut unit.symbols {
            symbol.start_line += delta;
            symbol.end_line += delta;
        }
        unit.scanned.line_count += delta;
        unit.scanned.size_bytes += delta as u64 * 20;
    }

    fn manifest_for(units: &[ParsedFileUnit], extra_clean: &[ParsedFileUnit]) -> CacheManifest {
        let mut manifest = CacheManifest {
            schema_version: CACHE_SCHEMA_VERSION.to_string(),
            repo_root: "/repo".to_string(),
            vendor_mode: VendorMode::Active,
            ..Default::default()
        };
        for unit in units.iter().chain(extra_clean) {
            manifest.files.insert(
                unit.scanned.rel_path.clone(),
                CacheShardEntry {
                    blake3_hash: unit.scanned.blake3_hash.clone(),
                    shard: CacheShardEntry::shard_rel_path(
                        &unit.scanned.rel_path,
                        &unit.scanned.blake3_hash,
                    ),
                    structural_digest: unit.structural_digest(),
                },
            );
        }
        manifest
    }

    #[test]
    fn coordinate_shift_tier_selection() {
        // Baseline: one small dirty Python file whose coordinates and line count shifted.
        let old = make_unit("domain/a.py", LanguageKind::Python, 40);
        let mut new = old.clone();
        shift_unit(&mut new, 5);
        let all_units = vec![new.clone()];
        let manifest = manifest_for(std::slice::from_ref(&old), &[]);
        assert!(
            coordinate_shift_eligible(
                std::slice::from_ref(&old),
                std::slice::from_ref(&new),
                &all_units,
                &manifest,
                1
            ),
            "digest-stable coordinate shift below thresholds must select Tier 3"
        );

        // Structural change (signature changed -> different digest) must fall back.
        let mut structural = new.clone();
        structural.symbols[0].signature = "def target_fn(x: int) -> int".to_string();
        assert!(!coordinate_shift_eligible(
            std::slice::from_ref(&old),
            &[structural],
            &all_units,
            &manifest,
            1
        ));

        // Scope or layer change must fall back.
        let mut rescoped = new.clone();
        rescoped.scanned.scope = FileScope::Test;
        assert!(!coordinate_shift_eligible(
            std::slice::from_ref(&old),
            &[rescoped],
            &all_units,
            &manifest,
            1
        ));
        let mut relayered = new.clone();
        relayered.scanned.arch_layer = ArchLayer::Tests;
        assert!(!coordinate_shift_eligible(
            std::slice::from_ref(&old),
            &[relayered],
            &all_units,
            &manifest,
            1
        ));

        // C/C++ dirty files are excluded (header prototype doc transfer can touch other files).
        let c_old = make_unit("drivers/a.c", LanguageKind::C, 40);
        let mut c_new = c_old.clone();
        shift_unit(&mut c_new, 5);
        let c_manifest = manifest_for(std::slice::from_ref(&c_old), &[]);
        assert!(!coordinate_shift_eligible(
            &[c_old],
            &[c_new.clone()],
            std::slice::from_ref(&c_new),
            &c_manifest,
            1
        ));

        // Added or deleted files must fall back.
        assert!(!coordinate_shift_eligible(
            std::slice::from_ref(&old),
            std::slice::from_ref(&new),
            &all_units,
            &manifest,
            2
        ));
    }

    #[test]
    fn coordinate_shift_tier_rejects_threshold_crossings() {
        // Single file crossing the 1,400-line sub-shard threshold (1,398 -> 1,498).
        let old = make_unit("src/threshold.py", LanguageKind::Python, 1398);
        let mut new = make_unit("src/threshold.py", LanguageKind::Python, 1498);
        new.scanned.blake3_hash = old.scanned.blake3_hash.clone();
        new.symbols[0].start_line = 1395;
        new.symbols[0].end_line = 1397;
        let manifest = manifest_for(std::slice::from_ref(&old), &[]);
        assert!(
            !coordinate_shift_eligible(
                std::slice::from_ref(&old),
                std::slice::from_ref(&new),
                std::slice::from_ref(&new),
                &manifest,
                1
            ),
            "crossing 1,400 lines must take the full structural path"
        );

        // Module group above the 3,000-line group threshold (3 x 1,100 = 3,300).
        let dirty_old = make_unit("domain/a.py", LanguageKind::Python, 1100);
        let mut dirty_new = dirty_old.clone();
        shift_unit(&mut dirty_new, 5);
        let sibling_b = make_unit("domain/b.py", LanguageKind::Python, 1100);
        let sibling_c = make_unit("domain/c.py", LanguageKind::Python, 1100);
        let all_units = vec![dirty_new.clone(), sibling_b.clone(), sibling_c.clone()];
        let manifest = manifest_for(std::slice::from_ref(&dirty_old), &[sibling_b, sibling_c]);
        assert!(
            !coordinate_shift_eligible(&[dirty_old], &[dirty_new], &all_units, &manifest, 3),
            "groups above 3,000 lines must take the full structural path"
        );
    }

    #[test]
    fn dirty_file_line_maps_translate_calls_docs_and_macros() {
        let mut old = make_unit("domain/a.py", LanguageKind::Python, 40);
        old.macros.push(ExtractedMacro {
            name: "MAX_DEVICES".to_string(),
            kind: MacroKind::Constant,
            value_or_args: "64".to_string(),
            hex_addr: None,
            file: "domain/a.py".to_string(),
            line: 10,
            scope: FileScope::FirstParty,
            arch_layer: ArchLayer::Domain,
            section_id: "domain".to_string(),
            description: "Old doc".to_string(),
        });
        old.raw_calls.push(RawCallSite {
            caller_file: "domain/a.py".to_string(),
            caller_name: "target_fn".to_string(),
            caller_start_line: 2,
            callee_name: "helper".to_string(),
            receiver_or_qualifier: None,
            call_line: 3,
        });
        let mut new = old.clone();
        shift_unit(&mut new, 5);
        new.symbols[0].doc_summary = "New doc".to_string();
        new.macros[0].line = 15;
        new.macros[0].description = "New macro doc".to_string();
        new.raw_calls[0].call_line = 8;

        let maps = build_dirty_file_maps(&old, &new).expect("maps");
        assert_eq!(maps.old_to_new_line.get(&2), Some(&7));
        assert_eq!(maps.old_to_new_line.get(&3), Some(&8));
        assert_eq!(maps.old_to_new_line.get(&4), Some(&9));
        assert_eq!(maps.old_to_new_line.get(&10), Some(&15));
        assert_eq!(
            maps.new_symbol_start_to_old
                .get(&("domain/a.py::target_fn".to_string(), 7)),
            Some(&2)
        );
        assert_eq!(
            maps.macro_contexts.get("MAX_DEVICES").map(String::as_str),
            Some("64 (New macro doc)")
        );

        // A non-monotonic restructure (one old line splitting into two new lines) is rejected.
        let mut conflicting_old = old.clone();
        conflicting_old.macros[0].line = 3; // same old line as the raw call
        let mut conflicting_new = new.clone();
        conflicting_new.macros[0].line = 12; // call maps 3 -> 8, macro maps 3 -> 12
        assert!(build_dirty_file_maps(&conflicting_old, &conflicting_new).is_none());
    }
}
