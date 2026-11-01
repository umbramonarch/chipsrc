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

/// Converts and indexes a source repository into a Hierarchical Agent Codebase Bundle.
///
/// Supports fast-path `<5ms` cache hits via stat-only `stamp_check` when `meta.json` stamps
/// match, structural digest no-op short-circuiting on comment-only edits, and per-file AST
/// shard caching (`cache/manifest.json` + `cache/<blake3>.json`) so only modified files are
/// re-parsed and written on subsequent runs.
pub fn convert_repo(config: &ConvertConfig) -> Result<ConversionBundle> {
    let start = Instant::now();
    let t_scan = Instant::now();
    let (source_root, repo_name) = scanner::canonical_repo_root_and_name(&config.repo_path);

    let meta_path = config.output_dir.join("meta.json");
    let index_md_path = config.output_dir.join("INDEX.md");
    let single_md_path = config.output_dir.join(format!("{repo_name}.md"));
    let bundle_ready = !config.force
        && meta_path.is_file()
        && index_md_path.is_file()
        && scanner::has_bundle_cache(&config.output_dir)
        && scanner::bundle_artifacts_complete(&config.output_dir)
        && (!config.single_file || single_md_path.is_file());

    let existing_meta_opt = if bundle_ready {
        scanner::load_meta_file(&config.output_dir).filter(|m| {
            m.metadata.vendor_mode == config.vendor_mode && !m.metadata.file_stamps.is_empty()
        })
    } else {
        None
    };

    // 1. Stat-only fast-path check against `meta.file_stamps` (zero source-file reads when clean)
    let mut pre_scanned: Option<(Vec<ScannedFile>, String)> = None;
    if let Some(mut existing_meta) = existing_meta_opt.clone() {
        if let Some(sc) = scanner::stamp_check(
            &config.repo_path,
            &existing_meta.metadata,
            config.max_file_bytes,
        ) {
            if sc.unchanged {
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
                        let _ = fs::write(&meta_path, format!("{json_str}\n"));
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
            existing_meta.metadata.incremental_reused_files = existing_meta.metadata.total_files;

            return Ok(ConversionBundle {
                output_dir: config.output_dir.clone(),
                metadata: existing_meta.metadata,
                sanity: existing_meta.sanity,
                sections: Vec::new(),
                indexes: BundleIndexes::default(),
                cache_hit: true,
                claudeignore_updated,
            });
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

    let (units, incremental_reused_files, incremental_reparsed_files) =
        if let Some(mut manifest) = prev_manifest_opt {
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
                                && prev_stamp_map.get(u.scanned.rel_path.as_str()).is_some_and(
                                    |s| {
                                        s.scope == u.scanned.scope
                                            && s.arch_layer == u.scanned.arch_layer
                                    },
                                )
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
            let can_short_circuit = digest_and_coords_unchanged && line_counts_unchanged;

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
                        let _ = fs::write(&new_shard_path, bytes);
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
                    let _ = fs::write(cache_dir.join("manifest.json"), m_bytes);
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
                existing_meta.metadata.scan_ms = scan_ms;
                existing_meta.metadata.parse_ms = parse_ms;
                existing_meta.metadata.link_ms = 0;
                existing_meta.metadata.graph_ms = 0;
                existing_meta.metadata.shard_ms = 0;
                existing_meta.metadata.emit_ms = emit_ms;
                existing_meta.metadata.elapsed_ms = elapsed_ms;

                if let Ok(json_str) = serde_json::to_string_pretty(&existing_meta) {
                    let _ = fs::write(&meta_path, format!("{json_str}\n"));
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
            all_units.extend(dirty_units);
            all_units.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));
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
    {
        let sym_map: BTreeMap<&str, &RankedSymbol> = ranked_symbols
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
        incremental_reused_files,
        incremental_reparsed_files,
        file_stamps,
    };

    let claudeignore_updated =
        emitter::emit_bundle(config, &metadata, &sanity, &sections, &indexes, &cache)?;
    metadata.emit_ms = t_emit.elapsed().as_millis() as u64;
    metadata.elapsed_ms = start.elapsed().as_millis() as u64;

    // Persist final emit_ms and elapsed_ms in meta.json
    let meta_file = BundleMetaFile {
        metadata: metadata.clone(),
        sanity: sanity.clone(),
    };
    if let Ok(meta_json) = serde_json::to_string_pretty(&meta_file) {
        let _ = fs::write(&meta_path, format!("{meta_json}\n"));
    }

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
        let (source_root_str, vendor_mode, repo_name, file_stamps_empty) =
            if let Some(ref mf) = meta_opt {
                (
                    mf.metadata.source_root.clone(),
                    mf.metadata.vendor_mode,
                    mf.metadata.repo_name.clone(),
                    mf.metadata.file_stamps.is_empty(),
                )
            } else if let Some(manifest) = scanner::load_cache_manifest_any_version(bundle_dir) {
                let name = bundle_dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("repo")
                    .to_string();
                (manifest.repo_root, manifest.vendor_mode, name, true)
            } else {
                continue;
            };
        let source_path = Path::new(&source_root_str);
        if !source_path.is_dir() {
            continue;
        }

        // Fast-path: check `meta.file_stamps` directly from `meta.json` (~2 KB) without loading
        // the multi-megabyte `cache.json` when no source files have changed (Issue #41).
        let needs_refresh = if !scanner::has_bundle_cache(bundle_dir)
            || file_stamps_empty
            || !scanner::bundle_artifacts_complete(bundle_dir)
        {
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
            cfg.single_file = bundle_dir.join(format!("{repo_name}.md")).is_file();
            convert_repo(&cfg)?;
            refreshed += 1;
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
