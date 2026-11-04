use crate::model::{
    ExtractedImport, ExtractedMacro, ExtractedSymbol, ExtractedType, FileScope, LanguageKind,
    MacroKind, ParsedFileUnit, ResolutionTier, ResolvedCallEdge, SymbolKind, VendorSurfaceSummary,
    Visibility, XrefEntry,
};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;
use std::path::Path;

/// Collects the unified symbol/type/macro tables from parsed units: deterministic sort,
/// exact-duplicate removal, and C/C++ header-prototype merging.
///
/// This is the coordinate-only part of [`resolve_and_link`] (no call-site resolution), shared
/// with the coordinate-shift incremental tier so a comment/line shift can rebuild the entity
/// tables without relinking the call graph.
pub fn collect_symbol_tables(
    units: &[ParsedFileUnit],
) -> (
    Vec<ExtractedSymbol>,
    Vec<ExtractedType>,
    Vec<ExtractedMacro>,
) {
    // Pre-size every table: a 12k-file corpus holds ~59k symbols, ~3k types, and ~492k macros, so
    // growing these vectors geometrically would recopy hundreds of megabytes of owned strings.
    let symbol_count: usize = units.iter().map(|u| u.symbols.len()).sum();
    let type_count: usize = units.iter().map(|u| u.types.len()).sum();
    let macro_count: usize = units.iter().map(|u| u.macros.len()).sum();

    // Deep-cloning ~1.7M owned rows is allocation-bound on a large corpus, so above a small
    // threshold clone in parallel batches and append in unit order. Below it the batch bookkeeping
    // (and its temporary copies) costs more than the clone itself, so append directly.
    const COLLECT_BATCH: usize = 512;
    const PARALLEL_COLLECT_MIN_UNITS: usize = 256;
    let mut symbols: Vec<ExtractedSymbol> = Vec::with_capacity(symbol_count);
    let mut types: Vec<ExtractedType> = Vec::with_capacity(type_count);
    let mut macros: Vec<ExtractedMacro> = Vec::with_capacity(macro_count);
    if units.len() <= PARALLEL_COLLECT_MIN_UNITS {
        for unit in units {
            symbols.extend_from_slice(&unit.symbols);
            types.extend_from_slice(&unit.types);
            macros.extend_from_slice(&unit.macros);
        }
    } else {
        for batch in units.chunks(COLLECT_BATCH) {
            let parts: Vec<(
                Vec<ExtractedSymbol>,
                Vec<ExtractedType>,
                Vec<ExtractedMacro>,
            )> = batch
                .par_iter()
                .map(|u| (u.symbols.clone(), u.types.clone(), u.macros.clone()))
                .collect();
            for (mut batch_symbols, mut batch_types, mut batch_macros) in parts {
                symbols.append(&mut batch_symbols);
                types.append(&mut batch_types);
                macros.append(&mut batch_macros);
            }
        }
    }
    symbols.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.start_line.cmp(&b.start_line))
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.symbol_id.cmp(&b.symbol_id))
    });
    symbols.dedup_by(|a, b| a.symbol_id == b.symbol_id && a.start_line == b.start_line);

    // Deduplicate C/C++ header prototypes against their `.c`/`.cpp` implementations.
    // Without this, a caller that `#include`s a header resolves the call to the header
    // prototype (`in > 0, out = 0`) instead of the implementation (`out > 0`), which severs the
    // call graph at every module boundary. Matched prototypes are removed and their doc summary
    // is transferred to the implementation when the implementation has no doc comment.
    merge_c_family_header_prototypes(&mut symbols);

    types.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.start_line.cmp(&b.start_line))
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.type_id.cmp(&b.type_id))
    });
    types.dedup_by(|a, b| a.type_id == b.type_id && a.start_line == b.start_line);

    macros.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.name.cmp(&b.name))
    });
    macros.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.name == b.name);

    (symbols, types, macros)
}

/// Resolves raw call sites across all parsed files into a unified call graph,
/// builds the code + hardware cross-reference table, and summarizes the active
/// vendor SDK and MMIO register surface referenced by first-party code.
#[allow(clippy::type_complexity)]
pub fn resolve_and_link(
    units: &[ParsedFileUnit],
) -> (
    Vec<ExtractedSymbol>,
    Vec<ExtractedType>,
    Vec<ExtractedMacro>,
    Vec<ResolvedCallEdge>,
    Vec<XrefEntry>,
    VendorSurfaceSummary,
) {
    // 1. Collect and deterministically sort symbols, types, and macros
    let (symbols, types, macros) = collect_symbol_tables(units);

    // 2. Build fast lookup indexes
    let mut by_name: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
    let mut by_file_name: FxHashMap<(&str, &str), usize> = FxHashMap::default();
    let mut by_file_name_line: FxHashMap<(&str, &str, usize), usize> = FxHashMap::default();

    for (idx, sym) in symbols.iter().enumerate() {
        by_name.entry(sym.name.as_str()).or_default().push(idx);
        by_file_name
            .entry((sym.file.as_str(), sym.name.as_str()))
            .or_insert(idx);
        by_file_name_line.insert((sym.file.as_str(), sym.name.as_str(), sym.start_line), idx);
    }

    // 3. Resolve every RawCallSite and function-pointer candidate across units in parallel
    let mut file_languages: FxHashMap<&str, LanguageKind> = FxHashMap::default();
    file_languages.reserve(units.len());
    for unit in units {
        file_languages.insert(unit.scanned.rel_path.as_str(), unit.scanned.language);
    }

    // Normalizing a defining path (`\`->`/`, stem, extension, language) is per *file*, while the
    // symbol table has one row per declaration. Compute the metadata once per distinct file and
    // map every symbol to its file's entry, so a header with hundreds of declarations pays one
    // normalization instead of hundreds.
    let mut file_meta: FxHashMap<&str, usize> = FxHashMap::default();
    let mut file_entries: Vec<PrecomputedSymFile> = Vec::new();
    let mut per_symbol: Vec<usize> = Vec::with_capacity(symbols.len());
    for sym in &symbols {
        let file_idx = match file_meta.get(sym.file.as_str()) {
            Some(&idx) => idx,
            None => {
                let def_norm = sym.file.replace('\\', "/");
                let def_stem = Path::new(&def_norm)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                let def_without_ext = strip_source_extension(&def_norm);
                let language = resolve_file_language(sym.file.as_str(), &file_languages);
                let idx = file_entries.len();
                file_entries.push(PrecomputedSymFile {
                    def_without_ext,
                    def_stem,
                    language,
                });
                file_meta.insert(sym.file.as_str(), idx);
                idx
            }
        };
        per_symbol.push(file_idx);
    }
    let sym_files = SymFileIndex {
        files: file_entries,
        per_symbol,
    };

    // Structural call-noise pruning needs repository-wide name tables, so build them once before
    // the parallel resolution pass. Test-scope symbols are excluded: a helper that only exists
    // under test can never keep a production `logger.info`-style edge alive.
    let mut defined_names: FxHashSet<&str> = FxHashSet::default();
    let mut callable_names: FxHashSet<&str> = FxHashSet::default();
    for sym in &symbols {
        if sym.scope == FileScope::Test {
            continue;
        }
        defined_names.insert(sym.name.as_str());
        if matches!(
            sym.kind,
            SymbolKind::Function
                | SymbolKind::Method
                | SymbolKind::Constructor
                | SymbolKind::Entrypoint
                | SymbolKind::Isr
        ) {
            callable_names.insert(sym.name.as_str());
        }
    }

    let per_unit_results: Vec<(Vec<ResolvedCallEdge>, Vec<XrefEntry>, bool)> = units
        .par_iter()
        .map(|unit| {
            let unit_sec_id = infer_unit_section_id(unit);
            let unit_language = unit.scanned.language;
            let precomputed_imports: Vec<PrecomputedImport<'_>> = unit
                .imports
                .iter()
                .map(|imp| PrecomputedImport::new(&unit.scanned.rel_path, imp))
                .collect();
            let mut direct_call_sites: FxHashSet<(usize, &str)> =
                FxHashSet::with_capacity_and_hasher(unit.raw_calls.len() * 2, Default::default());
            let mut unit_calls: Vec<ResolvedCallEdge> = Vec::with_capacity(unit.raw_calls.len());
            let mut unit_fn_ptr_xrefs: Vec<XrefEntry> = Vec::new();
            let mut candidate_indices: Vec<usize> = Vec::new();

            for raw in &unit.raw_calls {
                direct_call_sites.insert((raw.call_line, raw.callee_name.as_str()));
                let caller_idx = by_file_name_line
                    .get(&(
                        raw.caller_file.as_str(),
                        raw.caller_name.as_str(),
                        raw.caller_start_line,
                    ))
                    .copied()
                    .or_else(|| {
                        by_file_name
                            .get(&(raw.caller_file.as_str(), raw.caller_name.as_str()))
                            .copied()
                    });

                let (caller_section_id_str, caller_enclosing_type) = match caller_idx {
                    Some(idx) => (
                        symbols[idx].section_id.as_str(),
                        symbols[idx].enclosing_type.as_deref(),
                    ),
                    None => (unit_sec_id.as_str(), None),
                };

                let short_callee = raw
                    .callee_name
                    .rsplit_once("::")
                    .or_else(|| raw.callee_name.rsplit_once("?."))
                    .or_else(|| raw.callee_name.rsplit_once('.'))
                    .or_else(|| raw.callee_name.rsplit_once("->"))
                    .map(|(_, s)| s)
                    .unwrap_or(raw.callee_name.as_str());
                direct_call_sites.insert((raw.call_line, short_callee));

                let candidates = by_name
                    .get(raw.callee_name.as_str())
                    .or_else(|| by_name.get(short_callee));

                candidate_indices.clear();
                if let Some(indices) = candidates {
                    candidate_indices.extend(indices.iter().copied().filter(|&idx| {
                        languages_compatible(Some(unit_language), sym_files.of(idx).language)
                    }));
                }

                let (callee_id, tier) = if candidate_indices.is_empty() {
                    (
                        format!("external::{short_callee}"),
                        ResolutionTier::ExternalOrMacro,
                    )
                } else {
                    resolve_callee_candidates(
                        CallerSite {
                            file: raw.caller_file.as_str(),
                            section_id: caller_section_id_str,
                            language: Some(unit_language),
                            scope: caller_idx
                                .map(|i| symbols[i].scope)
                                .unwrap_or(unit.scanned.scope),
                            enclosing_type: caller_enclosing_type,
                        },
                        raw.callee_name.as_str(),
                        short_callee,
                        raw.receiver_or_qualifier.as_deref(),
                        &precomputed_imports,
                        &candidate_indices,
                        &symbols,
                        &sym_files,
                    )
                };

                if tier == ResolutionTier::ExternalOrMacro
                    && (is_structural_call_noise(
                        unit_language,
                        short_callee,
                        raw.receiver_or_qualifier.as_deref(),
                        &defined_names,
                        &callable_names,
                    ) || (unit_language == LanguageKind::Rust
                        && is_noisy_rust_external_call(
                            raw.callee_name.as_str(),
                            short_callee,
                            raw.receiver_or_qualifier.as_deref(),
                        )))
                {
                    continue;
                }

                let caller_id = match caller_idx {
                    Some(idx) => symbols[idx].symbol_id.clone(),
                    None => format!("{}::{}", raw.caller_file, raw.caller_name),
                };

                unit_calls.push(ResolvedCallEdge {
                    caller_id,
                    caller_name: raw.caller_name.clone(),
                    callee_name: raw.callee_name.clone(),
                    callee_id,
                    file: raw.caller_file.clone(),
                    line: raw.call_line,
                    tier,
                    section_id: caller_section_id_str.to_string(),
                });
            }

            // Idea 4: Precision-filter `fn_ptr_candidate` raw xrefs against known repository symbols.
            for rx in &unit.raw_xrefs {
                if rx.category != "fn_ptr_candidate" {
                    continue;
                }
                let target_name = rx.target_name.as_str();
                if direct_call_sites.contains(&(rx.line, target_name))
                    || is_language_builtin(target_name, Some(unit_language))
                    || is_ubiquitous_member_name(target_name)
                {
                    continue;
                }

                let Some(candidates) = by_name.get(target_name) else {
                    continue;
                };
                candidate_indices.clear();
                candidate_indices.extend(candidates.iter().copied().filter(|&idx| {
                    let sym = &symbols[idx];
                    !(sym.file == rx.file && rx.line == sym.start_line)
                        && languages_compatible(Some(unit_language), sym_files.of(idx).language)
                }));
                if candidate_indices.is_empty() {
                    continue;
                }

                let caller_name = rx.enclosing_symbol.as_deref().unwrap_or("<module_init>");
                let caller_idx = by_file_name.get(&(rx.file.as_str(), caller_name)).copied();
                let (caller_id, caller_section_id, caller_enclosing_type) = match caller_idx {
                    Some(idx) => (
                        symbols[idx].symbol_id.clone(),
                        symbols[idx].section_id.clone(),
                        symbols[idx].enclosing_type.as_deref(),
                    ),
                    None => (
                        format!("{}::{}", rx.file, caller_name),
                        unit_sec_id.clone(),
                        None,
                    ),
                };

                let (callee_id, tier) = resolve_callee_candidates(
                    CallerSite {
                        file: rx.file.as_str(),
                        section_id: &caller_section_id,
                        language: Some(unit_language),
                        scope: caller_idx
                            .map(|i| symbols[i].scope)
                            .unwrap_or(unit.scanned.scope),
                        enclosing_type: caller_enclosing_type,
                    },
                    target_name,
                    target_name,
                    None,
                    &precomputed_imports,
                    &candidate_indices,
                    &symbols,
                    &sym_files,
                );

                if !tier.is_high_confidence() {
                    continue;
                }

                unit_calls.push(ResolvedCallEdge {
                    caller_id: caller_id.clone(),
                    caller_name: caller_name.to_string(),
                    callee_name: rx.target_name.clone(),
                    callee_id,
                    file: rx.file.clone(),
                    line: rx.line,
                    tier,
                    section_id: caller_section_id.clone(),
                });

                unit_fn_ptr_xrefs.push(XrefEntry {
                    symbol: rx.target_name.clone(),
                    category: "fn_ptr_ref".to_string(),
                    relation: "dispatches_fn".to_string(),
                    target: caller_id,
                    file: rx.file.clone(),
                    line: rx.line,
                    section_id: caller_section_id,
                    context: rx.context.clone(),
                });
            }

            unit_calls.sort_by(|a, b| {
                a.file
                    .cmp(&b.file)
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.caller_id.cmp(&b.caller_id))
                    .then_with(|| a.callee_name.cmp(&b.callee_name))
                    .then_with(|| a.callee_id.cmp(&b.callee_id))
            });
            unit_calls.dedup_by(|a, b| {
                a.file == b.file
                    && a.line == b.line
                    && a.caller_id == b.caller_id
                    && a.callee_name == b.callee_name
                    && a.callee_id == b.callee_id
            });

            // 4. Build and sort per-unit XrefEntry list in parallel
            let mut unit_xrefs: Vec<XrefEntry> = Vec::with_capacity(
                unit_calls.len()
                    + unit_fn_ptr_xrefs.len()
                    + unit.raw_xrefs.len()
                    + unit.types.len()
                    + unit.macros.len(),
            );

            for edge in &unit_calls {
                let mut context =
                    String::with_capacity(edge.caller_name.len() + 4 + edge.callee_id.len());
                context.push_str(&edge.caller_name);
                context.push_str(" -> ");
                context.push_str(&edge.callee_id);
                unit_xrefs.push(XrefEntry {
                    symbol: edge.callee_name.clone(),
                    category: "call".to_string(),
                    relation: edge.tier.as_str().to_string(),
                    target: edge.caller_id.clone(),
                    file: edge.file.clone(),
                    line: edge.line,
                    section_id: edge.section_id.clone(),
                    context,
                });
            }

            unit_xrefs.extend(unit_fn_ptr_xrefs);

            for rx in &unit.raw_xrefs {
                if rx.category == "fn_ptr_candidate" {
                    continue;
                }
                let relation = match rx.category.as_str() {
                    "mmio_write" => "writes_reg",
                    "mmio_read" => "reads_reg",
                    "mmio_access" => "accesses_reg",
                    "field_write" => "writes_field",
                    "field_read" => "reads_field",
                    "fn_ptr_ref" => "dispatches_fn",
                    "import" => "imports",
                    "type_ref" => "references_type",
                    "macro_ref" => "expands_macro",
                    other => other,
                }
                .to_string();

                unit_xrefs.push(XrefEntry {
                    symbol: rx.target_name.clone(),
                    category: rx.category.clone(),
                    relation,
                    target: rx
                        .enclosing_symbol
                        .clone()
                        .unwrap_or_else(|| rx.file.clone()),
                    file: rx.file.clone(),
                    line: rx.line,
                    section_id: unit_sec_id.clone(),
                    context: rx.context.clone(),
                });
            }

            for t in &unit.types {
                unit_xrefs.push(XrefEntry {
                    symbol: t.name.clone(),
                    category: "type_def".to_string(),
                    relation: t.kind.as_str().to_string(),
                    target: t.type_id.clone(),
                    file: t.file.clone(),
                    line: t.start_line,
                    section_id: t.section_id.clone(),
                    context: t.fields_summary.clone(),
                });
            }

            for m in &unit.macros {
                let context = if m.description.is_empty() {
                    m.value_or_args.clone()
                } else if m.value_or_args.is_empty() {
                    m.description.clone()
                } else {
                    format!("{} ({})", m.value_or_args, m.description)
                };
                unit_xrefs.push(XrefEntry {
                    symbol: m.name.clone(),
                    category: "macro_def".to_string(),
                    relation: m.kind.as_str().to_string(),
                    target: m
                        .hex_addr
                        .clone()
                        .unwrap_or_else(|| m.value_or_args.clone()),
                    file: m.file.clone(),
                    line: m.line,
                    section_id: m.section_id.clone(),
                    context,
                });
            }

            unit_xrefs.sort_by(|a, b| {
                a.file
                    .cmp(&b.file)
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.symbol.cmp(&b.symbol))
                    .then_with(|| a.category.cmp(&b.category))
                    .then_with(|| a.relation.cmp(&b.relation))
                    .then_with(|| a.target.cmp(&b.target))
            });
            unit_xrefs.dedup_by(|a, b| {
                a.file == b.file
                    && a.line == b.line
                    && a.symbol == b.symbol
                    && a.category == b.category
                    && a.target == b.target
            });

            let rel_path_str = unit.scanned.rel_path.as_str();
            let all_local = unit_calls.iter().all(|c| c.file == rel_path_str)
                && unit_xrefs.iter().all(|x| x.file == rel_path_str);

            (unit_calls, unit_xrefs, all_local)
        })
        .collect();

    let total_calls: usize = per_unit_results.iter().map(|(c, _, _)| c.len()).sum();
    let total_xrefs: usize = per_unit_results.iter().map(|(_, x, _)| x.len()).sum();
    let all_units_local = per_unit_results.iter().all(|(_, _, ok)| *ok);
    let mut calls: Vec<ResolvedCallEdge> = Vec::with_capacity(total_calls);
    let mut xrefs: Vec<XrefEntry> = Vec::with_capacity(total_xrefs);
    for (uc, ux, _) in per_unit_results {
        calls.extend(uc);
        xrefs.extend(ux);
    }

    let units_sorted_by_file = units
        .windows(2)
        .all(|w| w[0].scanned.rel_path < w[1].scanned.rel_path);
    if !units_sorted_by_file || !all_units_local {
        calls.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.caller_id.cmp(&b.caller_id))
                .then_with(|| a.callee_name.cmp(&b.callee_name))
                .then_with(|| a.callee_id.cmp(&b.callee_id))
        });
        calls.dedup_by(|a, b| {
            a.file == b.file
                && a.line == b.line
                && a.caller_id == b.caller_id
                && a.callee_name == b.callee_name
                && a.callee_id == b.callee_id
        });
        xrefs.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.symbol.cmp(&b.symbol))
                .then_with(|| a.category.cmp(&b.category))
                .then_with(|| a.relation.cmp(&b.relation))
                .then_with(|| a.target.cmp(&b.target))
        });
        xrefs.dedup_by(|a, b| {
            a.file == b.file
                && a.line == b.line
                && a.symbol == b.symbol
                && a.category == b.category
                && a.target == b.target
        });
    }

    // 5. Compute VendorSurfaceSummary
    let vendor_surface = compute_vendor_surface(units, &symbols, &types, &macros, &calls);

    (symbols, types, macros, calls, xrefs, vendor_surface)
}

/// Precomputed path metadata and language for a defined symbol's file.
struct PrecomputedSymFile {
    def_without_ext: String,
    def_stem: String,
    language: Option<LanguageKind>,
}

/// Per-symbol view over [`PrecomputedSymFile`]: one entry per distinct defining file plus the
/// symbol-index -> file-index map.
struct SymFileIndex {
    files: Vec<PrecomputedSymFile>,
    per_symbol: Vec<usize>,
}

impl SymFileIndex {
    #[inline]
    fn of(&self, symbol_idx: usize) -> &PrecomputedSymFile {
        &self.files[self.per_symbol[symbol_idx]]
    }
}

/// Precomputed normalized path metadata for a single import statement within a caller file.
struct PrecomputedImport<'a> {
    raw_norm: String,
    first_segment: Option<String>,
    last_segment: Option<String>,
    rel_resolved: Option<String>,
    imp_without_ext: String,
    imp_stem: String,
    implicit_header_or_module_import: bool,
    is_std_stem: bool,
    imported_names: &'a [String],
}

impl<'a> PrecomputedImport<'a> {
    fn new(caller_file: &str, imp: &'a ExtractedImport) -> Self {
        let raw_norm = normalize_import_path(&imp.raw_path);
        let mut seg_iter = raw_norm
            .split(['/', '.', ':'])
            .filter(|segment| !segment.is_empty());
        let first_segment = seg_iter.next().map(|s| s.to_string());
        let last_segment = seg_iter
            .next_back()
            .map(|s| s.to_string())
            .or_else(|| first_segment.clone());
        let rel_resolved = resolve_relative_import_path(caller_file, &imp.raw_path);
        let imp_without_ext =
            strip_source_extension(raw_norm.trim_start_matches("../").trim_start_matches("./"));
        let imp_stem = Path::new(&imp_without_ext)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let names_module_stem = !imp_stem.is_empty()
            && imp
                .imported_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&imp_stem));
        let implicit_header_or_module_import = imp.imported_names.is_empty() || names_module_stem;
        let is_std_stem = imp_stem.eq_ignore_ascii_case("std");

        Self {
            raw_norm,
            first_segment,
            last_segment,
            rel_resolved,
            imp_without_ext,
            imp_stem,
            implicit_header_or_module_import,
            is_std_stem,
            imported_names: &imp.imported_names,
        }
    }
}

/// Caller-side context needed to resolve a single call site.
struct CallerSite<'a> {
    file: &'a str,
    section_id: &'a str,
    language: Option<LanguageKind>,
    scope: FileScope,
    enclosing_type: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
fn resolve_callee_candidates(
    caller: CallerSite<'_>,
    raw_callee_name: &str,
    callee_name: &str,
    receiver_or_qualifier: Option<&str>,
    imports: &[PrecomputedImport<'_>],
    candidate_indices: &[usize],
    symbols: &[ExtractedSymbol],
    sym_files: &SymFileIndex,
) -> (String, ResolutionTier) {
    let caller_file = caller.file;
    let caller_section_id = caller.section_id;
    let caller_language = caller.language;
    let is_static_path_call = raw_callee_name.contains("::");
    let effective_qualifier = match receiver_or_qualifier {
        Some(q) if is_self_or_class_receiver(q) => caller.enclosing_type.or(Some(q)),
        other => other,
    };

    let unresolved = || {
        (
            format!("external::{callee_name}"),
            ResolutionTier::ExternalOrMacro,
        )
    };

    if candidate_indices.is_empty() {
        return unresolved();
    }

    // Scope compatibility helper:
    // - Non-test code (`FirstParty` or `VendorSdk`) never resolves to `FileScope::Test` symbols
    //   (even if defined inside a `#[cfg(test)]` block in the same source file).
    // - `VendorSdk` code never resolves to `FirstParty` symbols via heuristics.
    let scope_compatible = |def: &ExtractedSymbol| -> bool {
        if caller.scope != FileScope::Test && def.scope == FileScope::Test {
            return false;
        }
        if caller.scope == FileScope::VendorSdk && def.scope != FileScope::VendorSdk {
            return false;
        }
        true
    };

    let ubiquitous_member = is_ubiquitous_member_name(callee_name);

    // Tier 1: Defined in the same file (and scope-compatible)
    let same_file: Vec<usize> = candidate_indices
        .iter()
        .copied()
        .filter(|&idx| symbols[idx].file == caller_file && scope_compatible(&symbols[idx]))
        .collect();
    if !same_file.is_empty() {
        if let Some(qual) = effective_qualifier {
            let qual = qual.trim();
            // Prefer an exact qualified-name match (`b::Box` over a same-leaf `a::Box`), then a
            // trailing sub-path or leaf match.
            let exact_match = same_file.iter().copied().find(|&idx| {
                symbols[idx]
                    .enclosing_type
                    .as_deref()
                    .is_some_and(|et| et.trim().eq_ignore_ascii_case(qual))
            });
            let qualified_match = exact_match.or_else(|| {
                same_file.iter().copied().find(|&idx| {
                    symbols[idx]
                        .enclosing_type
                        .as_deref()
                        .is_some_and(|et| enclosing_matches_qualifier(et, qual))
                })
            });
            if let Some(idx) = qualified_match {
                return (symbols[idx].symbol_id.clone(), ResolutionTier::SameFile);
            }
            // If the call has a concrete non-self qualifier (e.g. `Vec::new()` or `entry.path()`)
            // and a same-file candidate is a method on a DIFFERENT enclosing type, filter it out.
            if !is_self_or_class_receiver(qual) {
                let allowed_same_file: Vec<usize> = same_file
                    .iter()
                    .copied()
                    .filter(|&idx| {
                        qualified_candidate_allowed(
                            qual,
                            is_static_path_call,
                            ubiquitous_member,
                            &symbols[idx],
                        )
                    })
                    .collect();
                if let Some(&first_idx) = allowed_same_file.first() {
                    return (
                        symbols[first_idx].symbol_id.clone(),
                        ResolutionTier::SameFile,
                    );
                }
                return unresolved();
            }
        }
        return (
            symbols[same_file[0]].symbol_id.clone(),
            ResolutionTier::SameFile,
        );
    }

    let explicitly_imported = imports
        .iter()
        .any(|imp| imp.imported_names.iter().any(|n| n == callee_name));

    // Built-in / qualified-call safeguards before any name-based guessing.
    match receiver_or_qualifier {
        // Unqualified call to a standard language built-in that is not defined in this file
        // and not explicitly imported by name.
        None => {
            if !explicitly_imported && is_language_builtin(callee_name, caller_language) {
                return unresolved();
            }
        }
        // `module.func()` where `module` is an imported module/symbol that does not exist in the
        // repository (e.g. `import subprocess; subprocess.run(...)`, `time.sleep(...)`).
        Some(qual) => {
            if !is_self_or_class_receiver(qual)
                && is_external_module_qualifier(qual, imports, candidate_indices, sym_files)
            {
                return unresolved();
            }
        }
    }

    // Tier 2: Caller file's imports reference the defining file's stem/module or explicitly import callee_name
    let mut import_matches: Vec<(usize, usize)> = Vec::new();
    let non_self_qualifier = receiver_or_qualifier.filter(|q| !is_self_or_class_receiver(q));
    for &idx in candidate_indices {
        let def = &symbols[idx];
        if !scope_compatible(def) {
            continue;
        }
        if let Some(qual) = non_self_qualifier {
            let qual_is_imported_ns = imports.iter().any(|imp| {
                imp.imported_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(qual))
            });
            if !(qual_is_imported_ns && def.enclosing_type.is_none())
                && !qualified_candidate_allowed(qual, is_static_path_call, ubiquitous_member, def)
            {
                continue;
            }
        } else if def.enclosing_type.is_some()
            && caller.enclosing_type != def.enclosing_type.as_deref()
            && !explicitly_imported
        {
            // Unqualified call cannot invoke a method of an unrelated type across files.
            continue;
        }
        if let Some(score) = match_import_for_candidate(callee_name, sym_files.of(idx), imports) {
            import_matches.push((score, idx));
        }
    }
    if !import_matches.is_empty() {
        import_matches.sort_by(|(score_a, idx_a), (score_b, idx_b)| {
            score_b
                .cmp(score_a)
                .then_with(|| {
                    scope_rank(symbols[*idx_a].scope).cmp(&scope_rank(symbols[*idx_b].scope))
                })
                .then_with(|| symbols[*idx_a].symbol_id.cmp(&symbols[*idx_b].symbol_id))
        });
        return (
            symbols[import_matches[0].1].symbol_id.clone(),
            ResolutionTier::ImportResolved,
        );
    }

    // `obj.method()` / `Type::method()` receivers may only bind to methods of a matching type or
    // to symbols living in a module named by the qualifier. Ubiquitous container/IO/lifecycle
    // member names and mismatched explicit type qualifiers are never guessed blindly.
    let mut eligible: Vec<usize> = candidate_indices
        .iter()
        .copied()
        .filter(|&idx| scope_compatible(&symbols[idx]))
        .collect();

    if let Some(qual) = receiver_or_qualifier {
        if is_self_or_class_receiver(qual) {
            if let Some(caller_ty) = caller.enclosing_type {
                let matching_type: Vec<usize> = eligible
                    .iter()
                    .copied()
                    .filter(|&idx| {
                        symbols[idx]
                            .enclosing_type
                            .as_deref()
                            .is_some_and(|et| enclosing_matches_qualifier(et, caller_ty))
                    })
                    .collect();
                if !matching_type.is_empty() {
                    eligible = matching_type;
                } else if ubiquitous_member {
                    return unresolved();
                }
            } else if ubiquitous_member {
                return unresolved();
            }
        } else {
            eligible.retain(|&idx| {
                qualified_candidate_allowed(
                    qual,
                    is_static_path_call,
                    ubiquitous_member,
                    &symbols[idx],
                )
            });
        }
    } else {
        // Unqualified call (`foo()`): exclude methods (`enclosing_type.is_some()`) unless the caller
        // is in the same `enclosing_type`.
        eligible.retain(|&idx| {
            let def = &symbols[idx];
            match def.enclosing_type.as_deref() {
                None => true,
                Some(et) => caller
                    .enclosing_type
                    .is_some_and(|ct| enclosing_matches_qualifier(et, ct)),
            }
        });
    }

    if eligible.is_empty() {
        return unresolved();
    }

    // Tier 3: Exactly 1 definition across the entire repository
    if eligible.len() == 1 {
        return (
            symbols[eligible[0]].symbol_id.clone(),
            ResolutionTier::UniqueGlobal,
        );
    }

    // Tier 4: Multiple definitions across repository -> pick closest directory/section, then first-party over vendor, then lexicographically first symbol_id
    let mut ranked_candidates: Vec<usize> = eligible;
    ranked_candidates.sort_by(|&idx_a, &idx_b| {
        let a = &symbols[idx_a];
        let b = &symbols[idx_b];

        let qual_a = effective_qualifier.is_some_and(|q| {
            a.enclosing_type
                .as_deref()
                .is_some_and(|et| et.eq_ignore_ascii_case(q))
        });
        let qual_b = effective_qualifier.is_some_and(|q| {
            b.enclosing_type
                .as_deref()
                .is_some_and(|et| et.eq_ignore_ascii_case(q))
        });

        let sec_a = a.section_id == caller_section_id;
        let sec_b = b.section_id == caller_section_id;

        let prefix_a = common_dir_prefix_len(caller_file, &a.file);
        let prefix_b = common_dir_prefix_len(caller_file, &b.file);

        qual_b
            .cmp(&qual_a)
            .then_with(|| sec_b.cmp(&sec_a))
            .then_with(|| prefix_b.cmp(&prefix_a))
            .then_with(|| scope_rank(a.scope).cmp(&scope_rank(b.scope)))
            .then_with(|| a.symbol_id.cmp(&b.symbol_id))
    });

    (
        symbols[ranked_candidates[0]].symbol_id.clone(),
        ResolutionTier::AmbiguousName,
    )
}

/// Standard library built-in callables per language family. Calls to these names are resolved as
/// external unless the symbol is defined in the *same* file (Tier 1), which prevents an unrelated
/// repository symbol that happens to share the name from capturing a built-in call.
const C_BUILTINS: &[&str] = &[
    "sizeof", "offsetof", "malloc", "calloc", "realloc", "free", "memcpy", "memset", "memmove",
    "memcmp", "strlen", "strcmp", "strncmp", "snprintf", "printf", "fprintf",
];

const PYTHON_BUILTINS: &[&str] = &[
    "open",
    "print",
    "len",
    "int",
    "str",
    "float",
    "bool",
    "bytes",
    "list",
    "dict",
    "set",
    "tuple",
    "range",
    "enumerate",
    "zip",
    "map",
    "filter",
    "sorted",
    "reversed",
    "min",
    "max",
    "sum",
    "abs",
    "any",
    "all",
    "isinstance",
    "issubclass",
    "getattr",
    "setattr",
    "hasattr",
    "delattr",
    "super",
    "type",
    "repr",
    "id",
    "hash",
    "hex",
    "oct",
    "bin",
    "ord",
    "chr",
    "iter",
    "next",
    "callable",
    "vars",
    "dir",
    "round",
    "divmod",
    "pow",
    "format",
    "input",
    "exec",
    "eval",
    "compile",
    "globals",
    "locals",
    "staticmethod",
    "classmethod",
    "property",
    "object",
    "frozenset",
    "bytearray",
    "memoryview",
    "slice",
    "complex",
    "NotImplemented",
    "Exception",
    "ValueError",
    "TypeError",
    "KeyError",
    "RuntimeError",
];

const JS_BUILTINS: &[&str] = &[
    "parseInt",
    "parseFloat",
    "isNaN",
    "isFinite",
    "setTimeout",
    "clearTimeout",
    "setInterval",
    "clearInterval",
    "fetch",
    "require",
    "alert",
    "confirm",
    "prompt",
    "Array",
    "Object",
    "Promise",
    "JSON",
    "Math",
    "Date",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Symbol",
    "Error",
    "TypeError",
    "RegExp",
    "Number",
    "String",
    "Boolean",
    "BigInt",
    "Reflect",
    "Proxy",
    "console",
    "document",
    "window",
    "querySelector",
    "querySelectorAll",
    "getElementById",
    "addEventListener",
    "removeEventListener",
    "requestAnimationFrame",
    "structuredClone",
    "encodeURIComponent",
    "decodeURIComponent",
];

/// Ubiquitous container / IO / lifecycle / conversion member names. When such a name is invoked
/// on an arbitrary variable receiver (`session.commit()`, `data.get()`, `s.as_str()`, `Vec::new()`)
/// it is almost always a standard-library or third-party method, never an unrelated repository method.
const UBIQUITOUS_MEMBER_NAMES: &[&str] = &[
    "new",
    "default",
    "from",
    "into",
    "try_from",
    "try_into",
    "as_str",
    "as_bytes",
    "as_ref",
    "as_mut",
    "as_deref",
    "as_path",
    "as_slice",
    "to_str",
    "to_string",
    "to_owned",
    "to_path_buf",
    "to_vec",
    "to_lowercase",
    "to_uppercase",
    "to_ascii_lowercase",
    "to_ascii_uppercase",
    "eq_ignore_ascii_case",
    "parse",
    "fmt",
    "len",
    "is_empty",
    "get",
    "get_mut",
    "set",
    "add",
    "pop",
    "remove",
    "clear",
    "truncate",
    "retain",
    "dedup",
    "dedup_by",
    "sort",
    "sort_by",
    "sort_by_key",
    "sort_unstable",
    "reverse",
    "update",
    "append",
    "extend",
    "insert",
    "entry",
    "or_insert",
    "or_insert_with",
    "or_default",
    "with_capacity",
    "reserve",
    "keys",
    "values",
    "items",
    "commit",
    "rollback",
    "flush",
    "close",
    "open",
    "read",
    "write",
    "seek",
    "start",
    "stop",
    "run",
    "init",
    "reset",
    "deinit",
    "build",
    "join",
    "sleep",
    "wait",
    "notify",
    "acquire",
    "release",
    "lock",
    "split",
    "rsplit",
    "split_once",
    "rsplit_once",
    "strip",
    "lstrip",
    "rstrip",
    "trim",
    "trim_start",
    "trim_end",
    "trim_matches",
    "trim_start_matches",
    "trim_end_matches",
    "strip_prefix",
    "strip_suffix",
    "replace",
    "repeat",
    "format",
    "encode",
    "decode",
    "lower",
    "upper",
    "startswith",
    "endswith",
    "starts_with",
    "ends_with",
    "contains",
    "find",
    "rfind",
    "position",
    "rposition",
    "index",
    "count",
    "copy",
    "clone",
    "copied",
    "cloned",
    "iter",
    "into_iter",
    "iter_mut",
    "chars",
    "bytes",
    "lines",
    "map",
    "filter",
    "filter_map",
    "flat_map",
    "find_map",
    "flatten",
    "fold",
    "all",
    "any",
    "take",
    "skip",
    "take_while",
    "skip_while",
    "chain",
    "zip",
    "enumerate",
    "collect",
    "unwrap",
    "unwrap_or",
    "unwrap_or_default",
    "unwrap_or_else",
    "expect",
    "ok",
    "err",
    "some",
    "none",
    "is_some",
    "is_none",
    "is_ok",
    "is_err",
    "is_some_and",
    "is_ok_and",
    "map_or",
    "map_or_else",
    "map_err",
    "and_then",
    "or_else",
    "ok_or",
    "ok_or_else",
    "transpose",
    "first",
    "last",
    "min",
    "max",
    "clamp",
    "cmp",
    "partial_cmp",
    "total_cmp",
    "min_by",
    "max_by",
    "min_by_key",
    "max_by_key",
    "then_with",
    "push",
    "push_str",
    "slice",
    "splice",
    "forEach",
    "includes",
    "indexOf",
    "toString",
    "valueOf",
    "then",
    "catch",
    "finally",
    "info",
    "debug",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
];

const C_FAMILY_HEADER_EXTENSIONS: &[&str] = &["h", "hpp", "hh", "hxx"];
const C_FAMILY_IMPLEMENTATION_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx"];

fn source_extension(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let (stem, ext) = file_name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Allocation-free variant of [`source_extension`] for hot per-symbol path classification.
fn source_extension_borrowed(path: &str) -> Option<&str> {
    let file_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let (stem, ext) = file_name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    Some(ext)
}

fn is_c_family_header(path: &str) -> bool {
    source_extension_borrowed(path).is_some_and(|ext| {
        C_FAMILY_HEADER_EXTENSIONS
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    })
}

fn is_c_family_implementation(path: &str) -> bool {
    source_extension_borrowed(path).is_some_and(|ext| {
        C_FAMILY_IMPLEMENTATION_EXTENSIONS
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    })
}

/// Collapses C/C++ header prototypes into the `.c`/`.cc`/`.cpp`/`.cxx` symbol that implements them.
///
/// Header prototypes are only dropped when a matching implementation actually exists, so
/// header-only code (`static inline` helpers, vendor SDK headers without a translation unit, and
/// declaration-only interfaces) is fully preserved.
fn merge_c_family_header_prototypes(symbols: &mut Vec<ExtractedSymbol>) {
    if symbols.is_empty() {
        return;
    }

    // Per-symbol metadata is computed once instead of once per candidate comparison: path
    // classification (alloc-free), parameter arity, the lowercase file stem, and whether the
    // signature mentions `inline`.
    let mut is_impl = vec![false; symbols.len()];
    let mut is_header = vec![false; symbols.len()];
    let mut arity: Vec<Option<usize>> = Vec::with_capacity(symbols.len());
    let mut stem: Vec<Option<String>> = Vec::with_capacity(symbols.len());
    for (idx, sym) in symbols.iter().enumerate() {
        let impl_file = is_c_family_implementation(&sym.file);
        is_impl[idx] = impl_file && sym.visibility != Visibility::Static;
        is_header[idx] = !impl_file && is_c_family_header(&sym.file);
        arity.push(signature_param_arity(&sym.signature));
        stem.push(is_impl[idx].then(|| file_stem_lower(&sym.file)));
    }

    // Index implementation symbols by exact (leaf name, enclosing type).
    let mut implementations: FxHashMap<(&str, Option<&str>), Vec<u32>> = FxHashMap::default();
    for (idx, sym) in symbols.iter().enumerate() {
        if !is_impl[idx] {
            continue;
        }
        implementations
            .entry((sym.name.as_str(), sym.enclosing_type.as_deref()))
            .or_default()
            .push(idx as u32);
    }
    if implementations.is_empty() {
        return;
    }

    let mut doc_transfers: Vec<(u32, String)> = Vec::new();
    let mut removed: FxHashSet<u32> = FxHashSet::default();
    // `is_inline` is only needed for header prototypes; compute it lazily per proto signature.
    let mut compatible: Vec<u32> = Vec::new();

    for (proto_idx, proto) in symbols.iter().enumerate() {
        // Only a non-static, non-inline declaration in a C/C++ header can be a forward prototype.
        if !is_header[proto_idx] || proto.visibility == Visibility::Static {
            continue;
        }
        if proto
            .signature
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|tok| matches!(tok, "inline" | "__inline" | "__inline__" | "INLINE"))
        {
            continue;
        }

        let Some(candidates) =
            implementations.get(&(proto.name.as_str(), proto.enclosing_type.as_deref()))
        else {
            continue;
        };

        let proto_arity = arity[proto_idx];
        let proto_stem = file_stem_lower(&proto.file);

        // Filter candidates with compatible parameter arity (so C++ overloads are never collapsed).
        compatible.clear();
        compatible.extend(candidates.iter().copied().filter(|&idx| {
            match (proto_arity, arity[idx as usize]) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
        }));

        if compatible.is_empty() {
            continue;
        }

        // Prefer matching file stem (`drvAdc.h` <-> `drvAdc.c`), then same shard, then
        // first-party over vendor/test code, then lexicographically first symbol id.
        let best = compatible.iter().copied().min_by(|&a, &b| {
            let a = a as usize;
            let b = b as usize;
            let stem_a = stem[a].as_deref() != Some(proto_stem.as_str());
            let stem_b = stem[b].as_deref() != Some(proto_stem.as_str());
            let sec_a = symbols[a].section_id != proto.section_id;
            let sec_b = symbols[b].section_id != proto.section_id;
            stem_a
                .cmp(&stem_b)
                .then_with(|| sec_a.cmp(&sec_b))
                .then_with(|| scope_rank(symbols[a].scope).cmp(&scope_rank(symbols[b].scope)))
                .then_with(|| symbols[a].symbol_id.cmp(&symbols[b].symbol_id))
        });

        if let Some(best) = best {
            if !proto.doc_summary.is_empty() {
                doc_transfers.push((best, proto.doc_summary.clone()));
            }
            removed.insert(proto_idx as u32);
        }
    }

    if removed.is_empty() {
        return;
    }

    for (idx, doc_summary) in doc_transfers {
        let target = &mut symbols[idx as usize];
        if target.doc_summary.is_empty() {
            target.doc_summary = doc_summary;
        }
    }

    let mut kept = std::mem::take(symbols);
    *symbols = kept
        .drain(..)
        .enumerate()
        .filter_map(|(idx, sym)| (!removed.contains(&(idx as u32))).then_some(sym))
        .collect();
}

fn file_stem_lower(path: &str) -> String {
    let fname = path.rsplit(['/', '\\']).next().unwrap_or(path);
    fname
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(fname)
        .to_ascii_lowercase()
}

fn signature_param_arity(sig: &str) -> Option<usize> {
    let open = sig.find('(')?;
    let close = sig.rfind(')')?;
    if close <= open {
        return None;
    }
    let inner = sig[open + 1..close].trim();
    if inner.is_empty() || inner == "void" {
        return Some(0);
    }
    let mut count = 1usize;
    let mut depth = 0usize;
    for ch in inner.chars() {
        match ch {
            '(' | '<' | '[' | '{' => depth += 1,
            ')' | '>' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    Some(count)
}

fn languages_compatible(caller: Option<LanguageKind>, callee: Option<LanguageKind>) -> bool {
    match (caller, callee) {
        (Some(a), Some(b)) => a.language_family() == b.language_family(),
        // Unknown languages are never filtered out.
        _ => true,
    }
}

fn resolve_file_language(
    file: &str,
    file_languages: &FxHashMap<&str, LanguageKind>,
) -> Option<LanguageKind> {
    file_languages.get(file).copied().or_else(|| {
        source_extension(file).and_then(|ext| LanguageKind::from_extension(ext.as_str()))
    })
}

fn is_language_builtin(name: &str, caller_language: Option<LanguageKind>) -> bool {
    let in_c = C_BUILTINS.contains(&name);
    let in_python = PYTHON_BUILTINS.contains(&name);
    let in_js = JS_BUILTINS.contains(&name);

    match caller_language {
        Some(LanguageKind::C | LanguageKind::Cpp) => in_c,
        Some(LanguageKind::Python) => in_python,
        Some(
            LanguageKind::TypeScript
            | LanguageKind::Tsx
            | LanguageKind::JavaScript
            | LanguageKind::Jsx,
        ) => in_js,
        // Rust has no free-function builtins in this table; `std` calls are path-qualified.
        Some(LanguageKind::Rust) => false,
        None => in_c || in_python || in_js,
    }
}

fn is_ubiquitous_member_name(name: &str) -> bool {
    UBIQUITOUS_MEMBER_NAMES.contains(&name) || TREE_SITTER_METHODS.contains(&name)
}

const TREE_SITTER_METHODS: &[&str] = &[
    "child_by_field_name",
    "kind",
    "walk",
    "start_position",
    "end_position",
    "start_byte",
    "end_byte",
    "named_child",
    "named_child_count",
    "child",
    "child_count",
    "children",
    "next_sibling",
    "prev_sibling",
    "parent",
    "utf8_text",
    "root_node",
    "is_named",
    "is_missing",
    "has_error",
    "is_error",
    "is_extra",
    "children_by_field_name",
    "named_children",
    "id",
    "set_language",
];

/// Structural call-noise pruning for sites that already failed to resolve (`ExternalOrMacro`).
///
/// Rule 1: a receiver/qualified call whose short name is defined by no non-Test symbol anywhere in
/// the repository is third-party/stdlib noise (`logger.info`, `store.flush`, `console.log`).
/// Rule 2: a bare Rust `PascalCase(...)` call that names no callable symbol is a constructor,
/// enum variant, or std type path (`Wrapper(3)`, `Option`, `Reverse`).
///
/// Bare calls in other languages (C `malloc`, vendor HAL entry points) and bare lowercase Rust
/// calls are never pruned by these rules; unresolved names that *do* exist in the repository keep
/// their edges so `callees`/`xref` still show cross-module uses.
fn is_structural_call_noise(
    language: LanguageKind,
    short_callee: &str,
    receiver_or_qualifier: Option<&str>,
    defined_names: &FxHashSet<&str>,
    callable_names: &FxHashSet<&str>,
) -> bool {
    if receiver_or_qualifier.is_some() && !defined_names.contains(short_callee) {
        return true;
    }
    language == LanguageKind::Rust
        && receiver_or_qualifier.is_none()
        && is_pascal_case_word(short_callee)
        && !callable_names.contains(short_callee)
}

/// True when `name` starts with an ASCII uppercase letter and contains at least one ASCII
/// lowercase letter (`Wrapper`, `ParserConfig`), distinguishing type-like constructor calls from
/// all-caps constants (`MAX`, `GPIOA`) and lowercase functions.
fn is_pascal_case_word(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
        && name.bytes().any(|b| b.is_ascii_lowercase())
}

/// Returns `true` when an unresolved (`ExternalOrMacro`) call in a Rust file is a ubiquitous
/// standard-library method/constructor/iterator/option operation (`clone`, `to_string`, `as_str`,
/// `unwrap`, `iter`, `map`, `collect`, `Vec::new`, `String::new`, `Some`, `Ok`, `Err`, etc.) that
/// adds noise without architectural signal.
fn is_noisy_rust_external_call(
    raw_callee_name: &str,
    short_callee: &str,
    receiver_or_qualifier: Option<&str>,
) -> bool {
    if is_ubiquitous_member_name(short_callee) {
        return true;
    }
    if matches!(
        short_callee,
        "Some"
            | "Ok"
            | "Err"
            | "Box"
            | "Arc"
            | "Rc"
            | "Vec"
            | "String"
            | "Path"
            | "PathBuf"
            | "Default"
            | "From"
            | "Into"
            | "Self"
            | "sum"
            | "next"
            | "any"
            | "all"
            | "find"
            | "position"
            | "enumerate"
            | "zip"
            | "chain"
            | "flat_map"
            | "filter_map"
            | "copied"
            | "cloned"
            | "take"
            | "skip"
            | "rev"
            | "sort"
            | "sort_by"
            | "sort_by_key"
            | "dedup"
            | "retain"
            | "extend"
            | "insert"
            | "remove"
            | "contains"
            | "contains_key"
            | "entry"
            | "or_default"
            | "or_insert"
            | "or_insert_with"
            | "and_then"
            | "or_else"
            | "map_err"
            | "map_or"
            | "unwrap_or_default"
            | "unwrap_or_else"
            | "ok_or"
            | "ok_or_else"
            | "is_some"
            | "is_none"
            | "is_ok"
            | "is_err"
            | "as_ref"
            | "as_mut"
            | "as_deref"
            | "as_bytes"
            | "as_slice"
            | "to_vec"
            | "into"
            | "from"
            | "try_into"
            | "default"
            | "trim"
            | "split"
            | "split_once"
            | "lines"
            | "chars"
            | "bytes"
            | "starts_with"
            | "ends_with"
            | "replace"
            | "to_lowercase"
            | "to_ascii_lowercase"
            | "to_uppercase"
            | "to_ascii_uppercase"
            | "parse"
            | "write"
            | "writeln"
            | "push"
            | "push_str"
            | "pop"
            | "iter"
            | "iter_mut"
            | "into_iter"
            | "collect"
            | "map"
            | "filter"
            | "fold"
            | "count"
            | "min"
            | "max"
            | "first"
            | "last"
            | "get_mut"
            | "with_capacity"
            | "capacity"
            | "reserve"
            | "truncate"
            | "drain"
            | "clear"
            | "saturating_sub"
            | "saturating_add"
            | "div_ceil"
            | "is_ascii_alphanumeric"
            | "is_ascii_alphabetic"
            | "is_ascii_digit"
            | "is_ascii_uppercase"
            | "is_ascii_lowercase"
            | "is_ascii_hexdigit"
            | "is_alphanumeric"
            | "is_whitespace"
            | "is_control"
            | "char_indices"
            | "len_utf8"
            | "from_utf8"
            | "from_utf8_lossy"
            | "from_str"
            | "from_str_radix"
            | "from_slice"
            | "lossy"
            | "to_string_lossy"
            | "to_string_pretty"
            | "as_os_str"
            | "file_name"
            | "file_stem"
            | "extension"
            | "parent"
            | "path"
            | "join"
            | "exists"
            | "is_dir"
            | "is_file"
            | "file_type"
            | "metadata"
            | "modified"
            | "read_dir"
            | "read_to_string"
            | "create_dir_all"
            | "remove_dir_all"
            | "remove_file"
            | "temp_dir"
            | "canonicalize"
            | "components"
            | "display"
            | "duration_since"
            | "as_secs"
            | "as_millis"
            | "as_nanos"
            | "elapsed"
            | "now"
            | "with_context"
            | "context"
            | "then_some"
            | "into_mut"
            | "into_values"
            | "into_keys"
            | "borrow"
            | "borrow_mut"
            | "fill"
            | "copy_from_slice"
            | "is_power_of_two"
            | "to_be_bytes"
            | "to_le_bytes"
            | "ln_1p"
            | "sqrt"
            | "round"
            | "abs"
            | "into_par_iter"
            | "par_iter"
            | "flat_map_iter"
            | "fetch_add"
            | "pop_front"
            | "push_back"
            | "get_or_init"
            | "captures"
            | "is_match"
            | "escape"
            | "case_insensitive"
            | "hash"
            | "to_hex"
            | "finalize"
            | "Borrowed"
            | "Owned"
            | "next_back"
            | "is_some_and"
            | "is_none_or"
            | "eq_ignore_ascii_case"
    ) {
        return true;
    }
    if let Some(qual) = receiver_or_qualifier {
        let q_leaf = qualifier_leaf(qual);
        if matches!(
            q_leaf,
            "String"
                | "Vec"
                | "Option"
                | "Result"
                | "Cow"
                | "Box"
                | "Arc"
                | "Rc"
                | "Path"
                | "PathBuf"
                | "File"
                | "BTreeMap"
                | "BTreeSet"
                | "HashMap"
                | "HashSet"
                | "FxHashMap"
                | "FxHashSet"
                | "OnceLock"
                | "Mutex"
                | "RwLock"
                | "Instant"
                | "SystemTime"
                | "Duration"
                | "mem"
                | "str"
                | "fs"
                | "env"
                | "io"
                | "fmt"
                | "thread"
                | "rayon"
                | "serde_json"
                | "blake3"
                | "regex"
                | "memchr"
                | "memmem"
                | "Finder"
                | "Regex"
                | "RegexBuilder"
                | "Hasher"
                | "WalkBuilder"
                | "Parser"
                | "Cli"
        ) {
            return true;
        }
    }
    raw_callee_name.starts_with("std::") || raw_callee_name.starts_with("core::")
}

fn qualifier_leaf(qualifier: &str) -> &str {
    qualifier
        .trim()
        .rsplit(['.', ':', '-', '>'])
        .next()
        .unwrap_or(qualifier)
        .trim()
}

/// True when a symbol's `enclosing_type` answers a call-site qualifier. C++ enclosing types are
/// namespace-qualified (`etl::ivector`), so the comparison accepts the full qualified name, a
/// bare leaf (`ivector`), and the namespace leaf of the enclosing type.
///
/// A qualifier that carries an explicit scope path (`b::Box`) must match as a whole path or as a
/// trailing sub-path: never fall back to leaf-only matching, which would bind
/// `b::Box::run()` to a conflicting `a::Box::run`.
fn enclosing_matches_qualifier(enclosing: &str, qualifier: &str) -> bool {
    let enclosing = enclosing.trim();
    let qualifier = qualifier.trim();
    if enclosing.eq_ignore_ascii_case(qualifier) {
        return true;
    }
    if qualifier.contains("::") {
        return enclosing_path_ends_with(enclosing, qualifier);
    }
    let leaf = qualifier_leaf(qualifier);
    if leaf.is_empty() {
        return false;
    }
    if enclosing.eq_ignore_ascii_case(leaf) {
        return true;
    }
    enclosing
        .rsplit("::")
        .next()
        .is_some_and(|enclosing_leaf| enclosing_leaf.eq_ignore_ascii_case(leaf))
}

/// True when `enclosing` ends with `::{qualifier}` (case-insensitive) and the qualifier is a
/// strict trailing sub-path (never the whole string; equality is handled by the caller).
fn enclosing_path_ends_with(enclosing: &str, qualifier: &str) -> bool {
    let Some(prefix_len) = enclosing.len().checked_sub(qualifier.len()) else {
        return false;
    };
    if prefix_len == 0 {
        return false;
    }
    enclosing
        .get(prefix_len..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(qualifier))
        && enclosing
            .get(..prefix_len)
            .is_some_and(|head| head.ends_with("::"))
}

/// True when the qualifier is directly the instance/class receiver (`self`, `cls`, `this`, `super`)
/// rather than a member attribute chain (`self._queue`), variable, or module name.
#[inline]
fn is_self_or_class_receiver(qualifier: &str) -> bool {
    let trimmed = qualifier.trim();
    trimmed.eq_ignore_ascii_case("self")
        || trimmed.eq_ignore_ascii_case("cls")
        || trimmed.eq_ignore_ascii_case("this")
        || trimmed.eq_ignore_ascii_case("super")
}

/// True when `qualifier` names a module/file stem, so `qualifier.member()` may legitimately refer
/// to a repository-level function defined in that module.
fn module_qualifier_matches(qualifier: &str, def_file: &str) -> bool {
    let leaf = qualifier_leaf(qualifier);
    if leaf.is_empty() {
        return false;
    }

    let mut segments = def_file.rsplit(['/', '\\']);
    let file_name = segments.next().unwrap_or(def_file);
    let stem = file_name
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(file_name);
    if stem.eq_ignore_ascii_case(leaf) {
        return true;
    }

    // Module directories (`pkg/module/mod.rs`, `pkg/module/__init__.py`) also name the module.
    segments
        .next()
        .is_some_and(|dir| dir.eq_ignore_ascii_case(leaf))
}

fn qualified_candidate_allowed(
    qualifier: &str,
    is_static_path_call: bool,
    ubiquitous_member: bool,
    sym: &ExtractedSymbol,
) -> bool {
    let q_leaf = qualifier_leaf(qualifier);
    // A method of the type named by the qualifier always answers the call.
    if let Some(enclosing) = sym.enclosing_type.as_deref() {
        if enclosing_matches_qualifier(enclosing, qualifier) {
            return true;
        }
        // If the call site uses an explicit `Type::func()` path or a PascalCase type/namespace
        // qualifier (`String::new()`, `Parser::new()`, `RegexBuilder::new()`), it can NEVER bind
        // to a method of a different `enclosing_type`.
        let q_starts_upper = q_leaf
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_uppercase());
        if is_static_path_call || q_starts_upper || sym.kind == SymbolKind::Constructor {
            return false;
        }
        // Ubiquitous container/IO/lifecycle methods of unrelated types are never guessed.
        return !ubiquitous_member;
    }

    if matches!(sym.kind, SymbolKind::Function | SymbolKind::Entrypoint) {
        // A standalone function only answers `qualifier.name()` or `qualifier::name()` when the
        // qualifier names its module.
        return module_qualifier_matches(qualifier, &sym.file);
    }

    !ubiquitous_member
}

fn normalize_import_path(raw_path: &str) -> String {
    let before_brace = raw_path.split('{').next().unwrap_or(raw_path);
    let cleaned = before_brace
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'))
        .trim_end_matches("::*")
        .trim_end_matches("/*")
        .trim_end_matches("::")
        .replace("::", "/")
        .replace('\\', "/");
    strip_rust_path_prefixes(&cleaned).to_string()
}

fn strip_rust_path_prefixes(path: &str) -> &str {
    let mut cur = path.trim_start_matches('/');
    loop {
        if let Some(rest) = cur.strip_prefix("crate/") {
            cur = rest;
        } else if let Some(rest) = cur.strip_prefix("super/") {
            cur = rest;
        } else if let Some(rest) = cur.strip_prefix("self/") {
            cur = rest;
        } else {
            break;
        }
    }
    cur
}

fn resolve_relative_import_path(caller_file: &str, raw_import: &str) -> Option<String> {
    let norm_imp = raw_import
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'))
        .replace('\\', "/");
    if !norm_imp.starts_with("./") && !norm_imp.starts_with("../") {
        return None;
    }

    let caller_norm = caller_file.replace('\\', "/");
    let mut stack: Vec<&str> = caller_norm.split('/').collect();
    if !stack.is_empty() {
        stack.pop(); // Remove caller filename
    }

    for seg in norm_imp.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }

    let joined = stack.join("/");
    Some(strip_source_extension(&joined))
}

#[inline]
fn strip_mod_suffix_matches(haystack: &str, base: &str, suffix: &str) -> bool {
    haystack
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix == base)
}

#[inline]
fn ends_with_slash_segment(haystack: &str, seg: &str) -> bool {
    haystack
        .strip_suffix(seg)
        .is_some_and(|prefix| prefix.ends_with('/'))
}

#[inline]
fn ends_with_slash_segment_suffix(haystack: &str, seg: &str, suffix: &str) -> bool {
    haystack
        .strip_suffix(suffix)
        .and_then(|s| s.strip_suffix(seg))
        .is_some_and(|prefix| prefix.ends_with('/'))
}

/// True when the import path names the given repository source file.
fn import_references_file(imp: &PrecomputedImport<'_>, def: &PrecomputedSymFile) -> bool {
    let def_we = def.def_without_ext.as_str();
    if def_we.is_empty() {
        return false;
    }
    if let Some(resolved_rel) = imp.rel_resolved.as_deref() {
        if !resolved_rel.is_empty()
            && (def_we == resolved_rel
                || strip_mod_suffix_matches(def_we, resolved_rel, "/index")
                || strip_mod_suffix_matches(def_we, resolved_rel, "/mod")
                || strip_mod_suffix_matches(def_we, resolved_rel, "/__init__"))
        {
            return true;
        }
    }
    let raw = imp.imp_without_ext.as_str();
    if raw.is_empty() {
        return false;
    }
    def_we == raw
        || ends_with_slash_segment(def_we, raw)
        || ends_with_slash_segment_suffix(def_we, raw, "/mod")
        || ends_with_slash_segment_suffix(def_we, raw, "/index")
        || ends_with_slash_segment_suffix(def_we, raw, "/__init__")
}

fn import_mentions_name(imp: &PrecomputedImport<'_>, qualifier: &str, leaf: &str) -> bool {
    let matches = |segment: &str| {
        segment.eq_ignore_ascii_case(leaf) || segment.eq_ignore_ascii_case(qualifier)
    };

    if let Some(top) = imp.first_segment.as_deref() {
        if matches(top) {
            return true;
        }
    }

    if let Some(last) = imp.last_segment.as_deref() {
        if matches(last) {
            return true;
        }
    }

    imp.imported_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(leaf) || name.eq_ignore_ascii_case(qualifier))
}

/// True when `qualifier` is an imported module/symbol that does not resolve to any repository
/// candidate file (e.g. `import subprocess` or `import time` in a Python module).
fn is_external_module_qualifier(
    qualifier: &str,
    imports: &[PrecomputedImport<'_>],
    candidate_indices: &[usize],
    sym_files: &SymFileIndex,
) -> bool {
    let leaf = qualifier_leaf(qualifier);
    if leaf.is_empty() {
        return false;
    }

    for imp in imports {
        if !import_mentions_name(imp, qualifier, leaf) {
            continue;
        }
        let references_repo_file = candidate_indices
            .iter()
            .any(|&idx| import_references_file(imp, sym_files.of(idx)));
        if !references_repo_file {
            return true;
        }
    }

    false
}

fn match_import_for_candidate(
    callee_name: &str,
    def: &PrecomputedSymFile,
    imports: &[PrecomputedImport<'_>],
) -> Option<usize> {
    let def_stem = def.def_stem.as_str();
    let def_without_ext = def.def_without_ext.as_str();

    let mut best_score: Option<usize> = None;

    for imp in imports {
        let explicit_name = imp
            .imported_names
            .iter()
            .any(|n| n == callee_name || n == "*");

        let exact_rel_match = imp.rel_resolved.as_deref().is_some_and(|rel| {
            !rel.is_empty()
                && (def_without_ext == rel
                    || strip_mod_suffix_matches(def_without_ext, rel, "/index"))
        });

        let imp_without_ext = imp.imp_without_ext.as_str();
        let imp_stem = imp.imp_stem.as_str();

        // When the import is a relative path (`./...` or `../...`), only match the resolved
        // relative target path rather than unrelated files that happen to share the same stem.
        let path_matches = if imp.rel_resolved.is_some() {
            exact_rel_match
        } else if !imp_without_ext.is_empty() && !def_without_ext.is_empty() {
            def_without_ext == imp_without_ext
                || ends_with_slash_segment(def_without_ext, imp_without_ext)
                || ends_with_slash_segment_suffix(def_without_ext, imp_without_ext, "/mod")
                || ends_with_slash_segment_suffix(def_without_ext, imp_without_ext, "/index")
                || ends_with_slash_segment_suffix(def_without_ext, imp_without_ext, "/__init__")
                || imp_without_ext.ends_with(def_without_ext)
                || (!imp_stem.is_empty()
                    && !def_stem.is_empty()
                    && imp_stem.eq_ignore_ascii_case(def_stem))
        } else {
            false
        };

        let score = match (explicit_name, exact_rel_match, path_matches) {
            (true, true, _) => Some(5),
            (false, true, _) if imp.implicit_header_or_module_import => Some(4),
            (true, false, true) => Some(3),
            (false, false, true) if imp.implicit_header_or_module_import => Some(2),
            (true, false, false)
                if imp.rel_resolved.is_none() && (imp.raw_norm.is_empty() || !imp.is_std_stem) =>
            {
                Some(1)
            }
            _ => None,
        };

        if let Some(s) = score {
            best_score = Some(best_score.map_or(s, |cur| cur.max(s)));
        }
    }

    best_score
}

fn strip_source_extension(path: &str) -> String {
    let trimmed = path.trim_start_matches("./").trim_start_matches('/');
    if let Some((prefix, ext)) = trimmed.rsplit_once('.') {
        if matches!(
            ext.to_ascii_lowercase().as_str(),
            "c" | "h"
                | "cc"
                | "cpp"
                | "cxx"
                | "hpp"
                | "hh"
                | "hxx"
                | "inl"
                | "rs"
                | "py"
                | "pyi"
                | "ts"
                | "tsx"
                | "mts"
                | "cts"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "astro"
                | "vue"
                | "svelte"
        ) {
            return prefix.to_string();
        }
    }
    trimmed.to_string()
}

fn common_dir_prefix_len(path_a: &str, path_b: &str) -> usize {
    let Some(a_idx) = path_a.rfind(['/', '\\']) else {
        return 0;
    };
    let Some(b_idx) = path_b.rfind(['/', '\\']) else {
        return 0;
    };
    let a_dir = &path_a[..a_idx];
    let b_dir = &path_b[..b_idx];

    a_dir
        .split(['/', '\\'])
        .zip(b_dir.split(['/', '\\']))
        .take_while(|(x, y)| x == y)
        .count()
}

fn scope_rank(scope: FileScope) -> u8 {
    match scope {
        FileScope::FirstParty => 0,
        FileScope::Test => 1,
        FileScope::VendorSdk => 2,
    }
}

fn infer_unit_section_id(unit: &ParsedFileUnit) -> String {
    if let Some(s) = unit.symbols.first() {
        if !s.section_id.is_empty() {
            return s.section_id.clone();
        }
    }
    if let Some(t) = unit.types.first() {
        if !t.section_id.is_empty() {
            return t.section_id.clone();
        }
    }
    if let Some(m) = unit.macros.first() {
        if !m.section_id.is_empty() {
            return m.section_id.clone();
        }
    }
    let rel = unit.scanned.rel_path.replace('\\', "/");
    match rel.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => dir
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-"),
        _ => "root".to_string(),
    }
}

const GENERIC_HEADER_STEMS: &[&str] = &[
    "main", "config", "types", "common", "board", "system", "version", "def", "defs", "utils",
    "hal", "bsp",
];

const GENERIC_BIT_MACROS: &[&str] = &[
    "SET_BIT",
    "CLEAR_BIT",
    "READ_BIT",
    "CLEAR_REG",
    "WRITE_REG",
    "READ_REG",
    "MODIFY_REG",
    "BIT",
    "_VAL2FLD",
    "_FLD2VAL",
    "UNUSED",
    "ARRAY_SIZE",
    "MIN",
    "MAX",
];

/// Returns `true` when `m` is a function-like macro whose expansion body references only its own
/// formal parameters (and contains no hex MMIO literal), e.g. `#define CLEAR_BIT(REG, BIT) ((REG) &= ~(BIT))`.
fn is_pure_param_fn_macro(m: &ExtractedMacro) -> bool {
    if m.hex_addr.is_some() {
        return false;
    }
    let Some((params_raw, body_raw)) = m.value_or_args.split_once(" -> ") else {
        return false;
    };
    if !params_raw.starts_with('(') {
        return false;
    }
    let params: FxHashSet<&str> = params_raw
        .trim_matches(|c| c == '(' || c == ')')
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    if params.is_empty() {
        return false;
    }

    let mut saw_param_ref = false;
    for tok in body_raw
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
    {
        if tok.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }
        if matches!(
            tok,
            "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
                | "int8_t"
                | "int16_t"
                | "int32_t"
                | "int64_t"
                | "size_t"
                | "uintptr_t"
                | "int"
                | "unsigned"
                | "signed"
                | "long"
                | "short"
                | "char"
                | "void"
                | "volatile"
                | "const"
                | "sizeof"
        ) {
            continue;
        }
        if params.contains(tok) {
            saw_param_ref = true;
        } else {
            return false;
        }
    }
    saw_param_ref
}

fn is_excluded_generic_macro(m: &ExtractedMacro) -> bool {
    m.kind == MacroKind::LinkerSection
        || GENERIC_BIT_MACROS.contains(&m.name.as_str())
        || is_pure_param_fn_macro(m)
}

fn compute_vendor_surface(
    units: &[ParsedFileUnit],
    symbols: &[ExtractedSymbol],
    types: &[ExtractedType],
    macros: &[ExtractedMacro],
    calls: &[ResolvedCallEdge],
) -> VendorSurfaceSummary {
    let total_vendor_files = units
        .iter()
        .filter(|u| u.scanned.scope == FileScope::VendorSdk)
        .count();
    let total_vendor_symbols = symbols
        .iter()
        .filter(|s| s.scope == FileScope::VendorSdk)
        .count();

    let mut vendor_sym_names: FxHashSet<&str> = FxHashSet::default();
    let mut vendor_sym_ids: FxHashMap<&str, &str> = FxHashMap::default();
    for s in symbols.iter().filter(|s| s.scope == FileScope::VendorSdk) {
        vendor_sym_names.insert(s.name.as_str());
        vendor_sym_ids.insert(s.symbol_id.as_str(), s.name.as_str());
    }

    let mut vendor_type_names: FxHashSet<&str> = FxHashSet::default();
    for t in types.iter().filter(|t| t.scope == FileScope::VendorSdk) {
        vendor_type_names.insert(t.name.as_str());
    }

    let mut vendor_macro_names: FxHashSet<&str> = FxHashSet::default();
    let mut vendor_mmio_names: FxHashSet<&str> = FxHashSet::default();
    for m in macros.iter().filter(|m| m.scope == FileScope::VendorSdk) {
        if is_excluded_generic_macro(m) {
            continue;
        }
        vendor_macro_names.insert(m.name.as_str());
        if matches!(
            m.kind,
            MacroKind::MmioAddress | MacroKind::RegisterAccess | MacroKind::Bitmask
        ) {
            vendor_mmio_names.insert(m.name.as_str());
        }
    }

    let mut vendor_file_stems: FxHashSet<String> = FxHashSet::default();
    let mut vendor_file_paths: FxHashSet<String> = FxHashSet::default();
    let mut first_party_files: FxHashSet<&str> = FxHashSet::default();

    for u in units {
        match u.scanned.scope {
            FileScope::VendorSdk => {
                let norm = u.scanned.rel_path.replace('\\', "/");
                vendor_file_paths.insert(norm.clone());
                if let Some(fname) = Path::new(&norm).file_name().and_then(|s| s.to_str()) {
                    let stem = Path::new(fname)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(fname)
                        .to_ascii_lowercase();
                    if !GENERIC_HEADER_STEMS.contains(&stem.as_str()) {
                        vendor_file_stems.insert(fname.to_ascii_lowercase());
                        vendor_file_stems.insert(stem);
                    }
                }
            }
            FileScope::FirstParty => {
                first_party_files.insert(u.scanned.rel_path.as_str());
            }
            FileScope::Test => {}
        }
    }

    // Precompute every segment-aligned suffix of every vendor path once, so an import
    // (`#include "stm32f4xx_hal.h"` or `#include "Drivers/STM32F4xx_HAL_Driver/Inc/x.h"`) can be
    // matched with one hash lookup instead of scanning every vendor path with `ends_with`.
    let mut vendor_path_suffixes: FxHashSet<&str> = FxHashSet::default();
    for path in &vendor_file_paths {
        vendor_path_suffixes.insert(path.as_str());
        let mut idx = 0usize;
        while let Some(pos) = path[idx..].find('/') {
            let start = idx + pos + 1;
            vendor_path_suffixes.insert(&path[start..]);
            idx = start;
        }
    }

    let mut active_vendor_symbols: BTreeSet<String> = BTreeSet::new();
    let mut active_mmio_registers: BTreeSet<String> = BTreeSet::new();
    let mut active_vendor_headers: BTreeSet<String> = BTreeSet::new();

    // All MMIO macros defined directly in first-party files are active (excluding generic bit macros / linker sections)
    for m in macros.iter().filter(|m| m.scope == FileScope::FirstParty) {
        if is_excluded_generic_macro(m) {
            continue;
        }
        if matches!(
            m.kind,
            MacroKind::MmioAddress | MacroKind::RegisterAccess | MacroKind::Bitmask
        ) {
            active_mmio_registers.insert(m.name.clone());
        }
    }

    let has_any_vendor = total_vendor_files > 0
        || total_vendor_symbols > 0
        || !vendor_type_names.is_empty()
        || !vendor_macro_names.is_empty()
        || !vendor_mmio_names.is_empty();

    if has_any_vendor {
        // Check resolved calls from first-party files
        for call in calls {
            if !first_party_files.contains(call.file.as_str()) {
                continue;
            }
            if GENERIC_BIT_MACROS.contains(&call.callee_name.as_str()) {
                continue;
            }
            if let Some(&vname) = vendor_sym_ids.get(call.callee_id.as_str()) {
                active_vendor_symbols.insert(vname.to_string());
            } else if vendor_sym_names.contains(call.callee_name.as_str())
                || vendor_macro_names.contains(call.callee_name.as_str())
            {
                active_vendor_symbols.insert(call.callee_name.clone());
            }
            if vendor_mmio_names.contains(call.callee_name.as_str()) {
                active_mmio_registers.insert(call.callee_name.clone());
            }
        }
    }

    // Check raw_xrefs, imports, signatures, and type fields in first-party units
    for unit in units
        .iter()
        .filter(|u| u.scanned.scope == FileScope::FirstParty)
    {
        for rx in &unit.raw_xrefs {
            let target = rx.target_name.as_str();
            if target.starts_with('.') || GENERIC_BIT_MACROS.contains(&target) {
                continue;
            }
            if matches!(
                rx.category.as_str(),
                "mmio_access" | "mmio_write" | "mmio_read"
            ) {
                active_mmio_registers.insert(rx.target_name.clone());
            }
            if !has_any_vendor {
                continue;
            }
            if vendor_sym_names.contains(target)
                || vendor_type_names.contains(target)
                || vendor_macro_names.contains(target)
            {
                active_vendor_symbols.insert(rx.target_name.clone());
            }
            if vendor_mmio_names.contains(target) {
                active_mmio_registers.insert(rx.target_name.clone());
            }
            if let Some((periph, reg)) = target.split_once("->").or_else(|| target.split_once('.'))
            {
                let periph = periph.trim();
                let reg = reg.trim();
                if vendor_macro_names.contains(periph) || vendor_type_names.contains(periph) {
                    active_vendor_symbols.insert(periph.to_string());
                }
                let combined = format!("{periph}_{reg}");
                if vendor_mmio_names.contains(combined.as_str()) {
                    active_mmio_registers.insert(combined);
                }
            }
        }

        if !has_any_vendor {
            continue;
        }

        for imp in &unit.imports {
            for imported in &imp.imported_names {
                if GENERIC_BIT_MACROS.contains(&imported.as_str()) {
                    continue;
                }
                if vendor_sym_names.contains(imported.as_str())
                    || vendor_type_names.contains(imported.as_str())
                    || vendor_macro_names.contains(imported.as_str())
                {
                    active_vendor_symbols.insert(imported.clone());
                }
                if vendor_mmio_names.contains(imported.as_str()) {
                    active_mmio_registers.insert(imported.clone());
                }
            }

            let raw_clean = imp
                .raw_path
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'))
                .replace('\\', "/");
            let raw_clean = raw_clean
                .trim_start_matches("./")
                .trim_matches('/')
                .to_string();
            let fname_lower = Path::new(&raw_clean)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let stem_lower = Path::new(&raw_clean)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            // A segment-aligned suffix of a known vendor path (`Inc/x.h`, `x.h`) matches the
            // import. Generic header stems (`hal.h`, `config.h`) only match an exact vendor path
            // unless the import carries a directory component, which keeps the previous rule.
            let is_generic_stem = GENERIC_HEADER_STEMS.contains(&stem_lower.as_str());
            let path_boundary_match = if is_generic_stem && !raw_clean.contains('/') {
                vendor_file_paths.contains(raw_clean.as_str())
            } else {
                vendor_path_suffixes.contains(raw_clean.as_str())
            };
            let stem_fallback_match = !is_generic_stem
                && ((!fname_lower.is_empty() && vendor_file_stems.contains(&fname_lower))
                    || (!stem_lower.is_empty() && vendor_file_stems.contains(&stem_lower)));

            if (path_boundary_match || stem_fallback_match) && !raw_clean.is_empty() {
                active_vendor_headers.insert(raw_clean);
            }
        }

        for sym in &unit.symbols {
            for token in sym
                .signature
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|t| !t.is_empty())
            {
                if vendor_type_names.contains(token) {
                    active_vendor_symbols.insert(token.to_string());
                }
            }
        }

        for ty in &unit.types {
            for token in ty
                .fields_summary
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|t| !t.is_empty())
            {
                if vendor_type_names.contains(token) {
                    active_vendor_symbols.insert(token.to_string());
                }
            }
        }
    }

    VendorSurfaceSummary {
        total_vendor_files,
        total_vendor_symbols,
        active_vendor_symbols: active_vendor_symbols.into_iter().collect(),
        active_mmio_registers: active_mmio_registers.into_iter().collect(),
        active_vendor_headers: active_vendor_headers.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArchLayer, LanguageKind, ScannedFile, SymbolKind, Visibility};
    use std::path::PathBuf;

    fn sample_scanned_with_language(
        rel_path: &str,
        scope: FileScope,
        layer: ArchLayer,
        language: LanguageKind,
    ) -> ScannedFile {
        let mut scanned = sample_scanned(rel_path, scope, layer);
        scanned.language = language;
        scanned
    }

    fn sample_prototype(
        file: &str,
        name: &str,
        line: usize,
        scope: FileScope,
        layer: ArchLayer,
        section_id: &str,
        doc_summary: &str,
    ) -> ExtractedSymbol {
        let mut symbol = sample_symbol(file, name, line, scope, layer, section_id);
        symbol.end_line = line;
        symbol.signature = format!("void {name}(void);");
        symbol.doc_summary = doc_summary.to_string();
        symbol
    }

    fn sample_call(
        caller_file: &str,
        caller_name: &str,
        caller_start_line: usize,
        callee_name: &str,
        receiver_or_qualifier: Option<&str>,
        call_line: usize,
    ) -> crate::model::RawCallSite {
        crate::model::RawCallSite {
            caller_file: caller_file.to_string(),
            caller_name: caller_name.to_string(),
            caller_start_line,
            callee_name: callee_name.to_string(),
            receiver_or_qualifier: receiver_or_qualifier.map(ToOwned::to_owned),
            call_line,
        }
    }

    #[test]
    fn collect_symbol_tables_parallel_batches_preserve_rows_and_order() {
        // Cross the 512-unit parallel-clone batch boundary and feed units in reverse path order.
        let count = 600usize;
        let mut units: Vec<ParsedFileUnit> = Vec::with_capacity(count);
        for i in (0..count).rev() {
            let file = format!("src/f{i:03}.c");
            let mut unit = sample_unit(
                &file,
                FileScope::FirstParty,
                ArchLayer::Drivers,
                LanguageKind::C,
                vec![sample_symbol(
                    &file,
                    &format!("fn_{i}"),
                    i + 1,
                    FileScope::FirstParty,
                    ArchLayer::Drivers,
                    "01-src",
                )],
                Vec::new(),
                Vec::new(),
            );
            unit.macros.push(ExtractedMacro {
                name: format!("M_{i}"),
                kind: MacroKind::ObjectMacro,
                value_or_args: "1".to_string(),
                hex_addr: None,
                file: file.clone(),
                line: i + 1,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Drivers,
                section_id: "01-src".to_string(),
                description: String::new(),
            });
            unit.types.push(ExtractedType {
                type_id: format!("{file}::T_{i}"),
                name: format!("T_{i}"),
                kind: crate::model::TypeKind::Struct,
                visibility: Visibility::Public,
                file: file.clone(),
                start_line: 1,
                end_line: 2,
                fields_summary: String::new(),
                doc_summary: String::new(),
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Drivers,
                section_id: "01-src".to_string(),
            });
            units.push(unit);
        }

        let (symbols, types, macros) = collect_symbol_tables(&units);
        assert_eq!(symbols.len(), count);
        assert_eq!(types.len(), count);
        assert_eq!(macros.len(), count);
        for i in 0..count {
            assert_eq!(symbols[i].name, format!("fn_{i}"));
            assert_eq!(types[i].name, format!("T_{i}"));
            assert_eq!(macros[i].name, format!("M_{i}"));
        }
        assert!(symbols.windows(2).all(
            |w| (w[0].file.as_str(), w[0].start_line) <= (w[1].file.as_str(), w[1].start_line)
        ));
        assert!(macros
            .windows(2)
            .all(|w| (w[0].file.as_str(), w[0].line) <= (w[1].file.as_str(), w[1].line)));
        assert!(types.windows(2).all(
            |w| (w[0].file.as_str(), w[0].start_line) <= (w[1].file.as_str(), w[1].start_line)
        ));
    }

    fn sample_unit(
        rel_path: &str,
        scope: FileScope,
        layer: ArchLayer,
        language: LanguageKind,
        symbols: Vec<ExtractedSymbol>,
        imports: Vec<ExtractedImport>,
        raw_calls: Vec<crate::model::RawCallSite>,
    ) -> ParsedFileUnit {
        ParsedFileUnit {
            scanned: sample_scanned_with_language(rel_path, scope, layer, language),
            symbols,
            types: Vec::new(),
            macros: Vec::new(),
            imports,
            raw_calls,
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        }
    }

    fn find_call<'a>(calls: &'a [ResolvedCallEdge], callee_name: &str) -> &'a ResolvedCallEdge {
        calls
            .iter()
            .find(|c| c.callee_name == callee_name)
            .unwrap_or_else(|| panic!("missing resolved call edge for {callee_name}"))
    }
    fn sample_scanned(rel_path: &str, scope: FileScope, layer: ArchLayer) -> ScannedFile {
        ScannedFile {
            rel_path: rel_path.to_string(),
            abs_path: PathBuf::from(rel_path),
            language: LanguageKind::C,
            scope,
            arch_layer: layer,
            size_bytes: 256,
            mtime_secs: 0,
            mtime_nanos: 0,
            blake3_hash: "hash".to_string(),
            line_count: 30,
        }
    }

    fn sample_symbol(
        file: &str,
        name: &str,
        start_line: usize,
        scope: FileScope,
        layer: ArchLayer,
        section_id: &str,
    ) -> ExtractedSymbol {
        ExtractedSymbol {
            symbol_id: format!("{file}::{name}"),
            name: name.to_string(),
            qualified_name: name.to_string(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            file: file.to_string(),
            start_line,
            end_line: start_line + 5,
            signature: format!("void {name}(void)"),
            doc_summary: String::new(),
            enclosing_type: None,
            scope,
            arch_layer: layer,
            section_id: section_id.to_string(),
        }
    }

    #[test]
    fn test_resolve_and_link_tiers_and_vendor_surface() {
        let unit_app = ParsedFileUnit {
            scanned: sample_scanned("src/app/main.c", FileScope::FirstParty, ArchLayer::App),
            symbols: vec![
                sample_symbol(
                    "src/app/main.c",
                    "main",
                    10,
                    FileScope::FirstParty,
                    ArchLayer::App,
                    "src-app",
                ),
                sample_symbol(
                    "src/app/main.c",
                    "local_helper",
                    20,
                    FileScope::FirstParty,
                    ArchLayer::App,
                    "src-app",
                ),
            ],
            types: Vec::new(),
            macros: Vec::new(),
            imports: vec![
                ExtractedImport {
                    file: "src/app/main.c".to_string(),
                    line: 1,
                    raw_path: "drivers/uart.h".to_string(),
                    imported_names: Vec::new(),
                    is_system: false,
                },
                ExtractedImport {
                    file: "src/app/main.c".to_string(),
                    line: 2,
                    raw_path: "vendor/cmsis/stm32_hal.h".to_string(),
                    imported_names: Vec::new(),
                    is_system: false,
                },
            ],
            raw_calls: vec![
                // Tier 1: SameFile
                crate::model::RawCallSite {
                    caller_file: "src/app/main.c".to_string(),
                    caller_name: "main".to_string(),
                    caller_start_line: 10,
                    callee_name: "local_helper".to_string(),
                    receiver_or_qualifier: None,
                    call_line: 12,
                },
                // Tier 2: ImportResolved
                crate::model::RawCallSite {
                    caller_file: "src/app/main.c".to_string(),
                    caller_name: "main".to_string(),
                    caller_start_line: 10,
                    callee_name: "uart_init".to_string(),
                    receiver_or_qualifier: None,
                    call_line: 13,
                },
                // Tier 3: UniqueGlobal
                crate::model::RawCallSite {
                    caller_file: "src/app/main.c".to_string(),
                    caller_name: "main".to_string(),
                    caller_start_line: 10,
                    callee_name: "HAL_GPIO_Init".to_string(),
                    receiver_or_qualifier: None,
                    call_line: 14,
                },
                // Tier 5: ExternalOrMacro
                crate::model::RawCallSite {
                    caller_file: "src/app/main.c".to_string(),
                    caller_name: "main".to_string(),
                    caller_start_line: 10,
                    callee_name: "printf".to_string(),
                    receiver_or_qualifier: None,
                    call_line: 15,
                },
            ],
            raw_xrefs: vec![crate::model::RawXrefSite {
                file: "src/app/main.c".to_string(),
                line: 16,
                enclosing_symbol: Some("src/app/main.c::main".to_string()),
                target_name: "GPIOA->MODER".to_string(),
                category: "mmio_access".to_string(),
                context: "GPIOA->MODER |= 1;".to_string(),
            }],
            parse_errors: 0,
        };

        let unit_drv = ParsedFileUnit {
            scanned: sample_scanned(
                "src/drivers/uart.c",
                FileScope::FirstParty,
                ArchLayer::Drivers,
            ),
            symbols: vec![sample_symbol(
                "src/drivers/uart.c",
                "uart_init",
                5,
                FileScope::FirstParty,
                ArchLayer::Drivers,
                "src-drivers",
            )],
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        };

        let unit_other = ParsedFileUnit {
            scanned: sample_scanned(
                "vendor/sdk/uart_legacy.c",
                FileScope::VendorSdk,
                ArchLayer::VendorHal,
            ),
            symbols: vec![
                sample_symbol(
                    "vendor/sdk/uart_legacy.c",
                    "uart_init",
                    5,
                    FileScope::VendorSdk,
                    ArchLayer::VendorHal,
                    "vendor-sdk",
                ),
                sample_symbol(
                    "vendor/sdk/uart_legacy.c",
                    "HAL_GPIO_Init",
                    25,
                    FileScope::VendorSdk,
                    ArchLayer::VendorHal,
                    "vendor-sdk",
                ),
            ],
            types: Vec::new(),
            macros: vec![ExtractedMacro {
                name: "GPIOA_MODER".to_string(),
                kind: MacroKind::MmioAddress,
                value_or_args: "0x40020000".to_string(),
                hex_addr: Some("0x40020000".to_string()),
                file: "vendor/cmsis/stm32_hal.h".to_string(),
                line: 10,
                scope: FileScope::VendorSdk,
                arch_layer: ArchLayer::VendorHal,
                section_id: "vendor-cmsis".to_string(),
                description: "GPIOA mode register".to_string(),
            }],
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        };

        let (_syms, _types, _macros, calls, xrefs, vendor) =
            resolve_and_link(&[unit_app, unit_drv, unit_other]);

        assert_eq!(calls.len(), 4);
        let c_local = calls
            .iter()
            .find(|c| c.callee_name == "local_helper")
            .unwrap();
        assert_eq!(c_local.tier, ResolutionTier::SameFile);

        let c_uart = calls.iter().find(|c| c.callee_name == "uart_init").unwrap();
        assert_eq!(c_uart.tier, ResolutionTier::ImportResolved);
        assert_eq!(c_uart.callee_id, "src/drivers/uart.c::uart_init");

        let c_hal = calls
            .iter()
            .find(|c| c.callee_name == "HAL_GPIO_Init")
            .unwrap();
        assert_eq!(c_hal.tier, ResolutionTier::UniqueGlobal);

        let c_ext = calls.iter().find(|c| c.callee_name == "printf").unwrap();
        assert_eq!(c_ext.tier, ResolutionTier::ExternalOrMacro);

        assert!(xrefs
            .iter()
            .any(|x| x.category == "mmio_access" && x.symbol == "GPIOA->MODER"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "macro_def" && x.symbol == "GPIOA_MODER"));
        assert!(xrefs
            .iter()
            .any(|x| x.category == "call" && x.symbol == "uart_init"));
        assert_eq!(vendor.total_vendor_files, 1);
        assert_eq!(vendor.total_vendor_symbols, 2);
        assert!(vendor
            .active_vendor_symbols
            .contains(&"HAL_GPIO_Init".to_string()));
        assert!(vendor
            .active_mmio_registers
            .contains(&"GPIOA->MODER".to_string()));
    }

    #[test]
    fn test_python_object_and_module_calls_do_not_bind_to_unrelated_symbols() {
        // Python caller with object/module receivers.
        let unit_tool = sample_unit(
            "scripts/tool.py",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::Python,
            vec![sample_symbol(
                "scripts/tool.py",
                "run_tool",
                10,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "scripts",
            )],
            vec![ExtractedImport {
                file: "scripts/tool.py".to_string(),
                line: 1,
                raw_path: "time".to_string(),
                imported_names: Vec::new(),
                is_system: false,
            }],
            vec![
                // `session.commit()`: a DB session object, not a repository function.
                sample_call(
                    "scripts/tool.py",
                    "run_tool",
                    10,
                    "commit",
                    Some("session"),
                    11,
                ),
                // `dict.get()`
                sample_call("scripts/tool.py", "run_tool", 10, "get", Some("dict"), 12),
                // `time.sleep()`: stdlib module import that is not part of the repository.
                sample_call("scripts/tool.py", "run_tool", 10, "sleep", Some("time"), 13),
                // `len(...)`: Python builtin.
                sample_call("scripts/tool.py", "run_tool", 10, "len", None, 14),
                // `codec.encode_frame(...)`: module-qualified call that *does* live in the repo.
                sample_call(
                    "scripts/tool.py",
                    "run_tool",
                    10,
                    "encode_frame",
                    Some("codec"),
                    15,
                ),
            ],
        );

        // JavaScript helpers that merely share the same leaf names.
        let unit_js = sample_unit(
            "frontend/db.js",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::JavaScript,
            vec![
                sample_symbol(
                    "frontend/db.js",
                    "commit",
                    3,
                    FileScope::FirstParty,
                    ArchLayer::Libs,
                    "frontend",
                ),
                sample_symbol(
                    "frontend/db.js",
                    "sleep",
                    8,
                    FileScope::FirstParty,
                    ArchLayer::Libs,
                    "frontend",
                ),
            ],
            Vec::new(),
            Vec::new(),
        );

        // An unrelated Python `def get()` / `def len()` elsewhere in the repository.
        let unit_helpers = sample_unit(
            "scripts/helpers.py",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::Python,
            vec![sample_symbol(
                "scripts/helpers.py",
                "get",
                4,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "scripts",
            )],
            Vec::new(),
            Vec::new(),
        );

        let unit_sizes = sample_unit(
            "scripts/sizes.py",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::Python,
            vec![sample_symbol(
                "scripts/sizes.py",
                "len",
                4,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "scripts",
            )],
            Vec::new(),
            Vec::new(),
        );

        // A Python `def sleep()` in another module (must not capture `time.sleep()`).
        let unit_timing = sample_unit(
            "scripts/timing.py",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::Python,
            vec![sample_symbol(
                "scripts/timing.py",
                "sleep",
                6,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "scripts",
            )],
            Vec::new(),
            Vec::new(),
        );

        // The module-qualified target.
        let unit_codec = sample_unit(
            "scripts/codec.py",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::Python,
            vec![sample_symbol(
                "scripts/codec.py",
                "encode_frame",
                5,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "scripts",
            )],
            Vec::new(),
            Vec::new(),
        );

        let (_symbols, _types, _macros, calls, _xrefs, _vendor) = resolve_and_link(&[
            unit_tool,
            unit_js,
            unit_helpers,
            unit_sizes,
            unit_timing,
            unit_codec,
        ]);

        assert_eq!(calls.len(), 5);

        for callee in ["commit", "get", "sleep", "len"] {
            let edge = find_call(&calls, callee);
            assert_eq!(
                edge.tier,
                ResolutionTier::ExternalOrMacro,
                "`{callee}` must not bind to a same-named repository symbol"
            );
            assert_eq!(edge.callee_id, format!("external::{callee}"));
        }

        // Module-qualified calls that name a real repository module still resolve.
        let codec_edge = find_call(&calls, "encode_frame");
        assert_eq!(codec_edge.tier, ResolutionTier::UniqueGlobal);
        assert_eq!(codec_edge.callee_id, "scripts/codec.py::encode_frame");
    }

    fn sample_method(
        file: &str,
        name: &str,
        enclosing_type: &str,
        start_line: usize,
        scope: FileScope,
        layer: ArchLayer,
        section_id: &str,
    ) -> ExtractedSymbol {
        let mut symbol = sample_symbol(file, name, start_line, scope, layer, section_id);
        symbol.qualified_name = format!("{enclosing_type}::{name}");
        symbol.kind = SymbolKind::Method;
        symbol.enclosing_type = Some(enclosing_type.to_string());
        symbol
    }

    fn callee_names(calls: &[ResolvedCallEdge]) -> BTreeSet<&str> {
        calls.iter().map(|c| c.callee_name.as_str()).collect()
    }

    #[test]
    fn prune_rule1_drops_qualified_calls_to_undefined_short_names() {
        let unit_caller = sample_unit(
            "app/uses.py",
            FileScope::FirstParty,
            ArchLayer::App,
            LanguageKind::Python,
            vec![sample_symbol(
                "app/uses.py",
                "run",
                1,
                FileScope::FirstParty,
                ArchLayer::App,
                "app",
            )],
            Vec::new(),
            vec![
                // Defined (in another language) => the name exists in the repository, keep the edge.
                sample_call("app/uses.py", "run", 1, "commit", Some("store"), 2),
                // Undefined receiver methods => structural noise.
                sample_call("app/uses.py", "run", 1, "flush", Some("store"), 3),
                sample_call("app/uses.py", "run", 1, "info", Some("logger"), 4),
                // Bare builtins have no receiver => never pruned by rule 1.
                sample_call("app/uses.py", "run", 1, "print", None, 5),
                sample_call("app/uses.py", "run", 1, "len", None, 6),
            ],
        );
        let unit_js = sample_unit(
            "frontend/db.js",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::JavaScript,
            vec![sample_symbol(
                "frontend/db.js",
                "commit",
                3,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "frontend",
            )],
            Vec::new(),
            Vec::new(),
        );
        let unit_c = sample_unit(
            "hal/board.c",
            FileScope::VendorSdk,
            ArchLayer::VendorHal,
            LanguageKind::C,
            vec![sample_symbol(
                "hal/board.c",
                "board_entry",
                2,
                FileScope::VendorSdk,
                ArchLayer::VendorHal,
                "hal",
            )],
            Vec::new(),
            vec![
                sample_call("hal/board.c", "board_entry", 2, "vendor_undef", None, 2),
                sample_call("hal/board.c", "board_entry", 2, "malloc", None, 2),
            ],
        );

        let (_symbols, _types, _macros, calls, _xrefs, _vendor) =
            resolve_and_link(&[unit_caller, unit_js, unit_c]);

        assert_eq!(
            callee_names(&calls),
            BTreeSet::from(["commit", "len", "malloc", "print", "vendor_undef"]),
            "rule 1 must drop only receiver calls to names defined nowhere: {calls:?}"
        );
        let commit = find_call(&calls, "commit");
        assert_eq!(commit.tier, ResolutionTier::ExternalOrMacro);
        assert_eq!(commit.callee_id, "external::commit");
    }

    #[test]
    fn prune_rule2_drops_rust_bare_pascal_case_calls_but_keeps_callables() {
        let unit_lib = sample_unit(
            "src/lib.rs",
            FileScope::FirstParty,
            ArchLayer::Core,
            LanguageKind::Rust,
            vec![
                sample_symbol(
                    "src/lib.rs",
                    "real_fn",
                    1,
                    FileScope::FirstParty,
                    ArchLayer::Core,
                    "src",
                ),
                sample_symbol(
                    "src/lib.rs",
                    "use_it",
                    2,
                    FileScope::FirstParty,
                    ArchLayer::Core,
                    "src",
                ),
            ],
            Vec::new(),
            vec![
                // Bare PascalCase constructor with no callable definition => noise.
                sample_call("src/lib.rs", "use_it", 2, "Wrapper", None, 2),
                // Resolved same-file call stays resolved.
                sample_call("src/lib.rs", "use_it", 2, "real_fn", None, 2),
                // Bare lowercase unknown callable is not rule-2 noise.
                sample_call("src/lib.rs", "use_it", 2, "helper_undefined", None, 2),
                // PascalCase name defined as a callable function stays.
                sample_call("src/lib.rs", "use_it", 2, "BuilderFactory", None, 2),
                // Qualified variant path whose short name is defined nowhere => rule 1 noise.
                sample_call(
                    "src/lib.rs",
                    "use_it",
                    2,
                    "ChipsrcError::ParserConfig",
                    Some("ChipsrcError"),
                    2,
                ),
                // Qualified path whose short name is defined stays external (rule 1 boundary).
                sample_call(
                    "src/lib.rs",
                    "use_it",
                    2,
                    "Wrapper::assemble",
                    Some("Wrapper"),
                    2,
                ),
            ],
        );
        let unit_builder = sample_unit(
            "src/builder.rs",
            FileScope::FirstParty,
            ArchLayer::Core,
            LanguageKind::Rust,
            vec![sample_symbol(
                "src/builder.rs",
                "BuilderFactory",
                4,
                FileScope::FirstParty,
                ArchLayer::Core,
                "src",
            )],
            Vec::new(),
            Vec::new(),
        );
        let unit_container = sample_unit(
            "src/model.rs",
            FileScope::FirstParty,
            ArchLayer::Domain,
            LanguageKind::Rust,
            vec![sample_method(
                "src/model.rs",
                "assemble",
                "ConvertConfig",
                10,
                FileScope::FirstParty,
                ArchLayer::Domain,
                "src",
            )],
            Vec::new(),
            Vec::new(),
        );
        let unit_py = sample_unit(
            "script/tool.py",
            FileScope::FirstParty,
            ArchLayer::Libs,
            LanguageKind::Python,
            vec![sample_symbol(
                "script/tool.py",
                "run_tool",
                1,
                FileScope::FirstParty,
                ArchLayer::Libs,
                "script",
            )],
            Vec::new(),
            vec![sample_call(
                "script/tool.py",
                "run_tool",
                1,
                "Store",
                None,
                2,
            )],
        );

        let (_symbols, _types, _macros, calls, _xrefs, _vendor) =
            resolve_and_link(&[unit_lib, unit_builder, unit_container, unit_py]);

        assert_eq!(
            callee_names(&calls),
            BTreeSet::from([
                "BuilderFactory",
                "Store",
                "Wrapper::assemble",
                "helper_undefined",
                "real_fn"
            ]),
            "rule 2 must drop only bare Rust PascalCase calls with no callable: {calls:?}"
        );
        assert_eq!(
            find_call(&calls, "Wrapper::assemble").tier,
            ResolutionTier::ExternalOrMacro
        );
        assert_eq!(
            find_call(&calls, "BuilderFactory").tier,
            ResolutionTier::UniqueGlobal
        );
        assert_eq!(
            find_call(&calls, "Store").tier,
            ResolutionTier::ExternalOrMacro,
            "rule 2 applies to Rust only"
        );
    }

    #[test]
    fn test_c_header_prototype_merges_with_implementation() {
        let unit_header = sample_unit(
            "src/drvs/drvAdc.h",
            FileScope::FirstParty,
            ArchLayer::Drivers,
            LanguageKind::C,
            vec![
                sample_prototype(
                    "src/drvs/drvAdc.h",
                    "adc_GetValue",
                    8,
                    FileScope::FirstParty,
                    ArchLayer::Drivers,
                    "src-drvs",
                    "Reads the latest ADC conversion result.",
                ),
                // Header-only `static inline` helper: must never be dropped.
                {
                    let mut symbol = sample_symbol(
                        "src/drvs/drvAdc.h",
                        "drvAdc_IsReady",
                        12,
                        FileScope::FirstParty,
                        ArchLayer::Drivers,
                        "src-drvs",
                    );
                    symbol.visibility = Visibility::Static;
                    symbol
                },
                // Declaration-only interface with no translation unit implementation.
                sample_prototype(
                    "src/drvs/drvAdc.h",
                    "adc_Config",
                    20,
                    FileScope::FirstParty,
                    ArchLayer::Drivers,
                    "src-drvs",
                    "",
                ),
            ],
            Vec::new(),
            Vec::new(),
        );

        let unit_impl = sample_unit(
            "src/drvs/drvAdc.c",
            FileScope::FirstParty,
            ArchLayer::Drivers,
            LanguageKind::C,
            vec![sample_symbol(
                "src/drvs/drvAdc.c",
                "adc_GetValue",
                10,
                FileScope::FirstParty,
                ArchLayer::Drivers,
                "src-drvs",
            )],
            Vec::new(),
            Vec::new(),
        );

        let unit_app = sample_unit(
            "src/app/main.c",
            FileScope::FirstParty,
            ArchLayer::App,
            LanguageKind::C,
            vec![sample_symbol(
                "src/app/main.c",
                "main",
                5,
                FileScope::FirstParty,
                ArchLayer::App,
                "src-app",
            )],
            vec![ExtractedImport {
                file: "src/app/main.c".to_string(),
                line: 1,
                raw_path: "drvs/drvAdc.h".to_string(),
                imported_names: Vec::new(),
                is_system: false,
            }],
            vec![
                sample_call("src/app/main.c", "main", 5, "adc_GetValue", None, 7),
                // Header prototype without a `.c` implementation keeps resolving to the header.
                sample_call("src/app/main.c", "main", 5, "adc_Config", None, 8),
            ],
        );

        let (symbols, _types, _macros, calls, _xrefs, _vendor) =
            resolve_and_link(&[unit_header, unit_impl, unit_app]);

        let ids: Vec<&str> = symbols.iter().map(|s| s.symbol_id.as_str()).collect();
        assert!(
            !ids.contains(&"src/drvs/drvAdc.h::adc_GetValue"),
            "redundant header prototype must be merged into the implementation"
        );
        assert!(ids.contains(&"src/drvs/drvAdc.c::adc_GetValue"));
        assert!(ids.contains(&"src/drvs/drvAdc.h::drvAdc_IsReady"));
        assert!(ids.contains(&"src/drvs/drvAdc.h::adc_Config"));

        let impl_symbol = symbols
            .iter()
            .find(|s| s.symbol_id == "src/drvs/drvAdc.c::adc_GetValue")
            .expect("implementation symbol");
        assert_eq!(
            impl_symbol.doc_summary,
            "Reads the latest ADC conversion result."
        );

        let get_value = find_call(&calls, "adc_GetValue");
        assert_eq!(get_value.tier, ResolutionTier::ImportResolved);
        assert_eq!(get_value.callee_id, "src/drvs/drvAdc.c::adc_GetValue");

        let config = find_call(&calls, "adc_Config");
        assert_eq!(config.callee_id, "src/drvs/drvAdc.h::adc_Config");
    }

    #[test]
    fn test_qualified_constructor_and_ubiquitous_method_isolation() {
        let mut cfg_new = sample_symbol(
            "crates/chipsrc-core/src/model.rs",
            "new",
            10,
            FileScope::FirstParty,
            ArchLayer::Domain,
            "crates-chipsrc-core",
        );
        cfg_new.qualified_name = "ConvertConfig::new".to_string();
        cfg_new.kind = SymbolKind::Constructor;
        cfg_new.enclosing_type = Some("ConvertConfig".to_string());

        let mut layer_as_str = sample_symbol(
            "crates/chipsrc-core/src/model.rs",
            "as_str",
            30,
            FileScope::FirstParty,
            ArchLayer::Domain,
            "crates-chipsrc-core",
        );
        layer_as_str.qualified_name = "ArchLayer::as_str".to_string();
        layer_as_str.kind = SymbolKind::Method;
        layer_as_str.enclosing_type = Some("ArchLayer".to_string());

        let unit_model = sample_unit(
            "crates/chipsrc-core/src/model.rs",
            FileScope::FirstParty,
            ArchLayer::Domain,
            LanguageKind::Rust,
            vec![cfg_new, layer_as_str],
            Vec::new(),
            Vec::new(),
        );

        let unit_caller = sample_unit(
            "crates/chipsrc-core/src/parser.rs",
            FileScope::FirstParty,
            ArchLayer::Core,
            LanguageKind::Rust,
            vec![sample_symbol(
                "crates/chipsrc-core/src/parser.rs",
                "parse_files",
                10,
                FileScope::FirstParty,
                ArchLayer::Core,
                "crates-chipsrc-core",
            )],
            Vec::new(),
            vec![
                // Explicit ConvertConfig::new() MUST resolve
                sample_call(
                    "crates/chipsrc-core/src/parser.rs",
                    "parse_files",
                    10,
                    "ConvertConfig::new",
                    Some("ConvertConfig"),
                    12,
                ),
                // String::new() and Parser::new() must NOT resolve to ConvertConfig::new
                sample_call(
                    "crates/chipsrc-core/src/parser.rs",
                    "parse_files",
                    10,
                    "String::new",
                    Some("String"),
                    13,
                ),
                sample_call(
                    "crates/chipsrc-core/src/parser.rs",
                    "parse_files",
                    10,
                    "Parser::new",
                    Some("Parser"),
                    14,
                ),
                // s.as_str() on arbitrary variable must NOT resolve to ArchLayer::as_str
                sample_call(
                    "crates/chipsrc-core/src/parser.rs",
                    "parse_files",
                    10,
                    "as_str",
                    Some("name"),
                    15,
                ),
            ],
        );

        let (_symbols, _types, _macros, calls, _xrefs, _vendor) =
            resolve_and_link(&[unit_model, unit_caller]);

        assert!(
            calls.iter().any(|c| {
                c.callee_name == "ConvertConfig::new"
                    && c.callee_id == "crates/chipsrc-core/src/model.rs::new"
                    && c.tier == ResolutionTier::UniqueGlobal
            }),
            "ConvertConfig::new() must resolve to ConvertConfig::new"
        );
        assert!(
            !calls
                .iter()
                .any(|c| c.callee_name != "ConvertConfig::new" && c.callee_id.ends_with("::new")),
            "String::new / Parser::new must never bind to ConvertConfig::new: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.callee_id.ends_with("::as_str")),
            "name.as_str() must never bind to ArchLayer::as_str: {calls:?}"
        );
    }

    #[test]
    fn test_inline_cfg_test_helpers_resolve_same_file() {
        let helper_sym = sample_symbol(
            "crates/core/src/lib.rs",
            "make_unit",
            100,
            FileScope::Test,
            ArchLayer::Tests,
            "crates-core",
        );
        let test_fn = sample_symbol(
            "crates/core/src/lib.rs",
            "test_something",
            110,
            FileScope::Test,
            ArchLayer::Tests,
            "crates-core",
        );
        let unit = sample_unit(
            "crates/core/src/lib.rs",
            FileScope::FirstParty,
            ArchLayer::Core,
            LanguageKind::Rust,
            vec![helper_sym, test_fn],
            Vec::new(),
            vec![sample_call(
                "crates/core/src/lib.rs",
                "test_something",
                110,
                "make_unit",
                None,
                112,
            )],
        );

        let (_symbols, _types, _macros, calls, _xrefs, _vendor) = resolve_and_link(&[unit]);
        let edge = find_call(&calls, "make_unit");
        assert_eq!(edge.tier, ResolutionTier::SameFile);
        assert_eq!(edge.callee_id, "crates/core/src/lib.rs::make_unit");
    }

    fn cpp_method_symbol(
        file: &str,
        enclosing: &str,
        name: &str,
        start_line: usize,
    ) -> ExtractedSymbol {
        ExtractedSymbol {
            symbol_id: format!("{file}::{enclosing}::{name}"),
            name: name.to_string(),
            qualified_name: format!("{enclosing}::{name}"),
            kind: SymbolKind::Method,
            visibility: Visibility::Public,
            file: file.to_string(),
            start_line,
            end_line: start_line + 1,
            signature: format!("static void {name}()"),
            doc_summary: String::new(),
            enclosing_type: Some(enclosing.to_string()),
            scope: FileScope::FirstParty,
            arch_layer: ArchLayer::Core,
            section_id: "src".to_string(),
        }
    }

    /// INT-SCRUT-008: an explicitly scoped call must never bind to a same-leaf method in a
    /// conflicting namespace, and an exact qualified match wins over suffix/leaf matches.
    #[test]
    fn test_explicit_namespace_qualifier_never_binds_conflicting_same_leaf_method() {
        assert!(!enclosing_matches_qualifier("a::Box", "b::Box"));
        assert!(enclosing_matches_qualifier("b::Box", "b::Box"));
        assert!(enclosing_matches_qualifier("ns::b::Box", "b::Box"));
        assert!(enclosing_matches_qualifier("a::Box", "Box"));
        assert!(!enclosing_matches_qualifier("a::Box", "b::Box::run"));

        let file = "test.cpp";
        let unit = sample_unit(
            file,
            FileScope::FirstParty,
            ArchLayer::Core,
            LanguageKind::Cpp,
            vec![
                cpp_method_symbol(file, "a::Box", "run", 2),
                cpp_method_symbol(file, "b::Box", "run", 6),
                sample_symbol(
                    file,
                    "caller",
                    9,
                    FileScope::FirstParty,
                    ArchLayer::Core,
                    "src",
                ),
            ],
            Vec::new(),
            vec![sample_call(file, "caller", 9, "run", Some("b::Box"), 10)],
        );

        let (_symbols, _types, _macros, calls, _xrefs, _vendor) = resolve_and_link(&[unit]);
        let edge = find_call(&calls, "run");
        assert_eq!(
            edge.callee_id, "test.cpp::b::Box::run",
            "b::Box::run() must not resolve to a::Box::run"
        );
        assert_eq!(edge.tier, ResolutionTier::SameFile);
    }
}
