use crate::model::{
    ExtractedImport, ExtractedMacro, ExtractedSymbol, ExtractedType, FileScope, MacroKind,
    ParsedFileUnit, ResolutionTier, ResolvedCallEdge, VendorSurfaceSummary, XrefEntry,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;
use std::path::Path;

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
    let mut symbols: Vec<ExtractedSymbol> = units
        .iter()
        .flat_map(|u| u.symbols.iter().cloned())
        .collect();
    symbols.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.start_line.cmp(&b.start_line))
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.symbol_id.cmp(&b.symbol_id))
    });
    symbols.dedup_by(|a, b| a.symbol_id == b.symbol_id && a.start_line == b.start_line);

    let mut types: Vec<ExtractedType> =
        units.iter().flat_map(|u| u.types.iter().cloned()).collect();
    types.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.start_line.cmp(&b.start_line))
            .then_with(|| a.end_line.cmp(&b.end_line))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.type_id.cmp(&b.type_id))
    });
    types.dedup_by(|a, b| a.type_id == b.type_id && a.start_line == b.start_line);

    let mut macros: Vec<ExtractedMacro> = units
        .iter()
        .flat_map(|u| u.macros.iter().cloned())
        .collect();
    macros.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.name.cmp(&b.name))
    });
    macros.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.name == b.name);

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

    // 3. Resolve every RawCallSite across units
    let mut calls: Vec<ResolvedCallEdge> = Vec::new();

    for unit in units {
        let unit_sec_id = infer_unit_section_id(unit);

        for raw in &unit.raw_calls {
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

            let (caller_id, caller_section_id) = match caller_idx {
                Some(idx) => (
                    symbols[idx].symbol_id.clone(),
                    symbols[idx].section_id.clone(),
                ),
                None => (
                    format!("{}::{}", raw.caller_file, raw.caller_name),
                    unit_sec_id.clone(),
                ),
            };

            let short_callee = raw
                .callee_name
                .rsplit_once("::")
                .or_else(|| raw.callee_name.rsplit_once('.'))
                .or_else(|| raw.callee_name.rsplit_once("->"))
                .map(|(_, s)| s)
                .unwrap_or(raw.callee_name.as_str());

            let candidates = by_name
                .get(raw.callee_name.as_str())
                .or_else(|| by_name.get(short_callee));

            let (callee_id, tier) = resolve_callee_candidates(
                raw.caller_file.as_str(),
                &caller_section_id,
                short_callee,
                raw.receiver_or_qualifier.as_deref(),
                &unit.imports,
                candidates.map(|v| v.as_slice()).unwrap_or(&[]),
                &symbols,
            );

            calls.push(ResolvedCallEdge {
                caller_id,
                caller_name: raw.caller_name.clone(),
                callee_name: raw.callee_name.clone(),
                callee_id,
                file: raw.caller_file.clone(),
                line: raw.call_line,
                tier,
                section_id: caller_section_id,
            });
        }
    }

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

    // 4. Build unified XrefEntry list
    let mut xrefs: Vec<XrefEntry> =
        Vec::with_capacity(calls.len() + types.len() + macros.len() + units.len() * 4);

    for edge in &calls {
        xrefs.push(XrefEntry {
            symbol: edge.callee_name.clone(),
            category: "call".to_string(),
            relation: edge.tier.as_str().to_string(),
            target: edge.caller_id.clone(),
            file: edge.file.clone(),
            line: edge.line,
            section_id: edge.section_id.clone(),
            context: format!("{} -> {}", edge.caller_name, edge.callee_id),
        });
    }

    for unit in units {
        let unit_sec_id = infer_unit_section_id(unit);
        for rx in &unit.raw_xrefs {
            let relation = match rx.category.as_str() {
                "mmio_access" => "accesses_reg",
                "import" => "imports",
                "type_ref" => "references_type",
                "macro_ref" => "expands_macro",
                other => other,
            }
            .to_string();

            xrefs.push(XrefEntry {
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
    }

    for t in &types {
        xrefs.push(XrefEntry {
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

    for m in &macros {
        let context = if m.description.is_empty() {
            m.value_or_args.clone()
        } else if m.value_or_args.is_empty() {
            m.description.clone()
        } else {
            format!("{} ({})", m.value_or_args, m.description)
        };
        xrefs.push(XrefEntry {
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

    // 5. Compute VendorSurfaceSummary
    let vendor_surface = compute_vendor_surface(units, &symbols, &types, &macros, &calls);

    (symbols, types, macros, calls, xrefs, vendor_surface)
}

fn resolve_callee_candidates(
    caller_file: &str,
    caller_section_id: &str,
    callee_name: &str,
    receiver_or_qualifier: Option<&str>,
    imports: &[ExtractedImport],
    candidate_indices: &[usize],
    symbols: &[ExtractedSymbol],
) -> (String, ResolutionTier) {
    if candidate_indices.is_empty() {
        return (
            format!("external::{callee_name}"),
            ResolutionTier::ExternalOrMacro,
        );
    }

    // Tier 1: Defined in the same file
    let same_file: Vec<usize> = candidate_indices
        .iter()
        .copied()
        .filter(|&idx| symbols[idx].file == caller_file)
        .collect();
    if !same_file.is_empty() {
        if let Some(qual) = receiver_or_qualifier {
            if let Some(&idx) = same_file.iter().find(|&&idx| {
                symbols[idx]
                    .enclosing_type
                    .as_deref()
                    .is_some_and(|et| et.eq_ignore_ascii_case(qual))
            }) {
                return (symbols[idx].symbol_id.clone(), ResolutionTier::SameFile);
            }
        }
        return (
            symbols[same_file[0]].symbol_id.clone(),
            ResolutionTier::SameFile,
        );
    }

    // Tier 2: Caller file's imports reference the defining file's stem/module or explicitly import callee_name
    let mut import_matches: Vec<(usize, usize)> = Vec::new();
    for &idx in candidate_indices {
        let def = &symbols[idx];
        if let Some(score) = match_import_for_candidate(callee_name, &def.file, imports) {
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

    // Tier 3: Exactly 1 definition across the entire repository
    if candidate_indices.len() == 1 {
        return (
            symbols[candidate_indices[0]].symbol_id.clone(),
            ResolutionTier::UniqueGlobal,
        );
    }

    // Tier 4: Multiple definitions across repository -> pick closest directory/section, then first-party over vendor, then lexicographically first symbol_id
    let mut ranked_candidates: Vec<usize> = candidate_indices.to_vec();
    ranked_candidates.sort_by(|&idx_a, &idx_b| {
        let a = &symbols[idx_a];
        let b = &symbols[idx_b];

        let qual_a = receiver_or_qualifier.is_some_and(|q| {
            a.enclosing_type
                .as_deref()
                .is_some_and(|et| et.eq_ignore_ascii_case(q))
        });
        let qual_b = receiver_or_qualifier.is_some_and(|q| {
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

fn match_import_for_candidate(
    callee_name: &str,
    def_file: &str,
    imports: &[ExtractedImport],
) -> Option<usize> {
    let def_norm = def_file.replace('\\', "/");
    let def_stem = Path::new(&def_norm)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let def_without_ext = strip_source_extension(&def_norm);

    let mut best_score: Option<usize> = None;

    for imp in imports {
        let explicit_name = imp
            .imported_names
            .iter()
            .any(|n| n == callee_name || n == "*");

        let raw_norm = imp
            .raw_path
            .trim()
            .trim_matches(|c| matches!(c, '"' | '\'' | '<' | '>'))
            .replace("::", "/")
            .replace('\\', "/");
        let imp_without_ext = strip_source_extension(&raw_norm);
        let imp_stem = Path::new(&imp_without_ext)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        let path_matches = if !imp_without_ext.is_empty() && !def_without_ext.is_empty() {
            def_without_ext.ends_with(&imp_without_ext)
                || imp_without_ext.ends_with(&def_without_ext)
                || (!imp_stem.is_empty()
                    && !def_stem.is_empty()
                    && imp_stem.eq_ignore_ascii_case(def_stem))
        } else {
            false
        };

        let score = match (explicit_name, path_matches) {
            (true, true) => Some(3),
            (false, true) => Some(2),
            (true, false) if raw_norm.is_empty() || !imp_stem.eq_ignore_ascii_case("std") => {
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
        ) {
            return prefix.to_string();
        }
    }
    trimmed.to_string()
}

fn common_dir_prefix_len(path_a: &str, path_b: &str) -> usize {
    let a_parts: Vec<&str> = path_a.split(['/', '\\']).collect();
    let b_parts: Vec<&str> = path_b.split(['/', '\\']).collect();
    let a_dir = &a_parts[..a_parts.len().saturating_sub(1)];
    let b_dir = &b_parts[..b_parts.len().saturating_sub(1)];

    a_dir
        .iter()
        .zip(b_dir.iter())
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
                    vendor_file_stems.insert(fname.to_ascii_lowercase());
                }
                if let Some(stem) = Path::new(&norm).file_stem().and_then(|s| s.to_str()) {
                    vendor_file_stems.insert(stem.to_ascii_lowercase());
                }
            }
            FileScope::FirstParty => {
                first_party_files.insert(u.scanned.rel_path.as_str());
            }
            FileScope::Test => {}
        }
    }

    let mut active_vendor_symbols: BTreeSet<String> = BTreeSet::new();
    let mut active_mmio_registers: BTreeSet<String> = BTreeSet::new();
    let mut active_vendor_headers: BTreeSet<String> = BTreeSet::new();

    // All MMIO macros defined directly in first-party files are active
    for m in macros.iter().filter(|m| m.scope == FileScope::FirstParty) {
        if matches!(
            m.kind,
            MacroKind::MmioAddress | MacroKind::RegisterAccess | MacroKind::Bitmask
        ) {
            active_mmio_registers.insert(m.name.clone());
        }
    }

    // Check resolved calls from first-party files
    for call in calls {
        if !first_party_files.contains(call.file.as_str()) {
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

    // Check raw_xrefs, imports, signatures, and type fields in first-party units
    for unit in units
        .iter()
        .filter(|u| u.scanned.scope == FileScope::FirstParty)
    {
        for rx in &unit.raw_xrefs {
            let target = rx.target_name.as_str();
            if rx.category == "mmio_access" {
                active_mmio_registers.insert(rx.target_name.clone());
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

        for imp in &unit.imports {
            for imported in &imp.imported_names {
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

            let is_vendor_header = vendor_file_paths.iter().any(|vp| vp.ends_with(&raw_clean))
                || (!fname_lower.is_empty() && vendor_file_stems.contains(&fname_lower))
                || (!stem_lower.is_empty() && vendor_file_stems.contains(&stem_lower));

            if is_vendor_header && !raw_clean.is_empty() {
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

    fn sample_scanned(rel_path: &str, scope: FileScope, layer: ArchLayer) -> ScannedFile {
        ScannedFile {
            rel_path: rel_path.to_string(),
            abs_path: PathBuf::from(rel_path),
            language: LanguageKind::C,
            scope,
            arch_layer: layer,
            size_bytes: 256,
            mtime_secs: 0,
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

        assert!(!xrefs.is_empty());
        assert_eq!(vendor.total_vendor_files, 1);
        assert_eq!(vendor.total_vendor_symbols, 2);
        assert!(vendor
            .active_vendor_symbols
            .contains(&"HAL_GPIO_Init".to_string()));
        assert!(vendor
            .active_mmio_registers
            .contains(&"GPIOA->MODER".to_string()));
    }
}
