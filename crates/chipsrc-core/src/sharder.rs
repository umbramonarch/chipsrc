use crate::model::{
    ArchLayer, ExtractedMacro, ExtractedType, FileScope, MacroKind, ParsedFileUnit, RankedSymbol,
    ResolvedCallEdge, SectionShard, SectionSummary, SymbolKind, VendorMode, VendorSurfaceSummary,
    XrefEntry,
};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};

const GENERIC_FILE_STEMS: &[&str] = &[
    "main", "mod", "index", "lib", "init", "test", "tests", "config", "utils",
];

/// Single-file line threshold at which the sharder splits a large file into its own sub-shard.
pub const LARGE_SINGLE_FILE_LINES: usize = 1400;

/// Module-group line threshold above which the sharder splits a group into sub-shards.
pub const MAX_GROUP_LINES: usize = 3000;

/// Module-group file-count threshold above which the sharder splits a group into sub-shards.
pub const MAX_GROUP_FILES: usize = 8;

/// Returns the `(scope_sort_order, raw_slug)` grouping key that [`build_section_shards`] assigns
/// to a parsed file. Shared with the incremental coordinate-shift tier so shard-threshold
/// crossings can be detected without duplicating the module-derivation rules.
pub fn shard_group_key(unit: &ParsedFileUnit) -> (u8, String) {
    let (slug, _title, module_path) = derive_unit_shard_meta(unit);
    let effective_scope = if unit.scanned.scope == FileScope::FirstParty
        && crate::scanner::path_is_vendor_owned(&module_path)
    {
        FileScope::VendorSdk
    } else {
        unit.scanned.scope
    };
    (scope_sort_order(effective_scope), slug)
}

/// Returns `true` when a coordinate-only edit cannot change shard grouping.
///
/// Requirements: every dirty file stays strictly below [`LARGE_SINGLE_FILE_LINES`] in both its
/// old and new state, and every module group containing a dirty file stays within
/// [`MAX_GROUP_FILES`] / [`MAX_GROUP_LINES`] in both states. `dirty_old_line_counts` maps the
/// relative path of each dirty file to its pre-edit line count; all other files are unchanged.
pub fn coordinate_shift_grouping_stable(
    units: &[ParsedFileUnit],
    dirty_old_line_counts: &FxHashMap<&str, usize>,
) -> bool {
    struct GroupAggregate {
        old_lines: usize,
        new_lines: usize,
        files: usize,
        dirty: Vec<(usize, usize)>,
    }

    let mut groups: FxHashMap<(u8, String), GroupAggregate> = FxHashMap::default();
    for unit in units {
        let key = shard_group_key(unit);
        let new_lines = unit.scanned.line_count;
        let rel_path = unit.scanned.rel_path.as_str();
        let old_lines = dirty_old_line_counts
            .get(rel_path)
            .copied()
            .unwrap_or(new_lines);
        let entry = groups.entry(key).or_insert_with(|| GroupAggregate {
            old_lines: 0,
            new_lines: 0,
            files: 0,
            dirty: Vec::new(),
        });
        entry.old_lines += old_lines;
        entry.new_lines += new_lines;
        entry.files += 1;
        if dirty_old_line_counts.contains_key(rel_path) {
            entry.dirty.push((old_lines, new_lines));
        }
    }

    for aggregate in groups.values() {
        if aggregate.dirty.is_empty() {
            continue;
        }
        if aggregate.files > MAX_GROUP_FILES
            || aggregate.old_lines > MAX_GROUP_LINES
            || aggregate.new_lines > MAX_GROUP_LINES
        {
            return false;
        }
        for &(old_lines, new_lines) in &aggregate.dirty {
            if old_lines >= LARGE_SINGLE_FILE_LINES || new_lines >= LARGE_SINGLE_FILE_LINES {
                return false;
            }
        }
    }
    true
}

const GENERIC_HEADER_STEMS: &[&str] = &[
    "main", "config", "types", "common", "board", "system", "version", "def", "defs", "utils",
    "hal", "bsp",
];

struct RawShardGroup<'a> {
    raw_slug: String,
    title: String,
    module_path: String,
    arch_layer: ArchLayer,
    scope: FileScope,
    units: Vec<&'a ParsedFileUnit>,
}

/// Groups parsed files into architectural module shards, numbers them deterministically
/// (`01-<slug>`, `02-<slug>`, ...), updates `section_id` across all index records, prunes
/// inactive vendor index entries under `VendorMode::Active` / `VendorMode::None`, computes
/// cross-shard call dependencies, and renders each shard's Markdown signature skeleton.
#[allow(clippy::too_many_arguments)]
pub fn build_section_shards(
    repo_name_hint: &str,
    units: &[ParsedFileUnit],
    ranked_symbols: &mut Vec<RankedSymbol>,
    types: &mut Vec<ExtractedType>,
    macros: &mut Vec<ExtractedMacro>,
    calls: &mut Vec<ResolvedCallEdge>,
    xrefs: &mut Vec<XrefEntry>,
    vendor_surface: &VendorSurfaceSummary,
    vendor_mode: VendorMode,
) -> (Vec<SectionSummary>, Vec<SectionShard>) {
    if units.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let repo_name = if !repo_name_hint.trim().is_empty() {
        repo_name_hint.trim().to_string()
    } else {
        infer_repo_name(units)
    };

    // 1. Group files by (FileScope, initial section_id slug) so Test, VendorSdk, and FirstParty
    // files never share a RawShardGroup.
    let mut group_map: BTreeMap<(u8, String), RawShardGroup<'_>> = BTreeMap::new();
    let mut file_to_raw_slug: FxHashMap<String, String> = FxHashMap::default();

    for unit in units {
        if vendor_mode == VendorMode::None && unit.scanned.scope == FileScope::VendorSdk {
            continue;
        }
        let (slug, title, module_path) = derive_unit_shard_meta(unit);
        let effective_scope = if unit.scanned.scope == FileScope::FirstParty
            && crate::scanner::path_is_vendor_owned(&module_path)
        {
            FileScope::VendorSdk
        } else {
            unit.scanned.scope
        };
        file_to_raw_slug.insert(unit.scanned.rel_path.clone(), slug.clone());

        let key = (scope_sort_order(effective_scope), slug.clone());
        let entry = group_map.entry(key).or_insert_with(|| RawShardGroup {
            raw_slug: slug,
            title,
            module_path,
            arch_layer: unit.scanned.arch_layer,
            scope: effective_scope,
            units: Vec::new(),
        });

        entry.units.push(unit);
    }

    // Resolve each shard group's dominant ownership scope and architectural layer from its files.
    for group in group_map.values_mut() {
        let scope = dominant_group_scope(&group.units, &group.module_path);
        group.scope = scope;
        group.arch_layer = match scope {
            FileScope::VendorSdk => ArchLayer::VendorHal,
            FileScope::Test => ArchLayer::Tests,
            FileScope::FirstParty => group
                .units
                .iter()
                .filter(|u| u.scanned.scope == scope)
                .map(|u| u.scanned.arch_layer)
                .min_by_key(|layer| layer_sort_order(*layer))
                .unwrap_or(ArchLayer::Other),
        };
        let layer_str = group.arch_layer.as_str();
        group.title = if group.module_path == "root" {
            format!("Root Module ({layer_str})")
        } else {
            format!("{} ({layer_str})", group.module_path)
        };
    }

    let active_vendor_set: FxHashSet<&str> = vendor_surface
        .active_vendor_symbols
        .iter()
        .map(|s| s.as_str())
        .chain(
            vendor_surface
                .active_mmio_registers
                .iter()
                .map(|s| s.as_str()),
        )
        .collect();

    let active_header_set: FxHashSet<&str> = vendor_surface
        .active_vendor_headers
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Filter or keep vendor groups according to the requested vendor mode. In
    // `VendorMode::Active` a vendor shard survives ONLY when first-party code actually
    // references one of its headers, symbols, types, or macros.
    let has_non_vendor = group_map.values().any(|g| g.scope != FileScope::VendorSdk);

    let mut groups: Vec<RawShardGroup<'_>> = group_map
        .into_values()
        .filter(|g| {
            if g.scope != FileScope::VendorSdk || !has_non_vendor {
                return true;
            }
            match vendor_mode {
                VendorMode::All => true,
                VendorMode::None => false,
                VendorMode::Active => {
                    group_has_active_vendor_refs(g, &active_vendor_set, &active_header_set)
                }
            }
        })
        .flat_map(|g| split_oversized_shard_group(g, &mut file_to_raw_slug))
        .collect();

    // Compact vendor groups' file lists up front under VendorMode::Active so `file_to_numbered`
    // and `ranked_symbols`/`types`/`macros` agree on the exact retained files.
    for group in &mut groups {
        if vendor_mode == VendorMode::Active
            && has_non_vendor
            && group.scope == FileScope::VendorSdk
        {
            group.units.retain(|u| {
                unit_is_active_vendor_surface(u, &active_vendor_set, &active_header_set)
            });
        }
    }
    groups.retain(|g| !g.units.is_empty());

    // 2. Order shards deterministically:
    // FirstParty shards first (ordered by ArchLayer rank descending: app/cli/api -> core/services -> bsp -> drvs/domain -> config/libs -> other),
    // then Test shards, then VendorSdk shards.
    groups.sort_by(|a, b| {
        scope_sort_order(a.scope)
            .cmp(&scope_sort_order(b.scope))
            .then_with(|| layer_sort_order(a.arch_layer).cmp(&layer_sort_order(b.arch_layer)))
            .then_with(|| a.module_path.cmp(&b.module_path))
            .then_with(|| a.raw_slug.cmp(&b.raw_slug))
    });

    // Guarantee global clean_slug uniqueness across all groups (appending `-test` / `-vendor`
    // when a non-first-party group collides with an earlier slug, and a numeric suffix as last resort).
    {
        let mut used_slugs: BTreeSet<String> = BTreeSet::new();
        for group in &mut groups {
            let base = strip_numeric_prefix(&group.raw_slug).to_string();
            let mut candidate = base.clone();
            if used_slugs.contains(&candidate) {
                match group.scope {
                    FileScope::Test
                        if !candidate.ends_with("-test") && !candidate.ends_with("-tests") =>
                    {
                        candidate = format!("{base}-test");
                    }
                    FileScope::VendorSdk if !candidate.ends_with("-vendor") => {
                        candidate = format!("{base}-vendor");
                    }
                    _ => {}
                }
            }
            let stem_for_num = candidate.clone();
            let mut suffix_num = 2usize;
            while used_slugs.contains(&candidate) {
                candidate = format!("{stem_for_num}-{suffix_num}");
                suffix_num += 1;
            }
            used_slugs.insert(candidate.clone());
            group.raw_slug = candidate.clone();
            for u in &group.units {
                file_to_raw_slug.insert(u.scanned.rel_path.clone(), candidate.clone());
            }
        }
    }

    // Collect surviving files across all groups and prune items belonging to dropped files.
    let surviving_files: FxHashSet<&str> = groups
        .iter()
        .flat_map(|g| g.units.iter().map(|u| u.scanned.rel_path.as_str()))
        .collect();

    if surviving_files.len() < units.len() {
        ranked_symbols.retain(|rs| surviving_files.contains(rs.symbol.file.as_str()));
        types.retain(|t| surviving_files.contains(t.file.as_str()));
        macros.retain(|m| surviving_files.contains(m.file.as_str()));
        calls.retain(|c| surviving_files.contains(c.file.as_str()));
        xrefs.retain(|x| surviving_files.contains(x.file.as_str()));
    }

    // 3. Assign numbered section IDs (01-<slug>, 02-<slug>, ...) and build file/slug -> numbered maps
    let mut slug_to_numbered: FxHashMap<String, String> = FxHashMap::default();
    let mut file_to_numbered: FxHashMap<String, String> = FxHashMap::default();
    let mut section_to_layer: FxHashMap<String, ArchLayer> = FxHashMap::default();

    for (idx, group) in groups.iter().enumerate() {
        let clean_slug = strip_numeric_prefix(&group.raw_slug);
        let numbered_id = format!("{:02}-{clean_slug}", idx + 1);
        slug_to_numbered
            .entry(group.raw_slug.clone())
            .or_insert_with(|| numbered_id.clone());
        slug_to_numbered
            .entry(clean_slug.to_string())
            .or_insert_with(|| numbered_id.clone());
        section_to_layer.insert(numbered_id.clone(), group.arch_layer);
        for u in &group.units {
            file_to_numbered.insert(u.scanned.rel_path.clone(), numbered_id.clone());
        }
    }

    let fallback_sec_id = groups
        .first()
        .map(|g| {
            let clean = strip_numeric_prefix(&g.raw_slug);
            format!("01-{clean}")
        })
        .unwrap_or_else(|| "01-root".to_string());

    // File-first resolution so split sub-shards always own their files' symbols/types/macros.
    let resolve_numbered = |raw_sec: &str, file: &str| -> String {
        if let Some(mapped) = file_to_numbered.get(file) {
            return mapped.clone();
        }
        if let Some(raw_slug) = file_to_raw_slug.get(file) {
            if let Some(mapped) = slug_to_numbered.get(raw_slug) {
                return mapped.clone();
            }
        }
        if let Some(mapped) = slug_to_numbered.get(raw_sec) {
            return mapped.clone();
        }
        let clean_raw = strip_numeric_prefix(raw_sec);
        if let Some(mapped) = slug_to_numbered.get(clean_raw) {
            return mapped.clone();
        }
        fallback_sec_id.clone()
    };

    // Update section_id (and synchronize fallback ArchLayer::Other with the shard's dominant layer)
    // on all ranked_symbols, types, macros, calls, and xrefs.
    for rs in ranked_symbols.iter_mut() {
        rs.symbol.section_id = resolve_numbered(&rs.symbol.section_id, &rs.symbol.file);
        if rs.symbol.arch_layer == ArchLayer::Other {
            if let Some(&layer) = section_to_layer.get(&rs.symbol.section_id) {
                rs.symbol.arch_layer = layer;
            }
        }
    }
    for t in types.iter_mut() {
        t.section_id = resolve_numbered(&t.section_id, &t.file);
        if t.arch_layer == ArchLayer::Other {
            if let Some(&layer) = section_to_layer.get(&t.section_id) {
                t.arch_layer = layer;
            }
        }
    }
    for m in macros.iter_mut() {
        m.section_id = resolve_numbered(&m.section_id, &m.file);
        if m.arch_layer == ArchLayer::Other {
            if let Some(&layer) = section_to_layer.get(&m.section_id) {
                m.arch_layer = layer;
            }
        }
    }
    {
        let mut last_file = "";
        let mut last_sec = String::new();
        for c in calls.iter_mut() {
            if !last_file.is_empty() && c.file == last_file {
                c.section_id = last_sec.clone();
            } else {
                let sec = resolve_numbered(&c.section_id, &c.file);
                last_file = c.file.as_str();
                last_sec.clone_from(&sec);
                c.section_id = sec;
            }
        }
    }
    {
        let mut last_file = "";
        let mut last_sec = String::new();
        for x in xrefs.iter_mut() {
            if !last_file.is_empty() && x.file == last_file {
                x.section_id = last_sec.clone();
            } else {
                let sec = resolve_numbered(&x.section_id, &x.file);
                last_file = x.file.as_str();
                last_sec.clone_from(&sec);
                x.section_id = sec;
            }
        }
    }

    // 4. Compute inter-section dependencies from resolved cross-section calls
    let mut sym_id_to_section: FxHashMap<&str, &str> = FxHashMap::default();
    for rs in ranked_symbols.iter() {
        sym_id_to_section.insert(rs.symbol.symbol_id.as_str(), rs.symbol.section_id.as_str());
    }

    let mut depends_on_map: FxHashMap<String, BTreeSet<String>> = FxHashMap::default();
    let mut depended_by_map: FxHashMap<String, BTreeSet<String>> = FxHashMap::default();
    let mut callees_by_caller: FxHashMap<&str, Vec<&str>> = FxHashMap::default();

    for call in calls.iter() {
        if !call.tier.is_resolved() {
            continue;
        }
        callees_by_caller
            .entry(call.caller_id.as_str())
            .or_default()
            .push(call.callee_name.as_str());

        if let Some(&target_sec) = sym_id_to_section.get(call.callee_id.as_str()) {
            if target_sec != call.section_id {
                depends_on_map
                    .entry(call.section_id.clone())
                    .or_default()
                    .insert(target_sec.to_string());
                depended_by_map
                    .entry(target_sec.to_string())
                    .or_default()
                    .insert(call.section_id.clone());
            }
        }
    }

    for list in callees_by_caller.values_mut() {
        let mut seen = FxHashSet::default();
        list.retain(|item| seen.insert(*item));
    }

    // Pre-partition symbols, types, and macros by section_id in O(N + T + M)
    let mut symbols_by_section: FxHashMap<&str, Vec<&RankedSymbol>> = FxHashMap::default();
    for rs in ranked_symbols.iter() {
        symbols_by_section
            .entry(rs.symbol.section_id.as_str())
            .or_default()
            .push(rs);
    }
    let mut types_by_section: FxHashMap<&str, Vec<&ExtractedType>> = FxHashMap::default();
    for t in types.iter() {
        types_by_section
            .entry(t.section_id.as_str())
            .or_default()
            .push(t);
    }
    let mut macros_by_section: FxHashMap<&str, Vec<&ExtractedMacro>> = FxHashMap::default();
    for m in macros.iter() {
        macros_by_section
            .entry(m.section_id.as_str())
            .or_default()
            .push(m);
    }

    // 5. Prepare each shard's sorted symbols/types/macros, then render markdown_body in parallel
    let mut any_vendor_compacted = false;
    let mut kept_symbol_keys: FxHashSet<(String, usize, String)> = FxHashSet::default();
    let mut kept_type_keys: FxHashSet<(String, usize, String)> = FxHashSet::default();
    let mut kept_macro_keys: FxHashSet<(String, usize, String)> = FxHashSet::default();

    struct PreparedShard<'a> {
        section_id: String,
        md_file: String,
        group: RawShardGroup<'a>,
        files: Vec<String>,
        shard_symbols: Vec<&'a RankedSymbol>,
        shard_types: Vec<&'a ExtractedType>,
        shard_macros: Vec<&'a ExtractedMacro>,
        depends_on_sections: Vec<String>,
        depended_by_sections: Vec<String>,
        compact_vendor: bool,
    }

    let mut prepared_shards: Vec<PreparedShard<'_>> = Vec::with_capacity(groups.len());

    for (idx, mut group) in groups.into_iter().enumerate() {
        let clean_slug = strip_numeric_prefix(&group.raw_slug);
        let section_id = format!("{:02}-{clean_slug}", idx + 1);
        let md_file = format!("{section_id}.md");

        let compact_vendor = vendor_mode == VendorMode::Active
            && has_non_vendor
            && group.scope == FileScope::VendorSdk;

        group
            .units
            .sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));

        let files: Vec<String> = group
            .units
            .iter()
            .map(|u| u.scanned.rel_path.clone())
            .collect();

        let mut shard_symbols: Vec<&RankedSymbol> = symbols_by_section
            .remove(section_id.as_str())
            .unwrap_or_default();
        shard_symbols.sort_by(|a, b| {
            b.pagerank
                .total_cmp(&a.pagerank)
                .then_with(|| a.symbol.file.cmp(&b.symbol.file))
                .then_with(|| a.symbol.start_line.cmp(&b.symbol.start_line))
                .then_with(|| a.symbol.name.cmp(&b.symbol.name))
        });

        let mut shard_types: Vec<&ExtractedType> = types_by_section
            .remove(section_id.as_str())
            .unwrap_or_default();
        shard_types.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.start_line.cmp(&b.start_line))
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut shard_macros: Vec<&ExtractedMacro> = macros_by_section
            .remove(section_id.as_str())
            .unwrap_or_default();
        shard_macros.sort_by(|a, b| {
            let active_a = active_vendor_set.contains(a.name.as_str());
            let active_b = active_vendor_set.contains(b.name.as_str());
            let mmio_a = matches!(
                a.kind,
                MacroKind::MmioAddress | MacroKind::RegisterAccess | MacroKind::Bitmask
            );
            let mmio_b = matches!(
                b.kind,
                MacroKind::MmioAddress | MacroKind::RegisterAccess | MacroKind::Bitmask
            );
            active_b
                .cmp(&active_a)
                .then_with(|| mmio_b.cmp(&mmio_a))
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.name.cmp(&b.name))
        });

        // In `VendorMode::Active`, keep only vendor definitions from retained files that
        // first-party code actually references; when nothing in a category is active, the
        // retained-files list is kept and the renderer caps it instead.
        if compact_vendor {
            any_vendor_compacted = true;
            let retained_files: FxHashSet<&str> = files.iter().map(|s| s.as_str()).collect();
            shard_symbols.retain(|rs| retained_files.contains(rs.symbol.file.as_str()));
            shard_types.retain(|t| retained_files.contains(t.file.as_str()));
            shard_macros.retain(|m| retained_files.contains(m.file.as_str()));

            shard_symbols = filter_active_vendor_items(shard_symbols, |rs: &RankedSymbol| {
                active_vendor_set.contains(rs.symbol.name.as_str()) || rs.in_degree > 0
            });
            shard_types = filter_active_vendor_items(shard_types, |t: &ExtractedType| {
                active_vendor_set.contains(t.name.as_str())
            });
            shard_macros = filter_active_vendor_items(shard_macros, |m: &ExtractedMacro| {
                active_vendor_set.contains(m.name.as_str())
            });

            for rs in &shard_symbols {
                kept_symbol_keys.insert((
                    rs.symbol.file.clone(),
                    rs.symbol.start_line,
                    rs.symbol.symbol_id.clone(),
                ));
            }
            for t in &shard_types {
                kept_type_keys.insert((t.file.clone(), t.start_line, t.type_id.clone()));
            }
            for m in &shard_macros {
                kept_macro_keys.insert((m.file.clone(), m.line, m.name.clone()));
            }
        }

        let depends_on_sections: Vec<String> = depends_on_map
            .remove(&section_id)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default();
        let depended_by_sections: Vec<String> = depended_by_map
            .remove(&section_id)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default();

        prepared_shards.push(PreparedShard {
            section_id,
            md_file,
            group,
            files,
            shard_symbols,
            shard_types,
            shard_macros,
            depends_on_sections,
            depended_by_sections,
            compact_vendor,
        });
    }

    let rendered: Vec<(SectionSummary, SectionShard)> = prepared_shards
        .into_par_iter()
        .map(|ps| {
            let markdown_body = render_shard_markdown(
                &repo_name,
                &ps.section_id,
                &ps.group,
                &ps.shard_symbols,
                &ps.shard_types,
                &ps.shard_macros,
                &ps.depends_on_sections,
                &ps.depended_by_sections,
                &callees_by_caller,
                &active_vendor_set,
                ps.compact_vendor,
            );

            let token_estimate = markdown_body.len().div_ceil(4);

            let summary = SectionSummary {
                section_id: ps.section_id,
                title: ps.group.title,
                module_path: ps.group.module_path,
                arch_layer: ps.group.arch_layer.as_str().to_string(),
                scope: ps.group.scope.as_str().to_string(),
                file_count: ps.files.len(),
                symbol_count: ps.shard_symbols.len(),
                type_count: ps.shard_types.len(),
                macro_count: ps.shard_macros.len(),
                token_estimate,
                md_file: ps.md_file,
            };

            let shard = SectionShard {
                summary: summary.clone(),
                files: ps.files,
                depends_on_sections: ps.depends_on_sections,
                depended_by_sections: ps.depended_by_sections,
                markdown_body,
            };
            (summary, shard)
        })
        .collect();

    let mut summaries = Vec::with_capacity(rendered.len());
    let mut shards = Vec::with_capacity(rendered.len());
    for (summary, shard) in rendered {
        summaries.push(summary);
        shards.push(shard);
    }

    // Synchronize index tables with the exact per-shard retained sets so
    // `Σ section_summaries.{symbol,type,macro}_count == index/*.tsv` always holds.
    if any_vendor_compacted {
        ranked_symbols.retain(|rs| {
            rs.symbol.scope != FileScope::VendorSdk
                || kept_symbol_keys.contains(&(
                    rs.symbol.file.clone(),
                    rs.symbol.start_line,
                    rs.symbol.symbol_id.clone(),
                ))
        });
        types.retain(|t| {
            t.scope != FileScope::VendorSdk
                || kept_type_keys.contains(&(t.file.clone(), t.start_line, t.type_id.clone()))
        });
        macros.retain(|m| {
            m.scope != FileScope::VendorSdk
                || kept_macro_keys.contains(&(m.file.clone(), m.line, m.name.clone()))
        });
    }

    (summaries, shards)
}

#[allow(clippy::too_many_arguments)]
fn render_shard_markdown(
    repo_name: &str,
    section_id: &str,
    group: &RawShardGroup<'_>,
    shard_symbols: &[&RankedSymbol],
    shard_types: &[&ExtractedType],
    shard_macros: &[&ExtractedMacro],
    depends_on_sections: &[String],
    depended_by_sections: &[String],
    callees_by_caller: &FxHashMap<&str, Vec<&str>>,
    active_vendor_set: &FxHashSet<&str>,
    compact_vendor: bool,
) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(128);
    let arch_layer_str = group.arch_layer.as_str();
    let scope_str = group.scope.as_str();

    // YAML frontmatter
    lines.push("---".to_string());
    lines.push(format!("repo: \"{}\"", escape_yaml(repo_name)));
    lines.push(format!("section_id: \"{}\"", escape_yaml(section_id)));
    lines.push(format!("title: \"{}\"", escape_yaml(&group.title)));
    lines.push(format!(
        "module_path: \"{}\"",
        escape_yaml(&group.module_path)
    ));
    lines.push(format!("arch_layer: \"{arch_layer_str}\""));
    lines.push(format!("scope: \"{scope_str}\""));
    lines.push(format!("file_count: {}", group.units.len()));
    lines.push(format!("symbol_count: {}", shard_symbols.len()));
    lines.push("---".to_string());
    lines.push(String::new());

    // Header & module summary
    lines.push(format!("# {section_id}: {}", group.title));
    lines.push(String::new());

    let total_lines: usize = group.units.iter().map(|u| u.scanned.line_count).sum();
    lines.push(format!(
        "- **Module Path**: `{}` | **Layer**: `{arch_layer_str}` | **Scope**: `{scope_str}`",
        group.module_path
    ));
    lines.push(format!(
        "- **Files**: {} ({total_lines} lines) | **Symbols**: {} | **Types**: {} | **Macros/MMIO**: {}",
        group.units.len(),
        shard_symbols.len(),
        shard_types.len(),
        shard_macros.len()
    ));

    let deps_on_str = if depends_on_sections.is_empty() {
        "none".to_string()
    } else {
        depends_on_sections
            .iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let deps_by_str = if depended_by_sections.is_empty() {
        "none".to_string()
    } else {
        depended_by_sections
            .iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    lines.push(format!("- **Depends On Shards**: {deps_on_str}"));
    lines.push(format!("- **Depended By Shards**: {deps_by_str}"));
    lines.push(String::new());

    // 1. Files in Module
    lines.push("## Files in Module".to_string());
    lines.push(String::new());
    for u in &group.units {
        lines.push(format!(
            "- `{}` ({} lines, `{}`)",
            u.scanned.rel_path,
            u.scanned.line_count,
            u.scanned.language.as_str()
        ));
    }
    lines.push(String::new());

    // 2. Types & Data Structures
    lines.push("## Types & Data Structures".to_string());
    lines.push(String::new());
    if shard_types.is_empty() {
        lines.push("_No types defined in this module._".to_string());
    } else {
        let max_types = if compact_vendor { 40 } else { usize::MAX };
        for t in shard_types.iter().take(max_types) {
            let fields = if t.fields_summary.is_empty() {
                "-".to_string()
            } else {
                t.fields_summary.clone()
            };
            let doc_suffix = if t.doc_summary.is_empty() {
                String::new()
            } else {
                format!(" — _{}_", t.doc_summary)
            };
            lines.push(format!(
                "- `{}` `{}` **{}** (`{}:{}-{}`) — `{}`{doc_suffix}",
                t.visibility.as_str(),
                t.kind.as_str(),
                t.name,
                t.file,
                t.start_line,
                t.end_line,
                fields
            ));
        }
        if shard_types.len() > max_types {
            lines.push(format!(
                "- _... +{} more vendor types indexed in `index/types.tsv`_",
                shard_types.len() - max_types
            ));
        }
    }
    lines.push(String::new());

    // 3. Hardware / MMIO & Macros (capped at 100 entries per shard)
    const MAX_SHARD_MACROS: usize = 100;
    lines.push("## Hardware / MMIO & Macros".to_string());
    lines.push(String::new());
    if shard_macros.is_empty() {
        lines.push("_No macros or MMIO register definitions in this module._".to_string());
    } else {
        for m in shard_macros.iter().take(MAX_SHARD_MACROS) {
            let hex_part = m
                .hex_addr
                .as_deref()
                .map(|h| format!(" [hex: `{h}`]"))
                .unwrap_or_default();
            let val_part = if m.value_or_args.is_empty() {
                String::new()
            } else {
                format!(" = `{}`", m.value_or_args)
            };
            lines.push(format!(
                "- `{}` (`{}`){hex_part}{val_part} (`{}:{}`)",
                m.name,
                m.kind.as_str(),
                m.file,
                m.line
            ));
        }
        if shard_macros.len() > MAX_SHARD_MACROS {
            lines.push(format!(
                "- _... +{} more macros indexed in `index/macros.tsv`_",
                shard_macros.len() - MAX_SHARD_MACROS
            ));
        }
    }
    lines.push(String::new());

    // 4. Functions, Methods & ISRs
    lines.push("## Functions, Methods & ISRs".to_string());
    lines.push(String::new());
    if shard_symbols.is_empty() {
        lines.push("_No functions or methods defined in this module._".to_string());
    } else {
        let display_symbols: Vec<&RankedSymbol> = if compact_vendor {
            let active_only: Vec<&RankedSymbol> = shard_symbols
                .iter()
                .copied()
                .filter(|rs| {
                    active_vendor_set.contains(rs.symbol.name.as_str()) || rs.in_degree > 0
                })
                .collect();
            if active_only.is_empty() {
                shard_symbols.iter().copied().take(30).collect()
            } else {
                active_only
            }
        } else {
            shard_symbols.to_vec()
        };

        for rs in &display_symbols {
            let s = &rs.symbol;
            let mut tags = Vec::new();
            if rs.is_entrypoint {
                tags.push("ENTRYPOINT");
            }
            if rs.is_god_node {
                tags.push("HUB");
            }
            let tag_str = if tags.is_empty() {
                String::new()
            } else {
                format!(" **[{}]**", tags.join(", "))
            };

            let callees = callees_by_caller
                .get(s.symbol_id.as_str())
                .map(|v| {
                    v.iter()
                        .take(6)
                        .map(|c| format!("`{c}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let callees_part = if callees.is_empty() {
                String::new()
            } else {
                format!(" | calls: {callees}")
            };

            let sig_trimmed = s.signature.trim_start();
            let sig_after_vis = sig_trimmed
                .strip_prefix("pub(crate) ")
                .or_else(|| sig_trimmed.strip_prefix("pub(super) "))
                .or_else(|| sig_trimmed.strip_prefix("pub "))
                .or_else(|| sig_trimmed.strip_prefix("export default "))
                .or_else(|| sig_trimmed.strip_prefix("export "))
                .unwrap_or(sig_trimmed);
            let omit_kind_badge = s.kind == SymbolKind::Function
                && (sig_trimmed.starts_with("fn ")
                    || sig_trimmed.starts_with("def ")
                    || sig_trimmed.starts_with("function ")
                    || sig_trimmed.starts_with("async ")
                    || sig_after_vis.starts_with("fn ")
                    || sig_after_vis.starts_with("def ")
                    || sig_after_vis.starts_with("function ")
                    || sig_after_vis.starts_with("async "));

            if omit_kind_badge {
                lines.push(format!(
                    "- `{}` `{}` (`{}:{}-{}`){tag_str} — PR: `{:.4}`, in: `{}`, out: `{}`{callees_part}",
                    s.visibility.as_str(),
                    s.signature,
                    s.file,
                    s.start_line,
                    s.end_line,
                    rs.pagerank,
                    rs.in_degree,
                    rs.out_degree
                ));
            } else {
                lines.push(format!(
                    "- `{}` `{}` `{}` (`{}:{}-{}`){tag_str} — PR: `{:.4}`, in: `{}`, out: `{}`{callees_part}",
                    s.visibility.as_str(),
                    s.kind.as_str(),
                    s.signature,
                    s.file,
                    s.start_line,
                    s.end_line,
                    rs.pagerank,
                    rs.in_degree,
                    rs.out_degree
                ));
            }
            if !s.doc_summary.is_empty() {
                lines.push(format!("  - _{}_", s.doc_summary));
            }
        }

        if shard_symbols.len() > display_symbols.len() {
            lines.push(format!(
                "- _... +{} additional vendor SDK symbols indexed in `index/symbols.tsv`_",
                shard_symbols.len() - display_symbols.len()
            ));
        }
    }
    lines.push(String::new());

    lines.join("\n")
}

/// Resolves a shard group's dominant ownership scope from all of its files and its module path.
///
/// A group is `VendorSdk` when more than half of its files are vendor-owned OR when its module
/// path itself resolves to a vendor SDK component. Otherwise the majority scope wins, with
/// first-party ownership preferred on ties so test-only shards stay separated.
fn dominant_group_scope(units: &[&ParsedFileUnit], module_path: &str) -> FileScope {
    let total = units.len();
    if total == 0 {
        return FileScope::FirstParty;
    }

    let vendor_count = units
        .iter()
        .filter(|u| u.scanned.scope == FileScope::VendorSdk)
        .count();
    if vendor_count * 2 > total || crate::scanner::path_is_vendor_owned(module_path) {
        return FileScope::VendorSdk;
    }

    let first_party_count = units
        .iter()
        .filter(|u| u.scanned.scope == FileScope::FirstParty)
        .count();
    let test_count = units
        .iter()
        .filter(|u| u.scanned.scope == FileScope::Test)
        .count();
    if first_party_count == 0 && test_count > 0 {
        FileScope::Test
    } else {
        FileScope::FirstParty
    }
}

/// Returns `true` when `raw_header` matches `vendor_rel_path` at a path boundary, rejecting
/// bare generic header basenames (`main.h`, `config.h`, `types.h`, etc.).
pub(crate) fn vendor_path_matches_header(vendor_rel_path: &str, raw_header: &str) -> bool {
    let vp = vendor_rel_path.replace('\\', "/");
    let hc = raw_header.replace('\\', "/");
    let hc = hc.trim_start_matches("./").trim_matches('/');
    if hc.is_empty() {
        return false;
    }
    if vp == hc {
        return true;
    }
    if !hc.contains('/') {
        let stem = hc
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(hc)
            .to_ascii_lowercase();
        if GENERIC_HEADER_STEMS.contains(&stem.as_str()) {
            return false;
        }
    }
    vp.ends_with(&format!("/{hc}"))
}

/// Returns `true` when a vendor file participates in the active hardware/SDK surface referenced
/// by first-party code (via an active header, symbol, type, or macro).
fn unit_is_active_vendor_surface(
    unit: &ParsedFileUnit,
    active_vendor_set: &FxHashSet<&str>,
    active_header_set: &FxHashSet<&str>,
) -> bool {
    if active_header_set
        .iter()
        .any(|h| vendor_path_matches_header(&unit.scanned.rel_path, h))
    {
        return true;
    }
    unit.symbols
        .iter()
        .any(|s| active_vendor_set.contains(s.name.as_str()))
        || unit
            .types
            .iter()
            .any(|t| active_vendor_set.contains(t.name.as_str()))
        || unit
            .macros
            .iter()
            .any(|m| active_vendor_set.contains(m.name.as_str()))
}

/// Keeps only the items referenced by first-party code. When nothing in the list is active the
/// original (deterministically sorted) list is returned so the renderer can cap it instead of
/// emitting an empty category.
fn filter_active_vendor_items<T, F>(items: Vec<&T>, is_active: F) -> Vec<&T>
where
    F: Fn(&T) -> bool,
{
    let active: Vec<&T> = items
        .iter()
        .copied()
        .filter(|item| is_active(item))
        .collect();
    if active.is_empty() {
        items
    } else {
        active
    }
}

fn group_has_active_vendor_refs(
    group: &RawShardGroup<'_>,
    active_vendor_set: &FxHashSet<&str>,
    active_header_set: &FxHashSet<&str>,
) -> bool {
    group
        .units
        .iter()
        .any(|u| unit_is_active_vendor_surface(u, active_vendor_set, active_header_set))
}

/// Sub-shards an oversized non-vendor shard group (`> 8` files or `> 3,000` total source lines)
/// into cohesive sub-modules so no single `sections/*.md` file balloons into a 20k+ token monolith.
fn split_oversized_shard_group<'a>(
    group: RawShardGroup<'a>,
    file_to_raw_slug: &mut FxHashMap<String, String>,
) -> Vec<RawShardGroup<'a>> {
    let total_lines: usize = group.units.iter().map(|u| u.scanned.line_count).sum();
    if group.scope == FileScope::VendorSdk
        || group.units.len() <= 1
        || (group.units.len() <= MAX_GROUP_FILES && total_lines <= MAX_GROUP_LINES)
    {
        return vec![group];
    }

    let mut stem_counts: FxHashMap<String, usize> = FxHashMap::default();
    for u in &group.units {
        *stem_counts.entry(unit_file_stem(u)).or_insert(0) += 1;
    }

    // Step 1: Partition by each unit's individual `ArchLayer` if multiple layers exist in this group
    // (for example `ArchLayer::Domain` for `model.rs`/`error.rs` vs `ArchLayer::Core`).
    let mut by_layer: BTreeMap<u8, (ArchLayer, Vec<&'a ParsedFileUnit>)> = BTreeMap::new();
    for u in &group.units {
        by_layer
            .entry(layer_sort_order(u.scanned.arch_layer))
            .or_insert_with(|| (u.scanned.arch_layer, Vec::new()))
            .1
            .push(*u);
    }
    let has_multiple_layers = by_layer.len() > 1;

    let mut out = Vec::new();
    for (_order, (layer, mut layer_units)) in by_layer {
        layer_units.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));
        let layer_lines: usize = layer_units.iter().map(|u| u.scanned.line_count).sum();
        let layer_str = layer.as_str();
        let part_scope = dominant_group_scope(&layer_units, &group.module_path);

        // If this layer slice is already compact, keep it as a single sub-shard.
        if layer_units.len() <= MAX_GROUP_FILES && layer_lines <= MAX_GROUP_LINES {
            let sub_slug = if has_multiple_layers && layer != group.arch_layer {
                sanitize_slug(&format!("{}-{layer_str}", group.raw_slug))
            } else {
                group.raw_slug.clone()
            };
            let sub_path = group.module_path.clone();
            for u in &layer_units {
                file_to_raw_slug.insert(u.scanned.rel_path.clone(), sub_slug.clone());
            }
            out.push(RawShardGroup {
                raw_slug: sub_slug,
                title: format!("{sub_path} ({layer_str})"),
                module_path: sub_path,
                arch_layer: layer,
                scope: part_scope,
                units: layer_units,
            });
            continue;
        }

        // Step 2: Separate very large individual files (`>= LARGE_SINGLE_FILE_LINES`) into
        // dedicated `<base_slug>-<stem>` sub-shards, and pack remaining files into balanced chunks.
        let mut small_units: Vec<&'a ParsedFileUnit> = Vec::new();
        for u in layer_units {
            if u.scanned.line_count >= LARGE_SINGLE_FILE_LINES {
                let stem = disambiguated_unit_stem(u, &stem_counts, &group.raw_slug);
                let sub_slug = sanitize_slug(&format!("{}-{stem}", group.raw_slug));
                let sub_path = group.module_path.clone();
                let u_scope = u.scanned.scope;
                file_to_raw_slug.insert(u.scanned.rel_path.clone(), sub_slug.clone());
                out.push(RawShardGroup {
                    raw_slug: sub_slug,
                    title: format!("{sub_path} [{stem}] ({layer_str})"),
                    module_path: sub_path,
                    arch_layer: layer,
                    scope: u_scope,
                    units: vec![u],
                });
            } else {
                small_units.push(u);
            }
        }

        if small_units.is_empty() {
            continue;
        }

        // Pack remaining units into chunks of `<= MAX_GROUP_LINES` and `<= MAX_GROUP_FILES`.
        let mut chunks: Vec<Vec<&'a ParsedFileUnit>> = Vec::new();
        let mut current_chunk: Vec<&'a ParsedFileUnit> = Vec::new();
        let mut current_lines = 0usize;

        for u in small_units {
            if !current_chunk.is_empty()
                && (current_chunk.len() >= MAX_GROUP_FILES
                    || current_lines + u.scanned.line_count > MAX_GROUP_LINES)
            {
                chunks.push(std::mem::take(&mut current_chunk));
                current_lines = 0;
            }
            current_lines += u.scanned.line_count;
            current_chunk.push(u);
        }
        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }

        let num_chunks = chunks.len();
        for chunk in chunks {
            let chunk_scope = dominant_group_scope(&chunk, &group.module_path);
            let sub_path = group.module_path.clone();
            let (sub_slug, title) = if num_chunks == 1 && out.is_empty() {
                (group.raw_slug.clone(), format!("{sub_path} ({layer_str})"))
            } else if chunk.len() == 1 {
                let stem = disambiguated_unit_stem(chunk[0], &stem_counts, &group.raw_slug);
                (
                    sanitize_slug(&format!("{}-{stem}", group.raw_slug)),
                    format!("{sub_path} [{stem}] ({layer_str})"),
                )
            } else {
                let first_stem = disambiguated_unit_stem(chunk[0], &stem_counts, &group.raw_slug);
                let last_stem =
                    disambiguated_unit_stem(chunk[chunk.len() - 1], &stem_counts, &group.raw_slug);
                let (suffix, range_label) = if first_stem == last_stem {
                    (first_stem.clone(), format!("[{first_stem}]"))
                } else {
                    (
                        format!("{first_stem}-{last_stem}"),
                        format!("[{first_stem}..{last_stem}]"),
                    )
                };
                (
                    sanitize_slug(&format!("{}-{suffix}", group.raw_slug)),
                    format!("{sub_path} {range_label} ({layer_str})"),
                )
            };
            for u in &chunk {
                file_to_raw_slug.insert(u.scanned.rel_path.clone(), sub_slug.clone());
            }
            out.push(RawShardGroup {
                raw_slug: sub_slug,
                title,
                module_path: sub_path,
                arch_layer: layer,
                scope: chunk_scope,
                units: chunk,
            });
        }
    }

    out
}

fn disambiguated_unit_stem(
    unit: &ParsedFileUnit,
    stem_counts: &FxHashMap<String, usize>,
    group_raw_slug: &str,
) -> String {
    let raw_stem = unit_file_stem(unit);
    let is_generic = GENERIC_FILE_STEMS.contains(&raw_stem.as_str());
    let collides = stem_counts.get(&raw_stem).copied().unwrap_or(0) > 1;
    if !is_generic && !collides {
        return raw_stem;
    }

    let norm = unit.scanned.rel_path.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        let mut parent = parts[parts.len() - 2];
        if parent.eq_ignore_ascii_case("src") && parts.len() >= 3 {
            parent = parts[parts.len() - 3];
        }
        let parent_slug = sanitize_slug(parent);
        if !parent_slug.is_empty()
            && parent_slug != "src"
            && parent_slug != group_raw_slug
            && !group_raw_slug.ends_with(&format!("-{parent_slug}"))
        {
            return sanitize_slug(&format!("{parent_slug}-{raw_stem}"));
        }
    }
    raw_stem
}

fn unit_file_stem(unit: &ParsedFileUnit) -> String {
    let norm = unit.scanned.rel_path.replace('\\', "/");
    let fname = norm.rsplit('/').next().unwrap_or(norm.as_str());
    fname
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(fname)
        .to_ascii_lowercase()
}

fn is_three_segment_module_dirs(first: &str, second: &str) -> bool {
    matches!(
        first.to_ascii_lowercase().as_str(),
        "src" | "fw" | "firmware" | "app" | "apps" | "source"
    ) && matches!(
        second.to_ascii_lowercase().as_str(),
        "drvs"
            | "drv"
            | "drivers"
            | "driver"
            | "libs"
            | "lib"
            | "app"
            | "apps"
            | "bsp"
            | "services"
            | "service"
            | "core"
            | "modules"
            | "components"
    )
}

fn derive_unit_shard_meta(unit: &ParsedFileUnit) -> (String, String, String) {
    let existing_slug = unit
        .symbols
        .first()
        .map(|s| s.section_id.as_str())
        .or_else(|| unit.types.first().map(|t| t.section_id.as_str()))
        .or_else(|| unit.macros.first().map(|m| m.section_id.as_str()))
        .filter(|s| !s.is_empty());

    let normalized = unit.scanned.rel_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    let layer_str = unit.scanned.arch_layer.as_str();

    let (computed_slug, title, module_path) = if parts.len() >= 3
        && matches!(
            parts[0],
            "crates" | "packages" | "apps" | "services" | "modules" | "components"
        ) {
        let ws_root = parts[0];
        let crate_name = parts[1];
        if unit.scanned.scope == FileScope::Test
            || matches!(
                parts.get(2).copied(),
                Some("tests" | "test" | "benches" | "evals")
            )
        {
            let module_path = format!("{ws_root}/{crate_name}/tests");
            let slug = sanitize_slug(&format!("{ws_root}-{crate_name}-tests"));
            let title = format!("{module_path} ({layer_str})");
            (slug, title, module_path)
        } else {
            let module_path = format!("{ws_root}/{crate_name}");
            let slug = sanitize_slug(&format!("{ws_root}-{crate_name}"));
            let title = format!("{module_path} ({layer_str})");
            (slug, title, module_path)
        }
    } else {
        let dir_count = parts.len().saturating_sub(1);
        if dir_count >= 3 && is_three_segment_module_dirs(parts[0], parts[1]) {
            let a = parts[0];
            let b = parts[1];
            let c = parts[2];
            let module_path = format!("{a}/{b}/{c}");
            let slug = sanitize_slug(&format!("{a}-{b}-{c}"));
            let title = format!("{module_path} ({layer_str})");
            (slug, title, module_path)
        } else if dir_count >= 2 {
            let a = parts[0];
            let b = parts[1];
            let module_path = format!("{a}/{b}");
            let slug = sanitize_slug(&format!("{a}-{b}"));
            let title = format!("{module_path} ({layer_str})");
            (slug, title, module_path)
        } else if dir_count == 1 {
            let a = parts[0];
            let module_path = a.to_string();
            let slug = sanitize_slug(a);
            let title = format!("{module_path} ({layer_str})");
            (slug, title, module_path)
        } else {
            (
                "root".to_string(),
                format!("Root Module ({layer_str})"),
                "root".to_string(),
            )
        }
    };

    let final_slug = existing_slug
        .map(|s| strip_numeric_prefix(s).to_string())
        .unwrap_or(computed_slug);

    (final_slug, title, module_path)
}

fn strip_numeric_prefix(slug: &str) -> &str {
    let bytes = slug.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_digit() && bytes[1].is_ascii_digit() && bytes[2] == b'-'
    {
        &slug[3..]
    } else {
        slug
    }
}

fn sanitize_slug(raw: &str) -> String {
    let mut slug = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !slug.is_empty() {
            slug.push('-');
            prev_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "root".to_string()
    } else {
        slug
    }
}

fn scope_sort_order(scope: FileScope) -> u8 {
    match scope {
        FileScope::FirstParty => 0,
        FileScope::Test => 1,
        FileScope::VendorSdk => 2,
    }
}

/// Orders layers descending by architectural rank:
/// `app`/`cli`/`api` -> `core`/`services` -> `bsp` -> `drvs`/`domain` -> `config`/`libs` -> `other` -> `tests` -> `vendor_hal`
fn layer_sort_order(layer: ArchLayer) -> u8 {
    match layer {
        ArchLayer::App | ArchLayer::Cli | ArchLayer::Api => 0,
        ArchLayer::Core | ArchLayer::Services => 1,
        ArchLayer::Bsp => 2,
        ArchLayer::Drivers | ArchLayer::Domain => 3,
        ArchLayer::Config | ArchLayer::Libs => 4,
        ArchLayer::Other => 5,
        ArchLayer::Tests => 6,
        ArchLayer::VendorHal => 7,
    }
}

fn infer_repo_name(units: &[ParsedFileUnit]) -> String {
    for u in units {
        if let Some(parent) = u.scanned.abs_path.parent() {
            let rel_depth = u.scanned.rel_path.split(['/', '\\']).count();
            let mut root = u.scanned.abs_path.as_path();
            for _ in 0..rel_depth {
                if let Some(p) = root.parent() {
                    root = p;
                }
            }
            if let Some(name) = root.file_name().and_then(|s| s.to_str()) {
                if !name.is_empty() && name != "." {
                    return name.to_string();
                }
            }
            if let Some(name) = parent.file_name().and_then(|s| s.to_str()) {
                if !name.is_empty() && name != "." {
                    return name.to_string();
                }
            }
        }
    }
    "repository".to_string()
}

fn escape_yaml(val: &str) -> String {
    val.replace('\\', "/").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ExtractedSymbol, LanguageKind, ScannedFile, SymbolKind, TypeKind, Visibility,
    };
    use std::path::PathBuf;

    fn make_unit(rel_path: &str, scope: FileScope, arch_layer: ArchLayer) -> ParsedFileUnit {
        ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: rel_path.to_string(),
                abs_path: PathBuf::from(rel_path),
                language: LanguageKind::C,
                scope,
                arch_layer,
                size_bytes: 128,
                mtime_secs: 0,
                mtime_nanos: 0,
                blake3_hash: "0123456789abcdef".to_string(),
                line_count: 16,
            },
            symbols: Vec::new(),
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        }
    }

    fn add_symbol(unit: &mut ParsedFileUnit, name: &str) {
        unit.symbols.push(ExtractedSymbol {
            symbol_id: format!("{}::{}", unit.scanned.rel_path, name),
            name: name.to_string(),
            qualified_name: name.to_string(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            file: unit.scanned.rel_path.clone(),
            start_line: 1,
            end_line: 3,
            signature: format!("void {name}(void)"),
            doc_summary: String::new(),
            enclosing_type: None,
            scope: unit.scanned.scope,
            arch_layer: unit.scanned.arch_layer,
            section_id: String::new(),
        });
    }

    fn add_type(unit: &mut ParsedFileUnit, name: &str) {
        unit.types.push(ExtractedType {
            type_id: format!("{}::{}", unit.scanned.rel_path, name),
            name: name.to_string(),
            kind: TypeKind::Struct,
            visibility: Visibility::Public,
            file: unit.scanned.rel_path.clone(),
            start_line: 1,
            end_line: 5,
            fields_summary: "field: u32".to_string(),
            doc_summary: String::new(),
            scope: unit.scanned.scope,
            arch_layer: unit.scanned.arch_layer,
            section_id: String::new(),
        });
    }

    fn add_macro(unit: &mut ParsedFileUnit, name: &str, kind: MacroKind) {
        unit.macros.push(ExtractedMacro {
            name: name.to_string(),
            kind,
            value_or_args: "0x1U".to_string(),
            hex_addr: None,
            file: unit.scanned.rel_path.clone(),
            line: 2,
            scope: unit.scanned.scope,
            arch_layer: unit.scanned.arch_layer,
            section_id: String::new(),
            description: String::new(),
        });
    }

    fn build(
        units: &[ParsedFileUnit],
        vendor_surface: &VendorSurfaceSummary,
        vendor_mode: VendorMode,
    ) -> (Vec<SectionSummary>, Vec<SectionShard>) {
        let mut ranked_symbols: Vec<RankedSymbol> = units
            .iter()
            .flat_map(|u| u.symbols.iter().cloned())
            .map(|symbol| RankedSymbol {
                symbol,
                pagerank: 0.5,
                hub_score: 0.1,
                authority_score: 0.1,
                in_degree: 0,
                out_degree: 0,
                is_god_node: false,
                is_entrypoint: false,
                scc_id: None,
            })
            .collect();
        let mut types: Vec<ExtractedType> =
            units.iter().flat_map(|u| u.types.iter().cloned()).collect();
        let mut macros: Vec<ExtractedMacro> = units
            .iter()
            .flat_map(|u| u.macros.iter().cloned())
            .collect();
        let mut calls: Vec<ResolvedCallEdge> = Vec::new();
        let mut xrefs: Vec<XrefEntry> = Vec::new();

        build_section_shards(
            "test-repo",
            units,
            &mut ranked_symbols,
            &mut types,
            &mut macros,
            &mut calls,
            &mut xrefs,
            vendor_surface,
            vendor_mode,
        )
    }

    #[test]
    fn test_scope_keyed_grouping_separates_first_party_and_vendor() {
        let mut units = vec![
            make_unit(
                "fw/drvs/My_DriverLib/foo.c",
                FileScope::VendorSdk,
                ArchLayer::VendorHal,
            ),
            make_unit(
                "fw/drvs/My_DriverLib/bar.c",
                FileScope::VendorSdk,
                ArchLayer::VendorHal,
            ),
            make_unit("fw/drvs/pwm.c", FileScope::FirstParty, ArchLayer::Drivers),
        ];
        add_symbol(&mut units[0], "driverlib_foo_init");
        add_symbol(&mut units[2], "pwm_init");

        let surface = VendorSurfaceSummary::default();
        let (summaries, shards) = build(&units, &surface, VendorMode::All);

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].module_path, "fw/drvs");
        assert_eq!(summaries[0].scope, "first_party");
        assert_eq!(summaries[0].arch_layer, "drvs");
        assert_eq!(summaries[0].symbol_count, 1);

        assert_eq!(summaries[1].module_path, "fw/drvs/My_DriverLib");
        assert_eq!(summaries[1].scope, "vendor_sdk");
        assert_eq!(summaries[1].arch_layer, "vendor_hal");
        assert_eq!(summaries[1].symbol_count, 1);
        assert!(shards[1].markdown_body.contains("scope: \"vendor_sdk\""));
    }

    #[test]
    fn test_same_slug_different_scopes_disambiguated() {
        let units = vec![
            make_unit("fw/drvs/pwm.c", FileScope::FirstParty, ArchLayer::Drivers),
            make_unit("fw/drvs/motor.c", FileScope::FirstParty, ArchLayer::Drivers),
            make_unit(
                "fw/drvs/register_map.c",
                FileScope::VendorSdk,
                ArchLayer::VendorHal,
            ),
        ];

        let surface = VendorSurfaceSummary::default();
        let (summaries, _) = build(&units, &surface, VendorMode::All);

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].section_id, "01-fw-drvs");
        assert_eq!(summaries[0].scope, "first_party");
        assert_eq!(summaries[0].arch_layer, "drvs");
        assert_eq!(summaries[1].section_id, "02-fw-drvs-vendor");
        assert_eq!(summaries[1].scope, "vendor_sdk");
        assert_eq!(summaries[1].arch_layer, "vendor_hal");
    }

    #[test]
    fn test_vendor_module_path_forces_vendor_scope() {
        // Even when the files were (mis)classified as first-party, a vendor module path wins.
        let mut unit = make_unit(
            "references/libs/STM32Cube/bar.c",
            FileScope::FirstParty,
            ArchLayer::Libs,
        );
        add_symbol(&mut unit, "cube_bar_init");

        let surface = VendorSurfaceSummary::default();
        let (summaries, _) = build(&[unit], &surface, VendorMode::All);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].module_path, "references/libs");
        assert_eq!(summaries[0].scope, "vendor_sdk");
        assert_eq!(summaries[0].arch_layer, "vendor_hal");
    }

    #[test]
    fn test_active_mode_drops_unreferenced_vendor_shards() {
        let mut cmsis = make_unit(
            "vendor/cmsis/device.h",
            FileScope::VendorSdk,
            ArchLayer::VendorHal,
        );
        add_symbol(&mut cmsis, "hal_enable");
        add_symbol(&mut cmsis, "hal_never_used");
        add_type(&mut cmsis, "TIM_TypeDef");
        add_macro(&mut cmsis, "BUSY_FLAG", MacroKind::Bitmask);

        let mut legacy = make_unit(
            "vendor/legacy/old_drv.c",
            FileScope::VendorSdk,
            ArchLayer::VendorHal,
        );
        add_symbol(&mut legacy, "legacy_unused_init");

        let mut app = make_unit("src/app/main.c", FileScope::FirstParty, ArchLayer::App);
        add_symbol(&mut app, "app_main");

        let units = vec![cmsis, legacy, app];
        let surface = VendorSurfaceSummary {
            total_vendor_files: 2,
            total_vendor_symbols: 3,
            active_vendor_symbols: vec!["hal_enable".to_string()],
            active_mmio_registers: Vec::new(),
            active_vendor_headers: Vec::new(),
        };

        let (active_summaries, active_shards) = build(&units, &surface, VendorMode::Active);
        assert_eq!(active_summaries.len(), 2);
        assert!(active_summaries
            .iter()
            .all(|s| s.module_path != "vendor/legacy"));

        let cmsis_shard = active_shards
            .iter()
            .find(|s| s.summary.module_path == "vendor/cmsis")
            .expect("active vendor shard kept");
        assert!(cmsis_shard.markdown_body.contains("hal_enable"));
        assert!(!cmsis_shard.markdown_body.contains("hal_never_used"));
        assert_eq!(cmsis_shard.files, vec!["vendor/cmsis/device.h".to_string()]);

        // `VendorMode::All` keeps every vendor shard with its full symbol surface.
        let (all_summaries, all_shards) = build(&units, &surface, VendorMode::All);
        assert_eq!(all_summaries.len(), 3);
        let all_cmsis = all_shards
            .iter()
            .find(|s| s.summary.module_path == "vendor/cmsis")
            .expect("vendor shard in all mode");
        assert!(all_cmsis.markdown_body.contains("hal_never_used"));
    }

    #[test]
    fn test_active_mode_keeps_vendor_shards_without_first_party_code() {
        // A vendor-only repository must still produce shards in active mode.
        let mut unit = make_unit(
            "vendor/cmsis/device.h",
            FileScope::VendorSdk,
            ArchLayer::VendorHal,
        );
        add_symbol(&mut unit, "unused_hal");

        let surface = VendorSurfaceSummary::default();
        let (summaries, _) = build(&[unit], &surface, VendorMode::Active);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].scope, "vendor_sdk");
        assert_eq!(summaries[0].arch_layer, "vendor_hal");
    }

    #[test]
    fn test_active_mode_compacts_units_to_active_surface() {
        let mut active_header = make_unit(
            "vendor/hal/active_reg.h",
            FileScope::VendorSdk,
            ArchLayer::VendorHal,
        );
        add_symbol(&mut active_header, "ACTIVE_REG_READ");

        let mut idle_header = make_unit(
            "vendor/hal/idle_reg.h",
            FileScope::VendorSdk,
            ArchLayer::VendorHal,
        );
        add_symbol(&mut idle_header, "IDLE_REG_READ");

        let mut app = make_unit(
            "src/drvs/motor.c",
            FileScope::FirstParty,
            ArchLayer::Drivers,
        );
        add_symbol(&mut app, "motor_step");

        let units = vec![active_header, idle_header, app];
        let surface = VendorSurfaceSummary {
            total_vendor_files: 2,
            total_vendor_symbols: 2,
            active_vendor_symbols: vec!["ACTIVE_REG_READ".to_string()],
            active_mmio_registers: Vec::new(),
            active_vendor_headers: vec!["vendor/hal/active_reg.h".to_string()],
        };

        let (_, shards) = build(&units, &surface, VendorMode::Active);
        let hal_shard = shards
            .iter()
            .find(|s| s.summary.module_path == "vendor/hal")
            .expect("vendor/hal shard");
        assert_eq!(hal_shard.files, vec!["vendor/hal/active_reg.h".to_string()]);
        assert!(hal_shard.markdown_body.contains("ACTIVE_REG_READ"));
        assert!(!hal_shard.markdown_body.contains("IDLE_REG_READ"));
    }
}
