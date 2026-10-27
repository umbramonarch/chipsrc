use crate::model::{
    ArchLayer, ExtractedMacro, ExtractedType, FileScope, MacroKind, ParsedFileUnit, RankedSymbol,
    ResolvedCallEdge, SectionShard, SectionSummary, VendorMode, VendorSurfaceSummary, XrefEntry,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};

struct RawShardGroup<'a> {
    raw_slug: String,
    title: String,
    module_path: String,
    arch_layer: ArchLayer,
    scope: FileScope,
    units: Vec<&'a ParsedFileUnit>,
}

/// Groups parsed files into architectural module shards, numbers them deterministically
/// (`01-<slug>`, `02-<slug>`, ...), updates `section_id` across all index records, computes
/// cross-shard call dependencies, and renders each shard's Markdown signature skeleton.
#[allow(clippy::too_many_arguments)]
pub fn build_section_shards(
    units: &[ParsedFileUnit],
    ranked_symbols: &mut [RankedSymbol],
    types: &mut [ExtractedType],
    macros: &mut [ExtractedMacro],
    calls: &mut [ResolvedCallEdge],
    xrefs: &mut [XrefEntry],
    vendor_surface: &VendorSurfaceSummary,
    vendor_mode: VendorMode,
) -> (Vec<SectionSummary>, Vec<SectionShard>) {
    if units.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let repo_name = infer_repo_name(units);

    // 1. Group files by initial section_id slug
    let mut group_map: BTreeMap<String, RawShardGroup<'_>> = BTreeMap::new();
    let mut file_to_raw_slug: FxHashMap<String, String> = FxHashMap::default();

    for unit in units {
        if vendor_mode == VendorMode::None && unit.scanned.scope == FileScope::VendorSdk {
            continue;
        }
        let (slug, title, module_path) = derive_unit_shard_meta(unit);
        file_to_raw_slug.insert(unit.scanned.rel_path.clone(), slug.clone());

        let entry = group_map
            .entry(slug.clone())
            .or_insert_with(|| RawShardGroup {
                raw_slug: slug,
                title,
                module_path,
                arch_layer: unit.scanned.arch_layer,
                scope: unit.scanned.scope,
                units: Vec::new(),
            });

        // If any file in the group is FirstParty, promote group scope & layer accordingly
        if scope_sort_order(unit.scanned.scope) < scope_sort_order(entry.scope) {
            entry.scope = unit.scanned.scope;
            entry.arch_layer = unit.scanned.arch_layer;
            let (_, new_title, new_mod) = derive_unit_shard_meta(unit);
            entry.title = new_title;
            entry.module_path = new_mod;
        } else if unit.scanned.scope == entry.scope
            && layer_sort_order(unit.scanned.arch_layer) < layer_sort_order(entry.arch_layer)
        {
            entry.arch_layer = unit.scanned.arch_layer;
        }

        entry.units.push(unit);
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

    // Filter or keep vendor groups when vendor_mode == VendorMode::Active
    let has_non_vendor = group_map.values().any(|g| g.scope != FileScope::VendorSdk);

    let mut groups: Vec<RawShardGroup<'_>> = group_map
        .into_values()
        .filter(|g| {
            if g.scope != FileScope::VendorSdk || vendor_mode == VendorMode::All || !has_non_vendor
            {
                return true;
            }
            if vendor_mode == VendorMode::None {
                return false;
            }
            // In VendorMode::Active, keep vendor shard if it has active symbols/MMIO/headers,
            // or keep it as a compact summary shard if it defines symbols/macros
            group_has_active_vendor_refs(g, &active_vendor_set, &active_header_set)
                || g.units
                    .iter()
                    .any(|u| !u.symbols.is_empty() || !u.types.is_empty() || !u.macros.is_empty())
        })
        .collect();

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

    // 3. Assign numbered section IDs (01-<slug>, 02-<slug>, ...) and build slug -> numbered map
    let mut slug_to_numbered: FxHashMap<String, String> = FxHashMap::default();
    let mut file_to_numbered: FxHashMap<String, String> = FxHashMap::default();

    for (idx, group) in groups.iter().enumerate() {
        let clean_slug = strip_numeric_prefix(&group.raw_slug);
        let numbered_id = format!("{:02}-{clean_slug}", idx + 1);
        slug_to_numbered.insert(group.raw_slug.clone(), numbered_id.clone());
        slug_to_numbered.insert(clean_slug.to_string(), numbered_id.clone());
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

    let resolve_numbered = |raw_sec: &str, file: &str| -> String {
        if let Some(mapped) = slug_to_numbered.get(raw_sec) {
            return mapped.clone();
        }
        if let Some(mapped) = file_to_numbered.get(file) {
            return mapped.clone();
        }
        if let Some(raw_slug) = file_to_raw_slug.get(file) {
            if let Some(mapped) = slug_to_numbered.get(raw_slug) {
                return mapped.clone();
            }
        }
        fallback_sec_id.clone()
    };

    // Update section_id on all ranked_symbols, types, macros, calls, and xrefs
    for rs in ranked_symbols.iter_mut() {
        rs.symbol.section_id = resolve_numbered(&rs.symbol.section_id, &rs.symbol.file);
    }
    for t in types.iter_mut() {
        t.section_id = resolve_numbered(&t.section_id, &t.file);
    }
    for m in macros.iter_mut() {
        m.section_id = resolve_numbered(&m.section_id, &m.file);
    }
    for c in calls.iter_mut() {
        c.section_id = resolve_numbered(&c.section_id, &c.file);
    }
    for x in xrefs.iter_mut() {
        x.section_id = resolve_numbered(&x.section_id, &x.file);
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
        callees_by_caller
            .entry(call.caller_id.as_str())
            .or_default()
            .push(call.callee_name.as_str());

        if !call.tier.is_resolved() {
            continue;
        }
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

    // 5. Render each shard's markdown_body and assemble SectionSummary + SectionShard
    let mut summaries = Vec::with_capacity(groups.len());
    let mut shards = Vec::with_capacity(groups.len());

    for (idx, mut group) in groups.into_iter().enumerate() {
        let clean_slug = strip_numeric_prefix(&group.raw_slug);
        let section_id = format!("{:02}-{clean_slug}", idx + 1);
        let md_file = format!("{section_id}.md");

        group
            .units
            .sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));

        let files: Vec<String> = group
            .units
            .iter()
            .map(|u| u.scanned.rel_path.clone())
            .collect();

        let mut shard_symbols: Vec<&RankedSymbol> = ranked_symbols
            .iter()
            .filter(|rs| rs.symbol.section_id == section_id)
            .collect();
        shard_symbols.sort_by(|a, b| {
            b.pagerank
                .total_cmp(&a.pagerank)
                .then_with(|| a.symbol.file.cmp(&b.symbol.file))
                .then_with(|| a.symbol.start_line.cmp(&b.symbol.start_line))
                .then_with(|| a.symbol.name.cmp(&b.symbol.name))
        });

        let mut shard_types: Vec<&ExtractedType> = types
            .iter()
            .filter(|t| t.section_id == section_id)
            .collect();
        shard_types.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| a.start_line.cmp(&b.start_line))
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut shard_macros: Vec<&ExtractedMacro> = macros
            .iter()
            .filter(|m| m.section_id == section_id)
            .collect();
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

        let depends_on_sections: Vec<String> = depends_on_map
            .remove(&section_id)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default();
        let depended_by_sections: Vec<String> = depended_by_map
            .remove(&section_id)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default();

        let markdown_body = render_shard_markdown(
            &repo_name,
            &section_id,
            &group,
            &shard_symbols,
            &shard_types,
            &shard_macros,
            &depends_on_sections,
            &depended_by_sections,
            &callees_by_caller,
            &active_vendor_set,
            vendor_mode,
        );

        let token_estimate = markdown_body.len().div_ceil(4);

        let summary = SectionSummary {
            section_id: section_id.clone(),
            title: group.title.clone(),
            module_path: group.module_path.clone(),
            arch_layer: group.arch_layer.as_str().to_string(),
            scope: group.scope.as_str().to_string(),
            file_count: files.len(),
            symbol_count: shard_symbols.len(),
            type_count: shard_types.len(),
            macro_count: shard_macros.len(),
            token_estimate,
            md_file,
        };

        summaries.push(summary.clone());
        shards.push(SectionShard {
            summary,
            files,
            depends_on_sections,
            depended_by_sections,
            markdown_body,
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
    vendor_mode: VendorMode,
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
        let max_types = if group.scope == FileScope::VendorSdk && vendor_mode == VendorMode::Active
        {
            40
        } else {
            usize::MAX
        };
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
        let display_symbols: Vec<&RankedSymbol> =
            if group.scope == FileScope::VendorSdk && vendor_mode == VendorMode::Active {
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

fn group_has_active_vendor_refs(
    group: &RawShardGroup<'_>,
    active_vendor_set: &FxHashSet<&str>,
    active_header_set: &FxHashSet<&str>,
) -> bool {
    for u in &group.units {
        if active_header_set
            .iter()
            .any(|h| u.scanned.rel_path.ends_with(h))
        {
            return true;
        }
        if u.symbols
            .iter()
            .any(|s| active_vendor_set.contains(s.name.as_str()))
        {
            return true;
        }
        if u.types
            .iter()
            .any(|t| active_vendor_set.contains(t.name.as_str()))
        {
            return true;
        }
        if u.macros
            .iter()
            .any(|m| active_vendor_set.contains(m.name.as_str()))
        {
            return true;
        }
    }
    false
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

    let (computed_slug, title, module_path) = if parts.len() >= 3 && parts[0] == "crates" {
        let crate_name = parts[1];
        let module_path = format!("crates/{crate_name}");
        let slug = sanitize_slug(&format!("crates-{crate_name}"));
        let title = format!("{module_path} ({layer_str})");
        (slug, title, module_path)
    } else {
        let dir_count = parts.len().saturating_sub(1);
        if dir_count >= 2 {
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
