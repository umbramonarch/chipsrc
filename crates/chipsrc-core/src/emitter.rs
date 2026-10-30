use crate::error::{ChipsrcError, Result};
use crate::model::{
    BundleIndexes, BundleMetaFile, ConvertConfig, ExtractedType, FileScope, IncrementalAstCache,
    RankedSymbol, RepoMetadata, SanityReport, SectionShard,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::fs;
use std::path::Path;

/// Sanitizes a string for TSV emission by replacing tabs, newlines, and control characters
/// with spaces and collapsing consecutive whitespace into a single space.
pub fn sanitize_tsv(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == '\t' || c == '\r' || c == '\n' || c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Ensures `.claudeignore` in `repo_path` contains the bundle output directory ONLY when
/// `output_root` resides inside `repo_path`, preventing out-of-tree conversions from mutating
/// external directories.
pub fn ensure_claudeignore_entry(repo_path: &Path, output_root: &Path) -> Result<bool> {
    let canon_repo = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    let canon_out = output_root
        .canonicalize()
        .unwrap_or_else(|_| output_root.to_path_buf());

    let Ok(rel_out) = canon_out.strip_prefix(&canon_repo) else {
        // Output directory is outside the repository tree; never mutate `.claudeignore`.
        return Ok(false);
    };
    let Some(first_comp) = rel_out
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
    else {
        return Ok(false);
    };
    if first_comp.is_empty() || first_comp == "." || first_comp == ".." {
        return Ok(false);
    }

    let dir_name = first_comp;
    let entry = format!("{dir_name}/");
    let claudeignore_path = canon_repo.join(".claudeignore");

    let existing = fs::read_to_string(&claudeignore_path).unwrap_or_default();
    if existing
        .lines()
        .any(|l| l.trim() == entry || l.trim() == dir_name)
    {
        return Ok(false);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("# chipsrc generated bundles (prevents prompt cache invalidation)\n");
    updated.push_str(&entry);
    updated.push('\n');
    write_file(&claudeignore_path, &updated)?;
    Ok(true)
}

/// Emits the complete Hierarchical Agent Codebase Bundle (`INDEX.md`, `sections/*.md`,
/// `index/*.tsv`, `meta.json`, `cache.json`, optional `<repo_name>.md`, and `.claudeignore`).
pub fn emit_bundle(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    sanity: &SanityReport,
    sections: &[SectionShard],
    indexes: &BundleIndexes,
    cache: &IncrementalAstCache,
) -> Result<bool> {
    let output_dir = &config.output_dir;
    let sections_dir = output_dir.join("sections");
    let index_dir = output_dir.join("index");

    create_dir(output_dir)?;
    create_dir(&sections_dir)?;
    create_dir(&index_dir)?;

    // Clean stale .md files in output_dir/sections/ that are no longer part of `sections`
    let expected_md: FxHashSet<&str> = sections
        .iter()
        .map(|s| {
            s.summary
                .md_file
                .strip_prefix("sections/")
                .unwrap_or(s.summary.md_file.as_str())
        })
        .collect();
    if let Ok(entries) = fs::read_dir(&sections_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("md") {
                let keep = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| expected_md.contains(name));
                if !keep {
                    let _ = fs::remove_file(p);
                }
            }
        }
    }

    // 1. Write INDEX.md
    let index_md = build_master_index_markdown(metadata, sanity, sections, indexes);
    write_file(&output_dir.join("INDEX.md"), &index_md)?;

    // 2. Write sections/<md_file> for each SectionShard
    for shard in sections {
        let rel_md = shard
            .summary
            .md_file
            .strip_prefix("sections/")
            .unwrap_or(&shard.summary.md_file);
        write_file(&sections_dir.join(rel_md), &shard.markdown_body)?;
    }

    // 3. Write index/sections.tsv
    let mut sec_tsv = String::from(
        "section_id\ttitle\tmodule_path\tarch_layer\tscope\tfile_count\tsymbol_count\ttype_count\tmacro_count\ttoken_estimate\tmd_file\n",
    );
    for s in &indexes.sections {
        sec_tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            sanitize_tsv(&s.section_id),
            sanitize_tsv(&s.title),
            sanitize_tsv(&s.module_path),
            sanitize_tsv(&s.arch_layer),
            sanitize_tsv(&s.scope),
            s.file_count,
            s.symbol_count,
            s.type_count,
            s.macro_count,
            s.token_estimate,
            sanitize_tsv(&s.md_file),
        ));
    }
    write_file(&index_dir.join("sections.tsv"), &sec_tsv)?;

    // 4. Write index/symbols.tsv (includes doc_summary as 15th column)
    let mut sym_tsv = String::from(
        "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\tdoc_summary\n",
    );
    for rs in &indexes.symbols {
        let s = &rs.symbol;
        sym_tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            sanitize_tsv(&s.symbol_id),
            sanitize_tsv(&s.name),
            s.kind.as_str(),
            s.visibility.as_str(),
            sanitize_tsv(&s.file),
            s.start_line,
            s.end_line,
            sanitize_tsv(&s.signature),
            rs.pagerank,
            rs.in_degree,
            rs.out_degree,
            s.arch_layer.as_str(),
            s.scope.as_str(),
            sanitize_tsv(&s.section_id),
            sanitize_tsv(&s.doc_summary),
        ));
    }
    write_file(&index_dir.join("symbols.tsv"), &sym_tsv)?;

    // 5. Write index/types.tsv (includes doc_summary as 12th column)
    let mut typ_tsv = String::from(
        "type_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tfields_summary\tarch_layer\tscope\tsection_id\tdoc_summary\n",
    );
    for t in &indexes.types {
        typ_tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            sanitize_tsv(&t.type_id),
            sanitize_tsv(&t.name),
            t.kind.as_str(),
            t.visibility.as_str(),
            sanitize_tsv(&t.file),
            t.start_line,
            t.end_line,
            sanitize_tsv(&t.fields_summary),
            t.arch_layer.as_str(),
            t.scope.as_str(),
            sanitize_tsv(&t.section_id),
            sanitize_tsv(&t.doc_summary),
        ));
    }
    write_file(&index_dir.join("types.tsv"), &typ_tsv)?;

    // 6. Write index/calls.tsv
    let mut calls_tsv = String::from(
        "caller_id\tcaller_name\tcallee_name\tcallee_id\tfile\tline\ttier\tsection_id\n",
    );
    for c in &indexes.calls {
        calls_tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            sanitize_tsv(&c.caller_id),
            sanitize_tsv(&c.caller_name),
            sanitize_tsv(&c.callee_name),
            sanitize_tsv(&c.callee_id),
            sanitize_tsv(&c.file),
            c.line,
            c.tier.as_str(),
            sanitize_tsv(&c.section_id),
        ));
    }
    write_file(&index_dir.join("calls.tsv"), &calls_tsv)?;

    // 7. Write index/macros.tsv
    let mut mac_tsv = String::from(
        "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription\n",
    );
    for m in &indexes.macros {
        mac_tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            sanitize_tsv(&m.name),
            m.kind.as_str(),
            sanitize_tsv(&m.value_or_args),
            sanitize_tsv(m.hex_addr.as_deref().unwrap_or("-")),
            sanitize_tsv(&m.file),
            m.line,
            m.arch_layer.as_str(),
            m.scope.as_str(),
            sanitize_tsv(&m.section_id),
            sanitize_tsv(&m.description),
        ));
    }
    write_file(&index_dir.join("macros.tsv"), &mac_tsv)?;

    // 8. Write index/xref.tsv
    let mut xref_tsv =
        String::from("symbol\tcategory\trelation\ttarget\tfile\tline\tsection_id\tcontext\n");
    for x in &indexes.xrefs {
        xref_tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            sanitize_tsv(&x.symbol),
            sanitize_tsv(&x.category),
            sanitize_tsv(&x.relation),
            sanitize_tsv(&x.target),
            sanitize_tsv(&x.file),
            x.line,
            sanitize_tsv(&x.section_id),
            sanitize_tsv(&x.context),
        ));
    }
    write_file(&index_dir.join("xref.tsv"), &xref_tsv)?;

    // 9. Write meta.json
    let meta_file = BundleMetaFile {
        metadata: metadata.clone(),
        sanity: sanity.clone(),
    };
    let meta_json = serde_json::to_string_pretty(&meta_file)?;
    write_file(&output_dir.join("meta.json"), &meta_json)?;

    // 10. Write cache.json (compact single-line JSON for fast I/O and minimal footprint)
    let cache_json = serde_json::to_string(cache)?;
    write_file(&output_dir.join("cache.json"), &cache_json)?;

    // 11. Optional <repo_name>.md if config.single_file is true
    if config.single_file {
        let mut combined = String::with_capacity(index_md.len() + sections.len() * 2048);
        combined.push_str(&index_md);
        combined.push_str("\n---\n\n");
        for shard in sections {
            combined.push_str(&shard.markdown_body);
            combined.push_str("\n\n---\n\n");
        }
        let single_path = output_dir.join(format!("{}.md", metadata.repo_name));
        write_file(&single_path, &combined)?;
    }

    // 12. Ensure .claudeignore entry (only when output_dir is inside repo_path)
    let claudeignore_updated = ensure_claudeignore_entry(&config.repo_path, output_dir)?;
    Ok(claudeignore_updated)
}

fn build_master_index_markdown(
    metadata: &RepoMetadata,
    sanity: &SanityReport,
    sections: &[SectionShard],
    indexes: &BundleIndexes,
) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(256);

    lines.push(format!(
        "# {} — Codebase Intelligence Bundle",
        metadata.repo_name
    ));
    lines.push(String::new());

    // Agent Navigation Guide
    lines.push("> **Agent Navigation Guide**:".to_string());
    lines.push(
        "> - **1-Turn CLI Queries**: `chipsrc sym <name> [--show]`, `chipsrc callers <fn> [--show]`, `chipsrc callees <fn> [--show]`, `chipsrc type <name> [--show]`, `chipsrc macro <name|hex> [--show]`, `chipsrc section <query> [--show]`, `chipsrc xref <symbol>`, `chipsrc search <pattern>`."
            .to_string(),
    );
    lines.push(
        "> - **Direct Flat TSV Indexes**: Grep `index/symbols.tsv`, `index/types.tsv`, `index/calls.tsv`, `index/macros.tsv`, `index/xref.tsv`, and `index/sections.tsv`."
            .to_string(),
    );
    lines.push(
        "> - **Module Signature Skeletons**: Read `sections/*.md` for compact module signatures and exact `file:start_line-end_line` coordinates before opening raw source files."
            .to_string(),
    );
    lines.push(String::new());

    // Repository Summary
    lines.push("## Repository Summary".to_string());
    lines.push(String::new());
    lines.push(format!("- **Source Root**: `{}`", metadata.source_root));
    lines.push(format!(
        "- **Repository Fingerprint**: `{}` (vendor mode: `{}`)",
        metadata.fingerprint,
        metadata.vendor_mode.as_str()
    ));
    lines.push(format!(
        "- **Source Files**: {} total ({} first-party, {} vendor SDK, {} test) | **Total Lines**: {}",
        metadata.total_files,
        metadata.first_party_files,
        metadata.vendor_files,
        metadata.test_files,
        metadata.total_lines
    ));
    if !metadata.languages.is_empty() {
        let lang_summary: Vec<String> = metadata
            .languages
            .iter()
            .map(|l| format!("`{}` ({} files, {} lines)", l.language, l.files, l.lines))
            .collect();
        lines.push(format!("- **Languages**: {}", lang_summary.join(", ")));
    }
    lines.push(format!(
        "- **Indexed Entities**: {} symbols ({} hubs, {} entrypoints/ISRs) | {} types | {} call edges ({:.1}% resolved) | {} macros/MMIO | {} xrefs",
        metadata.symbol_count,
        metadata.god_node_count,
        metadata.entrypoint_count,
        metadata.type_count,
        metadata.call_edge_count,
        sanity.call_resolution_ratio * 100.0,
        metadata.macro_count,
        metadata.xref_count
    ));
    lines.push(format!(
        "- **Sanity & Token Compression**: **{}/100** ({:.1}% clean parse) | ~{} raw source tokens -> ~{} bundle index tokens (**{:.1}x compression**)",
        sanity.score,
        sanity.parse_clean_ratio * 100.0,
        sanity.raw_source_tokens_est,
        sanity.bundle_index_tokens_est,
        sanity.token_compression_ratio
    ));
    lines.push(String::new());

    // Architectural Layer Topology
    lines.push("## Architectural Layer Topology".to_string());
    lines.push(String::new());
    if indexes.layer_edges.is_empty() {
        lines.push("_No cross-layer call or import edges detected._".to_string());
    } else {
        lines.push("| From Layer -> To Layer | Calls | Imports | Status |".to_string());
        lines.push("| --- | ---: | ---: | --- |".to_string());
        for edge in &indexes.layer_edges {
            let status = if edge.is_upward_violation {
                "UPWARD VIOLATION"
            } else {
                "OK"
            };
            lines.push(format!(
                "| `{}` -> `{}` | {} | {} | {} |",
                edge.from_layer, edge.to_layer, edge.call_count, edge.import_count, status
            ));
        }
    }
    if !indexes.cycles.is_empty() {
        lines.push(String::new());
        lines.push("### Strongly Connected Cyclic Clusters (SCCs)".to_string());
        for c in &indexes.cycles {
            lines.push(format!(
                "- **SCC #{}** ({} symbols in `{}`): {}",
                c.scc_id,
                c.symbols.len(),
                c.files.join(", "),
                c.symbols
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(" <-> ")
            ));
        }
    }
    lines.push(String::new());

    // Entrypoints & Interrupt Service Routines (ISRs)
    lines.push("## Entrypoints & Interrupt Service Routines (ISRs)".to_string());
    lines.push(String::new());
    let entrypoints_list = select_entrypoints(indexes);
    if entrypoints_list.is_empty() {
        lines.push("_No explicit entrypoints or ISRs detected._".to_string());
    } else {
        lines.push("| Symbol | Kind | Layer | Location | Out-Calls | Signature |".to_string());
        lines.push("| --- | --- | --- | --- | ---: | --- |".to_string());
        for rs in entrypoints_list.iter().take(25) {
            let s = &rs.symbol;
            lines.push(format!(
                "| `{}` | `{}` | `{}` | `{}:{}-{}` | {} | `{}` |",
                escape_table(&s.name),
                s.kind.as_str(),
                s.arch_layer.as_str(),
                s.file,
                s.start_line,
                s.end_line,
                rs.out_degree,
                escape_table(&s.signature)
            ));
        }
    }
    lines.push(String::new());

    // Central Architectural Hubs (God Nodes)
    lines.push("## Central Architectural Hubs (God Nodes)".to_string());
    lines.push(String::new());
    let god_nodes_list = select_god_nodes(indexes);
    if god_nodes_list.is_empty() {
        lines.push("_No central architectural hubs ranked._".to_string());
    } else {
        lines.push(
            "| Rank | Symbol | Kind | Layer | PageRank | In/Out | Location | Signature |"
                .to_string(),
        );
        lines.push("| ---: | --- | --- | --- | ---: | --- | --- | --- |".to_string());
        for (idx, rs) in god_nodes_list.iter().take(15).enumerate() {
            let s = &rs.symbol;
            lines.push(format!(
                "| {} | `{}` | `{}` | `{}` | {:.4} | {}/{} | `{}:{}-{}` | `{}` |",
                idx + 1,
                escape_table(&s.name),
                s.kind.as_str(),
                s.arch_layer.as_str(),
                rs.pagerank,
                rs.in_degree,
                rs.out_degree,
                s.file,
                s.start_line,
                s.end_line,
                escape_table(&s.signature)
            ));
        }
    }
    lines.push(String::new());

    // Core Domain Types & Data Structures (Issue #45)
    let top_types = select_core_domain_types(indexes);
    if !top_types.is_empty() {
        lines.push("## Core Domain Types & Data Structures".to_string());
        lines.push(String::new());
        lines.push("| Type | Kind | Layer | Refs | Location | Fields / Variants |".to_string());
        lines.push("| --- | --- | --- | ---: | --- | --- |".to_string());
        for (t, refs) in top_types.into_iter().take(12) {
            let fields = if t.fields_summary.is_empty() {
                "-".to_string()
            } else {
                escape_table(&t.fields_summary)
            };
            lines.push(format!(
                "| `{}` | `{}` | `{}` | {} | `{}:{}-{}` | `{}` |",
                escape_table(&t.name),
                t.kind.as_str(),
                t.arch_layer.as_str(),
                refs,
                t.file,
                t.start_line,
                t.end_line,
                fields
            ));
        }
        lines.push(String::new());
    }

    // Active Hardware / MMIO & Vendor SDK Surface
    lines.push("## Active Hardware / MMIO & Vendor SDK Surface".to_string());
    lines.push(String::new());
    let vs = &indexes.vendor_surface;
    lines.push(format!(
        "- **Vendor SDK Footprint**: {} vendor files, {} vendor symbols ({} actively referenced by first-party code)",
        vs.total_vendor_files,
        vs.total_vendor_symbols,
        vs.active_vendor_symbols.len()
    ));
    if !vs.active_mmio_registers.is_empty() {
        let mmio_list: Vec<String> = vs
            .active_mmio_registers
            .iter()
            .take(40)
            .map(|r| format!("`{r}`"))
            .collect();
        lines.push(format!(
            "- **Active MMIO Registers & Bitmasks ({})**: {}",
            vs.active_mmio_registers.len(),
            mmio_list.join(", ")
        ));
    } else {
        lines.push("- **Active MMIO Registers & Bitmasks**: none".to_string());
    }
    if !vs.active_vendor_symbols.is_empty() {
        let vsym_list: Vec<String> = vs
            .active_vendor_symbols
            .iter()
            .take(40)
            .map(|s| format!("`{s}`"))
            .collect();
        lines.push(format!(
            "- **Active Vendor SDK Symbols ({})**: {}",
            vs.active_vendor_symbols.len(),
            vsym_list.join(", ")
        ));
    }
    if !vs.active_vendor_headers.is_empty() {
        let vhdr_list: Vec<String> = vs
            .active_vendor_headers
            .iter()
            .take(25)
            .map(|h| format!("`{h}`"))
            .collect();
        lines.push(format!(
            "- **Active Vendor Headers ({})**: {}",
            vs.active_vendor_headers.len(),
            vhdr_list.join(", ")
        ));
    }
    lines.push(String::new());

    // Architectural Module Shards (sections/*.md)
    lines.push("## Architectural Module Shards (`sections/*.md`)".to_string());
    lines.push(String::new());
    lines.push(
        "| ID | Module Path | Layer | Scope | Files | Symbols | Types | Est. Tokens | File |"
            .to_string(),
    );
    lines.push("| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |".to_string());
    for sec in sections {
        let s = &sec.summary;
        let rel_link = if s.md_file.starts_with("sections/") {
            s.md_file.clone()
        } else {
            format!("sections/{}", s.md_file)
        };
        lines.push(format!(
            "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | ~{} | [{}]({}) |",
            s.section_id,
            escape_table(&s.module_path),
            s.arch_layer,
            s.scope,
            s.file_count,
            s.symbol_count,
            s.type_count,
            s.token_estimate,
            rel_link,
            rel_link
        ));
    }
    lines.push(String::new());

    lines.join("\n")
}

fn select_entrypoints(indexes: &BundleIndexes) -> Vec<&RankedSymbol> {
    if !indexes.entrypoints.is_empty() && indexes.entrypoints.iter().any(|r| r.is_entrypoint) {
        return indexes.entrypoints.iter().collect();
    }
    indexes.symbols.iter().filter(|r| r.is_entrypoint).collect()
}

fn select_god_nodes(indexes: &BundleIndexes) -> Vec<&RankedSymbol> {
    if !indexes.god_nodes.is_empty() && indexes.god_nodes.iter().any(|r| r.is_god_node) {
        return indexes.god_nodes.iter().collect();
    }
    let mut nodes: Vec<&RankedSymbol> = indexes.symbols.iter().filter(|r| r.is_god_node).collect();
    nodes.sort_by(|a, b| b.pagerank.total_cmp(&a.pagerank));
    nodes
}

fn select_core_domain_types(indexes: &BundleIndexes) -> Vec<(&ExtractedType, usize)> {
    if indexes.types.is_empty() {
        return Vec::new();
    }
    let has_first_party = indexes
        .types
        .iter()
        .any(|t| t.scope == FileScope::FirstParty);

    let mut ref_counts: FxHashMap<&str, usize> = FxHashMap::default();
    for t in &indexes.types {
        if has_first_party && t.scope != FileScope::FirstParty {
            continue;
        }
        ref_counts.entry(t.name.as_str()).or_insert(0);
    }

    for rs in &indexes.symbols {
        if let Some(et) = rs.symbol.enclosing_type.as_deref() {
            if let Some(cnt) = ref_counts.get_mut(et) {
                *cnt += 1;
            }
        }
        for tok in rs
            .symbol
            .signature
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty())
        {
            if let Some(cnt) = ref_counts.get_mut(tok) {
                *cnt += 1;
            }
        }
    }

    for t in &indexes.types {
        for tok in t
            .fields_summary
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty() && *s != t.name)
        {
            if let Some(cnt) = ref_counts.get_mut(tok) {
                *cnt += 1;
            }
        }
    }

    let mut ranked: Vec<(&ExtractedType, usize)> = indexes
        .types
        .iter()
        .filter(|t| !has_first_party || t.scope == FileScope::FirstParty)
        .map(|t| {
            let refs = ref_counts.get(t.name.as_str()).copied().unwrap_or(0);
            (t, refs)
        })
        .collect();

    ranked.sort_by(|(ta, ra), (tb, rb)| {
        rb.cmp(ra)
            .then_with(|| {
                tb.fields_summary
                    .is_empty()
                    .cmp(&ta.fields_summary.is_empty())
                    .reverse()
            })
            .then_with(|| ta.file.cmp(&tb.file))
            .then_with(|| ta.start_line.cmp(&tb.start_line))
    });
    ranked
}

fn escape_table(s: &str) -> String {
    sanitize_tsv(s).replace('|', "\\|")
}

fn create_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| ChipsrcError::io(path, source))
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if content.len() <= 256 * 1024 {
        if let Ok(existing) = fs::read(path) {
            if existing == content.as_bytes() {
                return Ok(());
            }
        }
    }
    fs::write(path, content.as_bytes()).map_err(|source| ChipsrcError::io(path, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("chipsrc_emitter_{label}_{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_sanitize_tsv_strips_tabs_and_newlines() {
        let raw = "fn foo(\n\tint a,\r\n\tint   b\n) -> i32";
        assert_eq!(sanitize_tsv(raw), "fn foo( int a, int b ) -> i32");
    }

    #[test]
    fn test_ensure_claudeignore_entry_idempotent_and_scoped_to_repo() {
        let tmp = TestTempDir::new("claudeignore");
        let out_dir = tmp.0.join("output").join("demo_repo");
        fs::create_dir_all(&out_dir).expect("create out_dir");

        let first = ensure_claudeignore_entry(&tmp.0, &out_dir).expect("first ensure");
        assert!(first);

        let claudeignore = fs::read_to_string(tmp.0.join(".claudeignore")).expect("read ignore");
        assert!(claudeignore.contains("# chipsrc generated bundles"));
        assert!(claudeignore.contains("output/"));

        let second = ensure_claudeignore_entry(&tmp.0, &out_dir).expect("second ensure");
        assert!(!second);

        // Out-of-tree output directory must NOT write `.claudeignore`
        let external = TestTempDir::new("external_out");
        let ext_out = external.0.join("qa_bundles").join("demo");
        fs::create_dir_all(&ext_out).expect("create ext_out");
        let ext_updated = ensure_claudeignore_entry(&tmp.0, &ext_out).expect("external ensure");
        assert!(!ext_updated);
        assert!(!external.0.join(".claudeignore").exists());
    }
}
