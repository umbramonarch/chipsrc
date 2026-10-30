use crate::error::{ChipsrcError, Result};
use crate::mmio::normalize_hex_literal;
use crate::model::{
    BundleMetaFile, BundleStatusEntry, IncrementalAstCache, LanguageKind, SearchHit,
};
use crate::scanner::{check_files_changed, scan_repository};
use memchr::memmem;
use rayon::prelude::*;
use regex::RegexBuilder;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

/// Resolves `target` into one or more indexed bundle directories (containing `meta.json` and `INDEX.md`).
pub fn resolve_bundles(target: &Path) -> Result<Vec<PathBuf>> {
    if is_valid_bundle_dir(target) {
        return Ok(vec![target.to_path_buf()]);
    }

    let output_candidate = Path::new("output").join(target);
    if is_valid_bundle_dir(&output_candidate) {
        return Ok(vec![output_candidate]);
    }

    if let Some(stem) = target.file_name().and_then(|s| s.to_str()) {
        let stem_candidate = Path::new("output").join(stem);
        if is_valid_bundle_dir(&stem_candidate) {
            return Ok(vec![stem_candidate]);
        }
        let nested_candidate = target.join("output").join(stem);
        if is_valid_bundle_dir(&nested_candidate) {
            return Ok(vec![nested_candidate]);
        }
    }

    let mut search_roots = Vec::new();
    if target.is_dir() {
        let norm_target = normalize_bundle_path(target);
        search_roots.push(norm_target);
        let sub_out = normalize_bundle_path(&target.join("output"));
        if sub_out.is_dir() && !search_roots.contains(&sub_out) {
            search_roots.push(sub_out);
        }
    }

    let mut bundles = Vec::new();
    for root in search_roots {
        let norm_root = normalize_bundle_path(&root);
        if is_valid_bundle_dir(&norm_root) && !bundles.contains(&norm_root) {
            bundles.push(norm_root);
        }
        if let Ok(entries) = fs::read_dir(&root) {
            for entry in entries.flatten() {
                let p = normalize_bundle_path(&entry.path());
                if is_valid_bundle_dir(&p) && !bundles.contains(&p) {
                    bundles.push(p);
                }
            }
        }
    }

    bundles.sort();
    if bundles.is_empty() {
        return Err(ChipsrcError::BundleNotFound(target.to_path_buf()));
    }
    Ok(bundles)
}

fn normalize_bundle_path(p: &Path) -> PathBuf {
    if p == Path::new(".") {
        return PathBuf::from(".");
    }
    p.strip_prefix(".").unwrap_or(p).to_path_buf()
}

/// Resolves positional CLI `<target_or_query>` and optional `<query>` into `(bundles, query_string)`.
pub fn resolve_target_and_query(
    target_or_query: &str,
    query: Option<&str>,
) -> Result<(Vec<PathBuf>, String)> {
    if let Some(q) = query {
        let bundles = resolve_bundles(Path::new(target_or_query))?;
        return Ok((bundles, q.to_string()));
    }

    let p = Path::new(target_or_query);
    if !target_or_query.is_empty() && p.is_dir() && is_valid_bundle_dir(p) {
        return Ok((vec![p.to_path_buf()], String::new()));
    }

    let bundles = resolve_bundles(Path::new("."))?;
    Ok((bundles, target_or_query.to_string()))
}

/// Scans `workspace` (and `workspace/output`) for indexed bundles and checks live freshness against source files.
pub fn workspace_status(workspace: &Path) -> Result<Vec<BundleStatusEntry>> {
    let bundles = match resolve_bundles(workspace) {
        Ok(b) => b,
        Err(ChipsrcError::BundleNotFound(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut entries = Vec::with_capacity(bundles.len());
    for bundle_dir in bundles {
        let Some(meta_file) = load_meta_file(&bundle_dir) else {
            continue;
        };
        let meta = meta_file.metadata;
        let bundle_name = if !meta.repo_name.is_empty() {
            meta.repo_name.clone()
        } else {
            bundle_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("bundle")
                .to_string()
        };

        let source_path = Path::new(&meta.source_root);
        let changed_files_count = if source_path.is_dir() {
            if let Some(cache) = load_cache_file(&bundle_dir) {
                check_files_changed(source_path, &cache, 4 * 1024 * 1024).unwrap_or(0)
            } else if let Ok((_, live_fp)) =
                scan_repository(source_path, meta.vendor_mode, 4 * 1024 * 1024)
            {
                usize::from(live_fp != meta.fingerprint)
            } else {
                0
            }
        } else {
            0
        };

        entries.push(BundleStatusEntry {
            bundle_name,
            bundle_dir,
            source_root: meta.source_root,
            is_fresh: changed_files_count == 0,
            changed_files_count,
            symbol_count: meta.symbol_count,
            section_count: meta.section_count,
        });
    }

    entries.sort_by(|a, b| a.bundle_name.cmp(&b.bundle_name));
    Ok(entries)
}

/// Queries functions, methods, constructors, entrypoints, and ISRs across bundles (`index/symbols.tsv`).
pub fn query_symbols(
    bundles: &[PathBuf],
    query: &str,
    kind_filter: Option<&str>,
    show_source: bool,
    limit: usize,
) -> Result<String> {
    let q_trim = query.trim();
    let q_lower = q_trim.to_ascii_lowercase();
    let kind_lower = kind_filter.map(|k| k.trim().to_ascii_lowercase());

    #[derive(Clone)]
    struct SymHit {
        bundle_dir: PathBuf,
        bundle_name: String,
        symbol_id: String,
        name: String,
        kind: String,
        vis: String,
        file: String,
        start_line: usize,
        end_line: usize,
        signature: String,
        pagerank: f64,
        in_deg: usize,
        out_deg: usize,
        arch_layer: String,
        scope: String,
        section_id: String,
        score: u8,
    }

    let mut hits: Vec<SymHit> = Vec::new();

    for bundle_dir in bundles {
        let sym_tsv = bundle_dir.join("index").join("symbols.tsv");
        let Ok(content) = fs::read_to_string(&sym_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 14 {
                continue;
            }
            let symbol_id = cols[0];
            let name = cols[1];
            let kind = cols[2];

            if let Some(ref kf) = kind_lower {
                if !kind.eq_ignore_ascii_case(kf) && !kind.to_ascii_lowercase().starts_with(kf) {
                    continue;
                }
            }

            let name_lower = name.to_ascii_lowercase();
            let id_lower = symbol_id.to_ascii_lowercase();
            let sig_lower = cols[7].to_ascii_lowercase();

            let score = if q_lower.is_empty() {
                1
            } else if name == q_trim || symbol_id == q_trim {
                5
            } else if name_lower == q_lower || id_lower == q_lower {
                4
            } else if id_lower.ends_with(&format!("::{q_lower}"))
                || name_lower.starts_with(&q_lower)
            {
                3
            } else if name_lower.contains(&q_lower)
                || id_lower.contains(&q_lower)
                || sig_lower.contains(&q_lower)
            {
                2
            } else {
                0
            };

            if score == 0 {
                continue;
            }

            hits.push(SymHit {
                bundle_dir: bundle_dir.clone(),
                bundle_name: bundle_name.clone(),
                symbol_id: symbol_id.to_string(),
                name: name.to_string(),
                kind: kind.to_string(),
                vis: cols[3].to_string(),
                file: cols[4].to_string(),
                start_line: cols[5].parse().unwrap_or(1),
                end_line: cols[6].parse().unwrap_or(1),
                signature: cols[7].to_string(),
                pagerank: cols[8].parse().unwrap_or(0.0),
                in_deg: cols[9].parse().unwrap_or(0),
                out_deg: cols[10].parse().unwrap_or(0),
                arch_layer: cols[11].to_string(),
                scope: cols[12].to_string(),
                section_id: cols[13].to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!(
            "No symbols matched '{query}'. Try `chipsrc search \"{query}\"`.\n"
        ));
    }

    if hits.iter().any(|h| h.score >= 4) {
        hits.retain(|h| h.score >= 3);
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.pagerank.total_cmp(&a.pagerank))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.start_line.cmp(&b.start_line))
    });

    let total = hits.len();
    let mut out = String::new();
    for h in hits.into_iter().take(limit) {
        out.push_str(&format!(
            "[{}] {} `{}` ({}) | `{}:{}-{}` | layer={} scope={} shard=`{}` | PR={:.4} in={} out={}\n  sig: `{}`\n  id : `{}`\n",
            h.bundle_name,
            h.vis,
            h.name,
            h.kind,
            h.file,
            h.start_line,
            h.end_line,
            h.arch_layer,
            h.scope,
            h.section_id,
            h.pagerank,
            h.in_deg,
            h.out_deg,
            h.signature,
            h.symbol_id
        ));

        if show_source {
            if let Some(snippet) =
                read_source_snippet(&h.bundle_dir, &h.file, h.start_line, h.end_line)
            {
                out.push_str(&snippet);
            }
        }
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more symbol matches omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

/// Queries all static callers of `symbol` across bundles (`index/calls.tsv`).
pub fn query_callers(
    bundles: &[PathBuf],
    symbol: &str,
    show_source: bool,
    limit: usize,
) -> Result<String> {
    let q_trim = symbol.trim();
    let q_lower = q_trim.to_ascii_lowercase();

    struct CallerHit {
        bundle_dir: PathBuf,
        bundle_name: String,
        caller_id: String,
        caller_name: String,
        callee_name: String,
        callee_id: String,
        file: String,
        line: usize,
        tier: String,
        section_id: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let calls_tsv = bundle_dir.join("index").join("calls.tsv");
        let Ok(content) = fs::read_to_string(&calls_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 8 {
                continue;
            }
            let callee_name = cols[2];
            let callee_id = cols[3];
            let callee_lower = callee_name.to_ascii_lowercase();
            let id_lower = callee_id.to_ascii_lowercase();

            let score = if callee_name == q_trim || callee_id == q_trim {
                4
            } else if callee_lower == q_lower
                || id_lower == q_lower
                || id_lower.ends_with(&format!("::{q_lower}"))
            {
                3
            } else if callee_lower.contains(&q_lower) || id_lower.contains(&q_lower) {
                2
            } else {
                0
            };

            if score == 0 {
                continue;
            }

            hits.push(CallerHit {
                bundle_dir: bundle_dir.clone(),
                bundle_name: bundle_name.clone(),
                caller_id: cols[0].to_string(),
                caller_name: cols[1].to_string(),
                callee_name: callee_name.to_string(),
                callee_id: callee_id.to_string(),
                file: cols[4].to_string(),
                line: cols[5].parse().unwrap_or(1),
                tier: cols[6].to_string(),
                section_id: cols[7].to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!("No callers found for '{symbol}'.\n"));
    }

    if hits.iter().any(|h| h.score >= 3) {
        hits.retain(|h| h.score >= 3);
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let total = hits.len();
    let mut out = format!(
        "=== Callers of '{}' ({} call sites) ===\n",
        symbol,
        hits.len()
    );
    for h in hits.into_iter().take(limit) {
        out.push_str(&format!(
            "  [{}] `{}` (`{}`) -> `{}` (`{}`) at `{}:{}` [tier={}, shard=`{}`]\n",
            h.bundle_name,
            h.caller_name,
            h.caller_id,
            h.callee_name,
            h.callee_id,
            h.file,
            h.line,
            h.tier,
            h.section_id
        ));

        if show_source {
            let start = h.line.saturating_sub(2).max(1);
            let end = h.line + 4;
            if let Some(snippet) = read_source_snippet(&h.bundle_dir, &h.file, start, end) {
                out.push_str(&snippet);
            }
        }
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more callers omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

/// Queries all static callees invoked by `symbol` across bundles (`index/calls.tsv`).
pub fn query_callees(
    bundles: &[PathBuf],
    symbol: &str,
    show_source: bool,
    limit: usize,
) -> Result<String> {
    let q_trim = symbol.trim();
    let q_lower = q_trim.to_ascii_lowercase();

    struct CalleeHit {
        bundle_dir: PathBuf,
        bundle_name: String,
        caller_id: String,
        caller_name: String,
        callee_name: String,
        callee_id: String,
        file: String,
        line: usize,
        tier: String,
        section_id: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let calls_tsv = bundle_dir.join("index").join("calls.tsv");
        let Ok(content) = fs::read_to_string(&calls_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 8 {
                continue;
            }
            let caller_id = cols[0];
            let caller_name = cols[1];
            let caller_lower = caller_name.to_ascii_lowercase();
            let id_lower = caller_id.to_ascii_lowercase();

            let score = if caller_name == q_trim || caller_id == q_trim {
                4
            } else if caller_lower == q_lower
                || id_lower == q_lower
                || id_lower.ends_with(&format!("::{q_lower}"))
            {
                3
            } else if caller_lower.contains(&q_lower) || id_lower.contains(&q_lower) {
                2
            } else {
                0
            };

            if score == 0 {
                continue;
            }

            hits.push(CalleeHit {
                bundle_dir: bundle_dir.clone(),
                bundle_name: bundle_name.clone(),
                caller_id: caller_id.to_string(),
                caller_name: caller_name.to_string(),
                callee_name: cols[2].to_string(),
                callee_id: cols[3].to_string(),
                file: cols[4].to_string(),
                line: cols[5].parse().unwrap_or(1),
                tier: cols[6].to_string(),
                section_id: cols[7].to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!("No callees found for '{symbol}'.\n"));
    }

    if hits.iter().any(|h| h.score >= 3) {
        hits.retain(|h| h.score >= 3);
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let total = hits.len();
    let mut out = format!(
        "=== Callees invoked by '{}' ({} call sites) ===\n",
        symbol,
        hits.len()
    );
    for h in hits.into_iter().take(limit) {
        out.push_str(&format!(
            "  [{}] `{}` (`{}`) -> `{}` (`{}`) at `{}:{}` [tier={}, shard=`{}`]\n",
            h.bundle_name,
            h.caller_name,
            h.caller_id,
            h.callee_name,
            h.callee_id,
            h.file,
            h.line,
            h.tier,
            h.section_id
        ));

        if show_source {
            let start = h.line.saturating_sub(2).max(1);
            let end = h.line + 4;
            if let Some(snippet) = read_source_snippet(&h.bundle_dir, &h.file, start, end) {
                out.push_str(&snippet);
            }
        }
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more callees omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

/// Queries structs, enums, unions, traits, interfaces, classes, and typedefs (`index/types.tsv`).
pub fn query_types(
    bundles: &[PathBuf],
    query: &str,
    show_source: bool,
    limit: usize,
) -> Result<String> {
    let q_trim = query.trim();
    let q_lower = q_trim.to_ascii_lowercase();

    struct TypeHit {
        bundle_dir: PathBuf,
        bundle_name: String,
        type_id: String,
        name: String,
        kind: String,
        vis: String,
        file: String,
        start_line: usize,
        end_line: usize,
        fields_summary: String,
        arch_layer: String,
        scope: String,
        section_id: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let typ_tsv = bundle_dir.join("index").join("types.tsv");
        let Ok(content) = fs::read_to_string(&typ_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 11 {
                continue;
            }
            let type_id = cols[0];
            let name = cols[1];
            let fields = cols[7];

            let name_lower = name.to_ascii_lowercase();
            let id_lower = type_id.to_ascii_lowercase();
            let fields_lower = fields.to_ascii_lowercase();

            let score = if q_lower.is_empty() {
                1
            } else if name == q_trim || type_id == q_trim {
                5
            } else if name_lower == q_lower || id_lower == q_lower {
                4
            } else if name_lower.starts_with(&q_lower) {
                3
            } else if name_lower.contains(&q_lower)
                || id_lower.contains(&q_lower)
                || fields_lower.contains(&q_lower)
            {
                2
            } else {
                0
            };

            if score == 0 {
                continue;
            }

            hits.push(TypeHit {
                bundle_dir: bundle_dir.clone(),
                bundle_name: bundle_name.clone(),
                type_id: type_id.to_string(),
                name: name.to_string(),
                kind: cols[2].to_string(),
                vis: cols[3].to_string(),
                file: cols[4].to_string(),
                start_line: cols[5].parse().unwrap_or(1),
                end_line: cols[6].parse().unwrap_or(1),
                fields_summary: fields.to_string(),
                arch_layer: cols[8].to_string(),
                scope: cols[9].to_string(),
                section_id: cols[10].to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!(
            "No types matched '{query}'. Try `chipsrc search \"{query}\"`.\n"
        ));
    }

    if hits.iter().any(|h| h.score >= 4) {
        hits.retain(|h| h.score >= 3);
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.start_line.cmp(&b.start_line))
    });

    let total = hits.len();
    let mut out = String::new();
    for h in hits.into_iter().take(limit) {
        out.push_str(&format!(
            "[{}] {} {} `{}` | `{}:{}-{}` | layer={} scope={} shard=`{}`\n  fields: {}\n  id    : `{}`\n",
            h.bundle_name,
            h.vis,
            h.kind,
            h.name,
            h.file,
            h.start_line,
            h.end_line,
            h.arch_layer,
            h.scope,
            h.section_id,
            if h.fields_summary.is_empty() {
                "-"
            } else {
                &h.fields_summary
            },
            h.type_id
        ));

        if show_source {
            if let Some(snippet) =
                read_source_snippet(&h.bundle_dir, &h.file, h.start_line, h.end_line)
            {
                out.push_str(&snippet);
            }
        }
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more type matches omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

/// Queries `#define` macros, constants, bitmasks, and MMIO register accesses (`index/macros.tsv`),
/// normalizing hex literals (`0x400` <-> `400h`) and peripheral separators (`PERIPH_REG` <-> `PERIPH->REG` <-> `PERIPH.REG`).
pub fn query_macros(
    bundles: &[PathBuf],
    query: &str,
    show_source: bool,
    limit: usize,
) -> Result<String> {
    let q_trim = query.trim();
    let q_hex = normalize_hex_literal(q_trim);

    struct MacroHit {
        bundle_dir: PathBuf,
        bundle_name: String,
        name: String,
        kind: String,
        value: String,
        hex_addr: String,
        file: String,
        line: usize,
        arch_layer: String,
        scope: String,
        section_id: String,
        description: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let mac_tsv = bundle_dir.join("index").join("macros.tsv");
        let Ok(content) = fs::read_to_string(&mac_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 10 {
                continue;
            }
            let name = cols[0];
            let kind = cols[1];
            let val = cols[2];
            let hex_col = cols[3];
            let desc = cols[9];

            let row_hex = if hex_col != "-" && !hex_col.is_empty() {
                normalize_hex_literal(hex_col)
            } else {
                normalize_hex_literal(val)
            };

            let hex_exact = match (&q_hex, &row_hex) {
                (Some(qh), Some(rh)) => qh.eq_ignore_ascii_case(rh),
                _ => false,
            };

            let id_score = score_hw_identifier_match(name, q_trim);
            let val_score = if val
                .to_ascii_lowercase()
                .contains(&q_trim.to_ascii_lowercase())
                || desc
                    .to_ascii_lowercase()
                    .contains(&q_trim.to_ascii_lowercase())
            {
                1
            } else {
                0
            };

            let score = if hex_exact {
                5
            } else {
                id_score.max(val_score)
            };

            if score == 0 {
                continue;
            }

            hits.push(MacroHit {
                bundle_dir: bundle_dir.clone(),
                bundle_name: bundle_name.clone(),
                name: name.to_string(),
                kind: kind.to_string(),
                value: val.to_string(),
                hex_addr: hex_col.to_string(),
                file: cols[4].to_string(),
                line: cols[5].parse().unwrap_or(1),
                arch_layer: cols[6].to_string(),
                scope: cols[7].to_string(),
                section_id: cols[8].to_string(),
                description: desc.to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!(
            "No macros or MMIO registers matched '{query}'. Try `chipsrc xref \"{query}\"` or `chipsrc search \"{query}\"`.\n"
        ));
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let total = hits.len();
    let mut out = String::new();
    for h in hits.into_iter().take(limit) {
        let hex_info = if h.hex_addr != "-" && !h.hex_addr.is_empty() {
            format!(" [hex={}]", h.hex_addr)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "[{}] `{}` ({}){} = `{}` | `{}:{}` | layer={} scope={} shard=`{}` ({})\n",
            h.bundle_name,
            h.name,
            h.kind,
            hex_info,
            h.value,
            h.file,
            h.line,
            h.arch_layer,
            h.scope,
            h.section_id,
            h.description
        ));

        if show_source {
            let start = h.line.saturating_sub(2).max(1);
            let end = h.line + 4;
            if let Some(snippet) = read_source_snippet(&h.bundle_dir, &h.file, start, end) {
                out.push_str(&snippet);
            }
        }
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more macro/MMIO matches omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

/// Lists or inspects architectural module shards (`index/sections.tsv` and `sections/*.md`).
pub fn query_sections(
    bundles: &[PathBuf],
    query: &str,
    show_markdown: bool,
    limit: usize,
) -> Result<String> {
    let q_trim = query.trim();
    let q_lower = q_trim.to_ascii_lowercase();

    struct SecHit {
        bundle_dir: PathBuf,
        bundle_name: String,
        section_id: String,
        title: String,
        module_path: String,
        arch_layer: String,
        scope: String,
        file_count: usize,
        symbol_count: usize,
        type_count: usize,
        macro_count: usize,
        token_estimate: usize,
        md_file: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let sec_tsv = bundle_dir.join("index").join("sections.tsv");
        let Ok(content) = fs::read_to_string(&sec_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 11 {
                continue;
            }
            let section_id = cols[0];
            let title = cols[1];
            let module_path = cols[2];
            let arch_layer = cols[3];
            let scope = cols[4];

            let sec_lower = section_id.to_ascii_lowercase();
            let mod_lower = module_path.to_ascii_lowercase();
            let title_lower = title.to_ascii_lowercase();
            let layer_lower = arch_layer.to_ascii_lowercase();

            let score = if q_lower.is_empty() {
                1
            } else if sec_lower == q_lower || mod_lower == q_lower || layer_lower == q_lower {
                4
            } else if sec_lower.ends_with(&format!("-{q_lower}"))
                || sec_lower.starts_with(&q_lower)
                || mod_lower.contains(&q_lower)
            {
                3
            } else if title_lower.contains(&q_lower)
                || scope.to_ascii_lowercase().contains(&q_lower)
            {
                2
            } else {
                0
            };

            if score == 0 {
                continue;
            }

            hits.push(SecHit {
                bundle_dir: bundle_dir.clone(),
                bundle_name: bundle_name.clone(),
                section_id: section_id.to_string(),
                title: title.to_string(),
                module_path: module_path.to_string(),
                arch_layer: arch_layer.to_string(),
                scope: scope.to_string(),
                file_count: cols[5].parse().unwrap_or(0),
                symbol_count: cols[6].parse().unwrap_or(0),
                type_count: cols[7].parse().unwrap_or(0),
                macro_count: cols[8].parse().unwrap_or(0),
                token_estimate: cols[9].parse().unwrap_or(0),
                md_file: cols[10].to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!(
            "No module sections matched '{query}'. Run `chipsrc section \"\"` to list all shards.\n"
        ));
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.section_id.cmp(&b.section_id))
    });

    let mut out = String::new();
    for h in hits.into_iter().take(limit) {
        let rel_md = if h.md_file.starts_with("sections/") {
            h.md_file.clone()
        } else {
            format!("sections/{}", h.md_file)
        };
        out.push_str(&format!(
            "[{}] `{}` — {} | path=`{}` layer={} scope={} | {} files, {} syms, {} types, {} macros (~{} tokens) | `{}`\n",
            h.bundle_name,
            h.section_id,
            h.title,
            h.module_path,
            h.arch_layer,
            h.scope,
            h.file_count,
            h.symbol_count,
            h.type_count,
            h.macro_count,
            h.token_estimate,
            rel_md
        ));

        if show_markdown {
            let md_path = h.bundle_dir.join(&rel_md);
            if let Ok(md_body) = fs::read_to_string(&md_path) {
                out.push_str("---\n");
                out.push_str(&md_body);
                if !md_body.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("---\n");
            }
        }
    }

    Ok(out)
}

/// Queries the Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`),
/// normalizing hex literals (`0x400` <-> `400h`) and peripheral separators (`PERIPH_REG` <-> `PERIPH->REG` <-> `PERIPH.REG`).
pub fn query_xref(bundles: &[PathBuf], query: &str, limit: usize) -> Result<String> {
    let q_trim = query.trim();
    let q_hex = normalize_hex_literal(q_trim);

    struct XrefHit {
        bundle_name: String,
        symbol: String,
        category: String,
        relation: String,
        target: String,
        file: String,
        line: usize,
        section_id: String,
        context: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let xref_tsv = bundle_dir.join("index").join("xref.tsv");
        let Ok(content) = fs::read_to_string(&xref_tsv) else {
            continue;
        };
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 8 {
                continue;
            }
            let sym = cols[0];
            let category = cols[1];
            let relation = cols[2];
            let target = cols[3];
            let file = cols[4];
            let line_num: usize = cols[5].parse().unwrap_or(1);
            let section_id = cols[6];
            let context = cols[7];

            let hex_match = match &q_hex {
                Some(qh) => {
                    normalize_hex_literal(sym).is_some_and(|sh| sh.eq_ignore_ascii_case(qh))
                        || normalize_hex_literal(target)
                            .is_some_and(|th| th.eq_ignore_ascii_case(qh))
                        || normalize_hex_literal(context)
                            .is_some_and(|ch| ch.eq_ignore_ascii_case(qh))
                }
                None => false,
            };

            let sym_score = score_hw_identifier_match(sym, q_trim);
            let target_score = score_hw_identifier_match(target, q_trim);
            let ctx_score = if context
                .to_ascii_lowercase()
                .contains(&q_trim.to_ascii_lowercase())
            {
                1
            } else {
                0
            };

            let score = if hex_match {
                5
            } else {
                sym_score.max(target_score).max(ctx_score)
            };

            if score == 0 {
                continue;
            }

            hits.push(XrefHit {
                bundle_name: bundle_name.clone(),
                symbol: sym.to_string(),
                category: category.to_string(),
                relation: relation.to_string(),
                target: target.to_string(),
                file: file.to_string(),
                line: line_num,
                section_id: section_id.to_string(),
                context: context.to_string(),
                score,
            });
        }
    }

    if hits.is_empty() {
        return Ok(format!(
            "No cross-reference graph connections found for '{query}'.\n"
        ));
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let total = hits.len();
    let mut out = format!(
        "=== Cross-Reference Graph for '{}' ({} connections) ===\n",
        query, total
    );
    for h in hits.into_iter().take(limit) {
        out.push_str(&format!(
            "  [{} | {:<10} | {}] `{}` -> `{}` at `{}:{}` (shard=`{}`) | {}\n",
            h.bundle_name,
            h.category,
            h.relation,
            h.symbol,
            h.target,
            h.file,
            h.line,
            h.section_id,
            h.context
        ));
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more cross-references omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

#[derive(Clone, Debug)]
struct GraphSymMeta {
    symbol_id: String,
    name: String,
    kind: String,
    file: String,
    start_line: usize,
    arch_layer: String,
    scope: String,
    section_id: String,
}

#[derive(Clone, Debug)]
struct GraphCallEdge {
    caller_id: String,
    caller_name: String,
    callee_name: String,
    callee_id: String,
    file: String,
    line: usize,
    tier: String,
    section_id: String,
}

fn load_bundle_call_graph(
    bundle_dir: &Path,
) -> (FxHashMap<String, GraphSymMeta>, Vec<GraphCallEdge>) {
    let mut syms: FxHashMap<String, GraphSymMeta> = FxHashMap::default();
    let syms_tsv = bundle_dir.join("index").join("symbols.tsv");
    if let Ok(content) = fs::read_to_string(&syms_tsv) {
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 14 {
                continue;
            }
            let symbol_id = cols[0].to_string();
            syms.insert(
                symbol_id.clone(),
                GraphSymMeta {
                    symbol_id,
                    name: cols[1].to_string(),
                    kind: cols[2].to_string(),
                    file: cols[4].to_string(),
                    start_line: cols[5].parse().unwrap_or(1),
                    arch_layer: cols[11].to_string(),
                    scope: cols[12].to_string(),
                    section_id: cols[13].to_string(),
                },
            );
        }
    }

    let mut edges: Vec<GraphCallEdge> = Vec::new();
    let calls_tsv = bundle_dir.join("index").join("calls.tsv");
    if let Ok(content) = fs::read_to_string(&calls_tsv) {
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 8 {
                continue;
            }
            let caller_id = cols[0].to_string();
            let caller_name = cols[1].to_string();
            let callee_name = cols[2].to_string();
            let callee_id = cols[3].to_string();
            let file = cols[4].to_string();
            let call_line: usize = cols[5].parse().unwrap_or(1);
            let tier = cols[6].to_string();
            let section_id = cols[7].to_string();

            syms.entry(caller_id.clone())
                .or_insert_with(|| GraphSymMeta {
                    symbol_id: caller_id.clone(),
                    name: caller_name.clone(),
                    kind: "fn".to_string(),
                    file: file.clone(),
                    start_line: call_line,
                    arch_layer: "other".to_string(),
                    scope: "first_party".to_string(),
                    section_id: section_id.clone(),
                });

            syms.entry(callee_id.clone())
                .or_insert_with(|| GraphSymMeta {
                    symbol_id: callee_id.clone(),
                    name: callee_name.clone(),
                    kind: "fn".to_string(),
                    file: file.clone(),
                    start_line: call_line,
                    arch_layer: "other".to_string(),
                    scope: "first_party".to_string(),
                    section_id: section_id.clone(),
                });

            edges.push(GraphCallEdge {
                caller_id,
                caller_name,
                callee_name,
                callee_id,
                file,
                line: call_line,
                tier,
                section_id,
            });
        }
    }

    (syms, edges)
}

fn match_symbol_ids_for_query(syms: &FxHashMap<String, GraphSymMeta>, query: &str) -> Vec<String> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return Vec::new();
    }
    let q_lower = q_trim.to_ascii_lowercase();
    let suffix = format!("::{q_lower}");

    let mut scored: Vec<(u8, String)> = Vec::new();
    for (id, meta) in syms {
        let name_lower = meta.name.to_ascii_lowercase();
        let id_lower = id.to_ascii_lowercase();
        let score = if meta.name == q_trim || id == q_trim {
            4
        } else if name_lower == q_lower || id_lower == q_lower || id_lower.ends_with(&suffix) {
            3
        } else if name_lower.contains(&q_lower) || id_lower.contains(&q_lower) {
            2
        } else {
            0
        };
        if score > 0 {
            scored.push((score, id.clone()));
        }
    }

    let Some(max_score) = scored.iter().map(|(s, _)| *s).max() else {
        return Vec::new();
    };
    let min_keep = if max_score >= 3 { 3 } else { max_score };
    let mut ids: Vec<String> = scored
        .into_iter()
        .filter(|(s, _)| *s >= min_keep)
        .map(|(_, id)| id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Computes the shortest static call path (`from_query` -> ... -> `to_query`) across indexed
/// bundles using Breadth-First Search (BFS) over `index/calls.tsv` and `index/symbols.tsv`.
pub fn query_call_path(
    bundles: &[PathBuf],
    from_query: &str,
    to_query: &str,
    max_depth: usize,
) -> Result<String> {
    let max_hops = max_depth.max(1);

    for bundle_dir in bundles {
        let (syms, edges) = load_bundle_call_graph(bundle_dir);
        if syms.is_empty() {
            continue;
        }
        let start_ids = match_symbol_ids_for_query(&syms, from_query);
        let target_ids: FxHashSet<String> = match_symbol_ids_for_query(&syms, to_query)
            .into_iter()
            .collect();

        if start_ids.is_empty() || target_ids.is_empty() {
            continue;
        }

        let mut adj: FxHashMap<&str, Vec<&GraphCallEdge>> = FxHashMap::default();
        for edge in &edges {
            adj.entry(edge.caller_id.as_str()).or_default().push(edge);
        }

        let mut visited: FxHashSet<String> = FxHashSet::default();
        let mut parent_map: FxHashMap<String, (String, GraphCallEdge)> = FxHashMap::default();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();

        for sid in &start_ids {
            if target_ids.contains(sid) {
                let meta = &syms[sid];
                let bundle_name = bundle_name_from_dir(bundle_dir);
                return Ok(format!(
                    "=== Shortest Call Path: '{}' -> '{}' (0 hops in [{}]) ===\n  [0] `{}` (`{}`) ({}) at `{}:{}` [layer={}, shard=`{}`]\n",
                    from_query,
                    to_query,
                    bundle_name,
                    meta.name,
                    meta.symbol_id,
                    meta.kind,
                    meta.file,
                    meta.start_line,
                    meta.arch_layer,
                    meta.section_id
                ));
            }
            visited.insert(sid.clone());
            queue.push_back((sid.clone(), 0));
        }

        let mut reached_target: Option<String> = None;

        'bfs: while let Some((curr_id, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }
            let Some(out_edges) = adj.get(curr_id.as_str()) else {
                continue;
            };
            for &edge in out_edges {
                let next_id = &edge.callee_id;
                if visited.insert(next_id.clone()) {
                    parent_map.insert(next_id.clone(), (curr_id.clone(), edge.clone()));
                    if target_ids.contains(next_id) {
                        reached_target = Some(next_id.clone());
                        break 'bfs;
                    }
                    queue.push_back((next_id.clone(), depth + 1));
                }
            }
        }

        if let Some(target_id) = reached_target {
            let mut hops: Vec<(String, GraphCallEdge)> = Vec::new();
            let mut cursor = target_id.clone();
            while let Some((prev_id, edge)) = parent_map.get(&cursor) {
                hops.push((cursor.clone(), edge.clone()));
                cursor = prev_id.clone();
            }
            hops.reverse();

            let bundle_name = bundle_name_from_dir(bundle_dir);
            let start_meta = &syms[&cursor];
            let mut out = format!(
                "=== Shortest Call Path: '{}' -> '{}' ({} hop{} in [{}]) ===\n",
                from_query,
                to_query,
                hops.len(),
                if hops.len() == 1 { "" } else { "s" },
                bundle_name
            );
            out.push_str(&format!(
                "  [0] `{}` (`{}`) ({}) at `{}:{}` [layer={}, shard=`{}`]\n",
                start_meta.name,
                start_meta.symbol_id,
                start_meta.kind,
                start_meta.file,
                start_meta.start_line,
                start_meta.arch_layer,
                start_meta.section_id
            ));

            for (idx, (node_id, edge)) in hops.iter().enumerate() {
                let meta = syms.get(node_id);
                let kind = meta.map(|m| m.kind.as_str()).unwrap_or("fn");
                let layer = meta.map(|m| m.arch_layer.as_str()).unwrap_or("other");
                out.push_str(&format!(
                    "  -> [{}] `{}` (`{}`) ({}) via `{}:{}` [tier={}, layer={}, shard=`{}`]\n",
                    idx + 1,
                    edge.callee_name,
                    edge.callee_id,
                    kind,
                    edge.file,
                    edge.line,
                    edge.tier,
                    layer,
                    edge.section_id
                ));
            }
            return Ok(out);
        }
    }

    Ok(format!(
        "No call path found from '{from_query}' to '{to_query}' within max depth {max_hops}.\n"
    ))
}

/// Computes the reverse-BFS blast radius (`callee` <- `caller` <- ...) of modifying `symbol_query`,
/// grouping transitive callers by hop distance and highlighting reached entrypoints, ISRs, and tests.
pub fn query_impact(
    bundles: &[PathBuf],
    symbol_query: &str,
    max_depth: usize,
    limit: usize,
) -> Result<String> {
    let max_hops = max_depth.max(1);
    let mut out = String::new();
    let mut any_seed_found = false;

    for bundle_dir in bundles {
        let (syms, edges) = load_bundle_call_graph(bundle_dir);
        if syms.is_empty() {
            continue;
        }
        let seed_ids = match_symbol_ids_for_query(&syms, symbol_query);
        if seed_ids.is_empty() {
            continue;
        }
        any_seed_found = true;

        let mut rev_adj: FxHashMap<&str, Vec<&GraphCallEdge>> = FxHashMap::default();
        for edge in &edges {
            rev_adj
                .entry(edge.callee_id.as_str())
                .or_default()
                .push(edge);
        }

        let mut visited: FxHashSet<String> = FxHashSet::default();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        for sid in &seed_ids {
            visited.insert(sid.clone());
            queue.push_back((sid.clone(), 0));
        }

        let mut hops_by_depth: Vec<Vec<(GraphSymMeta, GraphCallEdge)>> =
            vec![Vec::new(); max_hops + 1];
        let mut affected_shards: BTreeSet<String> = BTreeSet::new();
        let mut reached_entrypoints: BTreeSet<String> = BTreeSet::new();
        let mut reached_isrs: BTreeSet<String> = BTreeSet::new();
        let mut reached_tests: BTreeSet<String> = BTreeSet::new();
        let mut total_impacted = 0usize;

        while let Some((curr_id, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }
            let Some(in_edges) = rev_adj.get(curr_id.as_str()) else {
                continue;
            };
            for &edge in in_edges {
                let caller_id = &edge.caller_id;
                if visited.insert(caller_id.clone()) {
                    let next_depth = depth + 1;
                    let meta = syms
                        .get(caller_id)
                        .cloned()
                        .unwrap_or_else(|| GraphSymMeta {
                            symbol_id: caller_id.clone(),
                            name: edge.caller_name.clone(),
                            kind: "fn".to_string(),
                            file: edge.file.clone(),
                            start_line: edge.line,
                            arch_layer: "other".to_string(),
                            scope: "first_party".to_string(),
                            section_id: edge.section_id.clone(),
                        });

                    affected_shards.insert(meta.section_id.clone());
                    if meta.kind == "entrypoint" {
                        reached_entrypoints.insert(meta.name.clone());
                    } else if meta.kind == "isr" {
                        reached_isrs.insert(meta.name.clone());
                    }
                    if meta.scope == "test"
                        || meta.arch_layer == "tests"
                        || meta.name.starts_with("test_")
                    {
                        reached_tests.insert(meta.name.clone());
                    }

                    hops_by_depth[next_depth].push((meta, edge.clone()));
                    total_impacted += 1;
                    queue.push_back((caller_id.clone(), next_depth));
                }
            }
        }

        let bundle_name = bundle_name_from_dir(bundle_dir);
        out.push_str(&format!(
            "=== Impact / Blast Radius for '{}' in [{}] ({} transitive callers across {} shards, max_depth={}) ===\n",
            symbol_query,
            bundle_name,
            total_impacted,
            affected_shards.len(),
            max_hops
        ));
        out.push_str(&format!(
            "  Affected Shards : {}\n",
            if affected_shards.is_empty() {
                "-".to_string()
            } else {
                affected_shards
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        out.push_str(&format!(
            "  Entrypoints     : {}\n",
            if reached_entrypoints.is_empty() {
                "-".to_string()
            } else {
                reached_entrypoints
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        out.push_str(&format!(
            "  ISR Handlers    : {}\n",
            if reached_isrs.is_empty() {
                "-".to_string()
            } else {
                reached_isrs.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        ));
        out.push_str(&format!(
            "  Test Roots      : {}\n",
            if reached_tests.is_empty() {
                "-".to_string()
            } else {
                reached_tests.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        ));

        let mut shown = 0usize;
        for (depth, group) in hops_by_depth.into_iter().enumerate().skip(1) {
            if group.is_empty() || shown >= limit {
                continue;
            }
            out.push_str(&format!("  Hop {depth} ({} callers):\n", group.len()));
            for (meta, edge) in group {
                if shown >= limit {
                    break;
                }
                out.push_str(&format!(
                    "    - `{}` (`{}`) ({}) at `{}:{}` -> calls `{}` at line {} [layer={}, scope={}, shard=`{}`]\n",
                    meta.name,
                    meta.symbol_id,
                    meta.kind,
                    meta.file,
                    meta.start_line,
                    edge.callee_name,
                    edge.line,
                    meta.arch_layer,
                    meta.scope,
                    meta.section_id
                ));
                shown += 1;
            }
        }
        if total_impacted > shown {
            out.push_str(&format!(
                "  ... +{} more impacted callers omitted (pass `--limit {}` to view all).\n",
                total_impacted - shown,
                total_impacted
            ));
        }
    }

    if !any_seed_found {
        return Ok(format!(
            "No symbol or call edges matched '{symbol_query}' for impact analysis.\n"
        ));
    }

    Ok(out)
}

/// High-speed parallel search across one or more bundles using SIMD (`memchr::memmem::Finder`)
/// for literal case-sensitive queries and `RegexBuilder` for pattern/case-insensitive queries.
pub fn parallel_bundle_search(
    bundles: &[PathBuf],
    pattern: &str,
    kind: &str,
    ignore_case: bool,
    limit: usize,
) -> Result<Vec<SearchHit>> {
    let re = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .map_err(|source| ChipsrcError::InvalidRegex {
            pattern: pattern.to_string(),
            source,
        })?;

    let is_literal = !ignore_case
        && !pattern.is_empty()
        && !pattern.chars().any(|c| {
            matches!(
                c,
                '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\'
            )
        });
    let simd_finder = is_literal.then(|| memmem::Finder::new(pattern.as_bytes()));

    let matches_line = |line: &str| -> bool {
        if let Some(ref finder) = simd_finder {
            finder.find(line.as_bytes()).is_some()
        } else {
            re.is_match(line)
        }
    };

    let k = kind.trim().to_ascii_lowercase();
    let search_syms = k == "all" || k.starts_with("sym");
    let search_types = k == "all" || k.starts_with("typ");
    let search_calls = k == "all" || k.starts_with("call");
    let search_macros = k == "all" || k.starts_with("mac") || k.starts_with("reg");
    let search_xrefs = k == "all" || k.starts_with("xref");
    let search_secs = k == "all" || k.starts_with("sec") || k == "md";

    let mut all_hits: Vec<SearchHit> = Vec::new();

    for bundle_dir in bundles {
        let bundle_name = bundle_name_from_dir(bundle_dir);

        let tsv_targets = [
            (search_syms, "symbol", "symbols.tsv", 4usize, 5usize),
            (search_types, "type", "types.tsv", 4usize, 5usize),
            (search_calls, "call", "calls.tsv", 4usize, 5usize),
            (search_macros, "macro", "macros.tsv", 4usize, 5usize),
            (search_xrefs, "xref", "xref.tsv", 4usize, 5usize),
        ];

        for (enabled, hit_kind, filename, file_col, line_col) in tsv_targets {
            if !enabled || all_hits.len() >= limit {
                continue;
            }
            let tsv_path = bundle_dir.join("index").join(filename);
            let Ok(content) = fs::read_to_string(&tsv_path) else {
                continue;
            };
            if let Some(ref finder) = simd_finder {
                if finder.find(content.as_bytes()).is_none() {
                    continue;
                }
            }

            for raw_line in content.lines().skip(1) {
                if all_hits.len() >= limit {
                    break;
                }
                if !matches_line(raw_line) {
                    continue;
                }
                let cols: Vec<&str> = raw_line.split('\t').collect();
                let file = cols.get(file_col).copied().unwrap_or(filename).to_string();
                let line = cols
                    .get(line_col)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                all_hits.push(SearchHit {
                    bundle_name: bundle_name.clone(),
                    kind: hit_kind.to_string(),
                    file,
                    line,
                    snippet: raw_line.replace('\t', " | "),
                });
            }
        }

        // Parallel scan across sections/*.md using Rayon
        let sections_dir = bundle_dir.join("sections");
        if search_secs && all_hits.len() < limit && sections_dir.exists() {
            let mut md_paths: Vec<PathBuf> = fs::read_dir(&sections_dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("md"))
                .collect();
            md_paths.sort();

            let md_hits: Vec<SearchHit> = md_paths
                .par_iter()
                .flat_map_iter(|path| {
                    let rel_file = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| format!("sections/{n}"))
                        .unwrap_or_else(|| "sections/shard.md".to_string());
                    let content = match fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(_) => return Vec::new(),
                    };
                    if let Some(ref finder) = simd_finder {
                        if finder.find(content.as_bytes()).is_none() {
                            return Vec::new();
                        }
                    }
                    content
                        .lines()
                        .enumerate()
                        .filter(|(_, line)| matches_line(line))
                        .map(|(idx, line)| SearchHit {
                            bundle_name: bundle_name.clone(),
                            kind: "section".to_string(),
                            file: rel_file.clone(),
                            line: idx + 1,
                            snippet: line.trim().to_string(),
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            for hit in md_hits {
                if all_hits.len() >= limit {
                    break;
                }
                all_hits.push(hit);
            }
        }
    }

    Ok(all_hits)
}

/// Normalizes and scores hardware/code identifier matches across `PERIPH_REG`, `PERIPH->REG`, `PERIPH.REG`, and `PERIPH::REG`.
fn score_hw_identifier_match(candidate: &str, query: &str) -> u8 {
    let c_trim = candidate.trim();
    let q_trim = query.trim();
    if c_trim.is_empty() || q_trim.is_empty() {
        return 0;
    }

    if c_trim.eq_ignore_ascii_case(q_trim) {
        return 4;
    }

    let c_canon = canonicalize_hw_ident(c_trim);
    let q_canon = canonicalize_hw_ident(q_trim);
    if !c_canon.is_empty() && c_canon == q_canon {
        return 4;
    }

    // Check peripheral prefix + register suffix splitting
    if let (Some((cp, cr)), Some((qp, qr))) = (split_periph_reg(c_trim), split_periph_reg(q_trim)) {
        if periph_stems_compatible(cp, qp) && cr.eq_ignore_ascii_case(qr) {
            return 3;
        }
    }

    // Check if query is a peripheral name (e.g. "GPIOA" or "GPIO") matching "GPIOA->MODER" or "GPIOA_MODER"
    if let Some((cp, cr)) = split_periph_reg(c_trim) {
        if cp.eq_ignore_ascii_case(q_trim) || cr.eq_ignore_ascii_case(q_trim) {
            return 3;
        }
        if periph_stems_compatible(cp, q_trim) {
            return 2;
        }
    }

    let c_upper = c_trim.to_ascii_uppercase();
    let q_upper = q_trim.to_ascii_uppercase();
    if c_upper.contains(&q_upper) || c_canon.contains(&q_canon) {
        return 2;
    }

    0
}

fn canonicalize_hw_ident(s: &str) -> String {
    s.trim()
        .replace("->", "_")
        .replace("::", "_")
        .replace('.', "_")
        .to_ascii_uppercase()
}

fn split_periph_reg(s: &str) -> Option<(&str, &str)> {
    s.split_once("->")
        .or_else(|| s.split_once('.'))
        .or_else(|| s.split_once("::"))
        .or_else(|| s.split_once('_'))
}

fn periph_stems_compatible(a: &str, b: &str) -> bool {
    let au = a.trim().to_ascii_uppercase();
    let bu = b.trim().to_ascii_uppercase();
    if au == bu {
        return true;
    }
    let strip_inst = |tok: &str| -> String {
        if tok.len() >= 4 && tok.ends_with('X') {
            return tok[..tok.len() - 1].to_string();
        }
        if tok.len() == 5 && tok.starts_with("GPIO") && matches!(tok.as_bytes()[4], b'A'..=b'K') {
            return "GPIO".to_string();
        }
        let trimmed = tok.trim_end_matches(|c: char| c.is_ascii_digit());
        if trimmed.len() >= 3 {
            trimmed.to_string()
        } else {
            tok.to_string()
        }
    };
    let sa = strip_inst(&au);
    let sb = strip_inst(&bu);
    sa.len() >= 3
        && sa == sb
        && (au == sa || bu == sb || a.ends_with(['x', 'X']) || b.ends_with(['x', 'X']))
}

/// Reads `start_line..=end_line` (capped at 60 lines) from `<source_root>/<rel_file>` and formats as a fenced code block.
fn read_source_snippet(
    bundle_dir: &Path,
    rel_file: &str,
    start_line: usize,
    end_line: usize,
) -> Option<String> {
    let meta = load_meta_file(bundle_dir)?;
    let root_path = Path::new(&meta.metadata.source_root);
    let full_path = if root_path.join(rel_file).is_file() {
        root_path.join(rel_file)
    } else if Path::new(rel_file).is_file() {
        PathBuf::from(rel_file)
    } else {
        return None;
    };

    let content = fs::read_to_string(&full_path).ok()?;
    let all_lines: Vec<&str> = content.lines().collect();
    if all_lines.is_empty() {
        return None;
    }

    let s_line = start_line.max(1);
    let e_line = end_line.max(s_line).min(all_lines.len());
    if s_line > all_lines.len() {
        return None;
    }

    const MAX_SNIPPET_LINES: usize = 60;
    let capped_end = e_line.min(s_line + MAX_SNIPPET_LINES - 1);

    let ext = full_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let lang_tag = LanguageKind::from_extension(ext)
        .map(|l| l.as_str())
        .unwrap_or("text");

    let mut out = String::new();
    out.push_str(&format!("```{lang_tag}\n"));
    for line_no in s_line..=capped_end {
        out.push_str(&format!("{:>4} | {}\n", line_no, all_lines[line_no - 1]));
    }
    if e_line > capped_end {
        out.push_str(&format!(
            "     | ... (+{} more lines in `{}:{}-{}`)\n",
            e_line - capped_end,
            rel_file,
            capped_end + 1,
            e_line
        ));
    }
    out.push_str("```\n");
    Some(out)
}

fn is_valid_bundle_dir(dir: &Path) -> bool {
    dir.is_dir() && dir.join("meta.json").is_file() && dir.join("INDEX.md").is_file()
}

fn load_meta_file(bundle_dir: &Path) -> Option<BundleMetaFile> {
    let raw = fs::read_to_string(bundle_dir.join("meta.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

fn load_cache_file(bundle_dir: &Path) -> Option<IncrementalAstCache> {
    let raw = fs::read_to_string(bundle_dir.join("cache.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

fn bundle_name_from_dir(bundle_dir: &Path) -> String {
    if let Some(meta) = load_meta_file(bundle_dir) {
        if !meta.metadata.repo_name.is_empty() {
            return meta.metadata.repo_name;
        }
    }
    bundle_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bundle")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RepoMetadata, SanityReport, VendorMode};

    #[test]
    fn test_hw_identifier_and_hex_matching() {
        assert_eq!(score_hw_identifier_match("GPIOA->MODER", "GPIOA_MODER"), 4);
        assert_eq!(score_hw_identifier_match("GPIOA_MODER", "GPIOA.MODER"), 4);
        assert_eq!(score_hw_identifier_match("GPIOA->MODER", "GPIOA"), 3);
        assert_eq!(score_hw_identifier_match("GPIOx_MODER", "GPIOA->MODER"), 3);
        assert_eq!(score_hw_identifier_match("TIM1->CCR1", "UART0_DR"), 0);
    }

    #[test]
    fn test_query_symbols_macros_and_parallel_search_with_show() {
        let tmp = std::env::temp_dir().join(format!("chipsrc_query_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let src_dir = tmp.join("src");
        let bundle_dir = tmp.join("output").join("demo");
        let index_dir = bundle_dir.join("index");
        let sections_dir = bundle_dir.join("sections");

        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&index_dir).unwrap();
        fs::create_dir_all(&sections_dir).unwrap();

        let c_file = src_dir.join("drv.c");
        fs::write(
            &c_file,
            "#define REG_CTRL 0x41C00004UL\nvoid lock_actuator(int id) {\n    GPIOA->MODER = id;\n}\n",
        )
        .unwrap();

        let meta = BundleMetaFile {
            metadata: RepoMetadata {
                repo_name: "demo".to_string(),
                source_root: tmp.display().to_string(),
                fingerprint: "abc12345".to_string(),
                vendor_mode: VendorMode::Active,
                total_files: 1,
                first_party_files: 1,
                symbol_count: 1,
                section_count: 1,
                ..Default::default()
            },
            sanity: SanityReport {
                score: 98,
                ..Default::default()
            },
        };
        fs::write(
            bundle_dir.join("meta.json"),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();
        fs::write(bundle_dir.join("INDEX.md"), "# demo\n").unwrap();

        let syms_tsv = "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\n\
src/drv.c::lock_actuator\tlock_actuator\tfn\tpub\tsrc/drv.c\t2\t4\tvoid lock_actuator(int id)\t0.500000\t1\t0\tdrvs\tfirst_party\t01-src\n";
        fs::write(index_dir.join("symbols.tsv"), syms_tsv).unwrap();

        let macros_tsv = "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription\n\
REG_CTRL\tmmio_addr\t0x41C00004UL\t0x41C00004\tsrc/drv.c\t1\tdrvs\tfirst_party\t01-src\tMMIO register\n\
GPIOA->MODER\treg_access\tGPIOA->MODER = id;\t-\tsrc/drv.c\t3\tdrvs\tfirst_party\t01-src\tRegister access\n";
        fs::write(index_dir.join("macros.tsv"), macros_tsv).unwrap();

        let bundles = resolve_bundles(&bundle_dir).unwrap();
        assert_eq!(bundles.len(), 1);

        let sym_out = query_symbols(&bundles, "lock_actuator", None, true, 10).unwrap();
        assert!(sym_out.contains("void lock_actuator(int id)"));
        assert!(sym_out.contains("GPIOA->MODER = id;"));

        let mac_hex_out = query_macros(&bundles, "41C00004h", false, 10).unwrap();
        assert!(mac_hex_out.contains("REG_CTRL"));

        let mac_periph_out = query_macros(&bundles, "GPIOA_MODER", false, 10).unwrap();
        assert!(mac_periph_out.contains("GPIOA->MODER"));

        let hits = parallel_bundle_search(&bundles, "lock_actuator", "all", false, 10).unwrap();
        assert!(!hits.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }
}
