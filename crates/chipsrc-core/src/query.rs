use crate::error::{ChipsrcError, Result};
use crate::mmio::{normalize_hex_literal, normalize_query_hex_literal};
use crate::model::{BundleStatusEntry, LanguageKind, SearchHit, DEFAULT_MAX_FILE_BYTES};
use crate::scanner::{
    canonical_repo_root_and_name, check_files_changed, check_meta_files_changed,
    first_missing_bundle_artifact, has_bundle_cache, has_valid_tsv_header, load_cache_file,
    load_cache_manifest_any_version, load_meta_file, scan_repository,
};
use memchr::memmem;
use rayon::prelude::*;
use regex::RegexBuilder;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

/// Resolves `target` into one or more indexed bundle directories (containing `meta.json` and `INDEX.md`).
pub fn resolve_bundles(target: &Path) -> Result<Vec<PathBuf>> {
    resolve_bundles_internal(target, true)
}

/// Discovers all indexed bundles under `workspace` (and `workspace/output`) without filtering
/// to a single workspace `source_root`.
pub fn discover_workspace_bundles(workspace: &Path) -> Result<Vec<PathBuf>> {
    resolve_bundles_internal(workspace, false)
}

fn resolve_bundles_internal(
    target: &Path,
    prefer_matching_source_root: bool,
) -> Result<Vec<PathBuf>> {
    if is_valid_bundle_dir(target) {
        return Ok(vec![target.to_path_buf()]);
    }

    let is_bare_single_name =
        !target.is_absolute() && target.components().count() == 1 && target != Path::new(".");

    if is_bare_single_name {
        let output_candidate = Path::new("output").join(target);
        if is_valid_bundle_dir(&output_candidate) {
            return Ok(vec![output_candidate]);
        }
    }

    if target.is_dir() {
        if let Some(stem) = target.file_name().and_then(|s| s.to_str()) {
            let nested_candidate = target.join("output").join(stem);
            if is_valid_bundle_dir(&nested_candidate) {
                return Ok(vec![nested_candidate]);
            }
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

    // Issue #17: When multiple bundles exist under `output/` and `target` is a repository root
    // (such as `.`), prefer the bundle(s) whose `metadata.source_root` matches `target` so
    // unrelated bundles in `output/` do not bleed into default queries.
    if prefer_matching_source_root && bundles.len() > 1 && target.is_dir() {
        let (target_canon, _) = canonical_repo_root_and_name(target);
        let matching: Vec<PathBuf> = bundles
            .iter()
            .filter(|b| {
                load_meta_file(b).is_some_and(|m| {
                    let (src_canon, _) =
                        canonical_repo_root_and_name(Path::new(&m.metadata.source_root));
                    src_canon.eq_ignore_ascii_case(&target_canon)
                })
            })
            .cloned()
            .collect();
        if !matching.is_empty() {
            return Ok(matching);
        }
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

/// Structured zero-copy view of a canonical `file::scoped` (or `file::Enclosing::short`) symbol ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolIdView<'a> {
    pub file: &'a str,
    pub scoped: &'a str,
    pub short: &'a str,
}

impl<'a> SymbolIdView<'a> {
    pub fn parse(symbol_id: &'a str) -> Self {
        parse_symbol_id(symbol_id)
    }
}

/// Splits a canonical `file::Enclosing::name` symbol/type ID into `(file, scoped, short)`.
pub fn parse_symbol_id(id: &str) -> SymbolIdView<'_> {
    if let Some((file, rest)) = id.split_once("::") {
        let scoped = rest
            .rsplit_once(':')
            .filter(|(_, line)| !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()))
            .map(|(s, _)| s)
            .unwrap_or(rest);
        let short = scoped.rsplit_once("::").map(|(_, s)| s).unwrap_or(scoped);
        SymbolIdView {
            file,
            scoped,
            short,
        }
    } else {
        SymbolIdView {
            file: "",
            scoped: id,
            short: id,
        }
    }
}

/// Returns `true` when `q` explicitly targets a file path (contains `/` or `\` or ends with a source extension).
pub fn query_targets_file(q: &str) -> bool {
    let t = q.trim();
    t.contains('/')
        || t.contains('\\')
        || t.rsplit_once('.')
            .is_some_and(|(_, ext)| LanguageKind::from_extension(ext).is_some())
}

/// Scans `workspace` (and `workspace/output`) for indexed bundles and checks live freshness against source files.
pub fn workspace_status(workspace: &Path) -> Result<Vec<BundleStatusEntry>> {
    if !workspace.exists() && !Path::new("output").join(workspace).exists() {
        return Err(ChipsrcError::BundleNotFound(workspace.to_path_buf()));
    }
    let bundles = match discover_workspace_bundles(workspace) {
        Ok(b) => b,
        Err(ChipsrcError::BundleNotFound(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut entries = Vec::with_capacity(bundles.len());
    for bundle_dir in bundles {
        let missing_artifact = first_missing_bundle_artifact(&bundle_dir);
        let Some(meta_file) = load_meta_file(&bundle_dir) else {
            let fallback_manifest = load_cache_manifest_any_version(&bundle_dir);
            let bundle_name = bundle_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("bundle")
                .to_string();
            let source_root = fallback_manifest
                .as_ref()
                .map(|m| m.repo_root.clone())
                .unwrap_or_default();
            let total_files = fallback_manifest
                .as_ref()
                .map(|m| m.files.len().max(1))
                .unwrap_or(1);
            let reason = missing_artifact
                .map(|m| format!("missing {m}"))
                .unwrap_or_else(|| "missing or invalid meta.json".to_string());
            entries.push(BundleStatusEntry {
                bundle_name,
                bundle_dir,
                source_root,
                is_fresh: false,
                changed_files_count: total_files,
                symbol_count: 0,
                section_count: 0,
                reason: Some(reason),
            });
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
            if !has_bundle_cache(&bundle_dir) || meta.file_stamps.is_empty() {
                meta.total_files.max(1)
            } else if let Some(count) =
                check_meta_files_changed(source_path, &meta, DEFAULT_MAX_FILE_BYTES)
            {
                count
            } else if let Some(cache) = load_cache_file(&bundle_dir) {
                check_files_changed(source_path, &cache, DEFAULT_MAX_FILE_BYTES).unwrap_or(0)
            } else if let Ok((_, live_fp)) =
                scan_repository(source_path, meta.vendor_mode, DEFAULT_MAX_FILE_BYTES)
            {
                usize::from(live_fp != meta.fingerprint)
            } else {
                0
            }
        } else {
            0
        };

        let is_fresh = changed_files_count == 0 && missing_artifact.is_none();
        let reason = if let Some(ref missing) = missing_artifact {
            Some(format!("missing {missing}"))
        } else if !has_bundle_cache(&bundle_dir) {
            Some("missing or outdated cache/manifest.json".to_string())
        } else if meta.file_stamps.is_empty() {
            Some("missing file_stamps in meta.json".to_string())
        } else if changed_files_count > 0 {
            Some(format!("{changed_files_count} files changed"))
        } else {
            None
        };

        entries.push(BundleStatusEntry {
            bundle_name,
            bundle_dir,
            source_root: meta.source_root,
            is_fresh,
            changed_files_count,
            symbol_count: meta.symbol_count,
            section_count: meta.section_count,
            reason,
        });
    }

    entries.sort_by(|a, b| a.bundle_name.cmp(&b.bundle_name));
    Ok(entries)
}

/// Loads a required `index/<name>` TSV table from `bundle_dir`, returning
/// [`ChipsrcError::IncompleteBundle`] if the table is missing, empty, or lacks its header line.
pub fn load_index_table(bundle_dir: &Path, name: &str) -> Result<String> {
    let rel = if name.starts_with("index/") {
        name.to_string()
    } else {
        format!("index/{name}")
    };
    let path = bundle_dir.join(&rel);
    match fs::read_to_string(&path) {
        Ok(content) if has_valid_tsv_header(&rel, &content) => Ok(content),
        _ => Err(ChipsrcError::IncompleteBundle {
            bundle: bundle_dir.to_path_buf(),
            missing: rel,
        }),
    }
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
        doc_summary: String,
        score: u8,
    }

    let mut hits: Vec<SymHit> = Vec::new();

    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "symbols.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 14 {
                continue;
            }
            let symbol_id = cols[0];
            let name = cols[1];
            let kind = cols[2];
            let doc_summary = cols.get(14).copied().unwrap_or("");

            if let Some(ref kf) = kind_lower {
                if !kind.eq_ignore_ascii_case(kf) && !kind.to_ascii_lowercase().starts_with(kf) {
                    continue;
                }
            }

            let id_view = parse_symbol_id(symbol_id);
            let name_lower = name.to_ascii_lowercase();
            let scoped_lower = id_view.scoped.to_ascii_lowercase();
            let short_lower = id_view.short.to_ascii_lowercase();
            let sig_lower = cols[7].to_ascii_lowercase();
            let targets_file = query_targets_file(q_trim);

            let score = if q_lower.is_empty() {
                1
            } else if name == q_trim
                || id_view.scoped == q_trim
                || id_view.short == q_trim
                || symbol_id == q_trim
            {
                5
            } else if name_lower == q_lower
                || scoped_lower == q_lower
                || short_lower == q_lower
                || (targets_file && symbol_id.eq_ignore_ascii_case(q_trim))
            {
                4
            } else if scoped_lower.ends_with(&format!("::{q_lower}"))
                || name_lower.starts_with(&q_lower)
                || scoped_lower.starts_with(&q_lower)
                || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
            {
                3
            } else if name_lower.contains(&q_lower)
                || scoped_lower.contains(&q_lower)
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
                doc_summary: doc_summary.to_string(),
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
    let mut snippet_cache = SourceSnippetCache::default();
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
        if !h.doc_summary.is_empty() {
            out.push_str(&format!("  doc: {}\n", h.doc_summary));
        }

        if show_source {
            if let Some(snippet) =
                snippet_cache.read_snippet(&h.bundle_dir, &h.file, h.start_line, h.end_line)
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
    let has_exact_sym = bundles_have_exact_symbol(bundles, q_trim, &q_lower)?;
    let suffix = format!("::{q_lower}");

    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "calls.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 8 {
                continue;
            }
            let callee_name = cols[2];
            let callee_id = cols[3];
            let id_view = parse_symbol_id(callee_id);
            let callee_lower = callee_name.to_ascii_lowercase();
            let scoped_lower = id_view.scoped.to_ascii_lowercase();
            let targets_file = query_targets_file(q_trim);

            let score = if callee_name == q_trim
                || id_view.scoped == q_trim
                || id_view.short == q_trim
                || callee_id == q_trim
            {
                4
            } else if callee_lower == q_lower
                || scoped_lower == q_lower
                || id_view.short.eq_ignore_ascii_case(q_trim)
                || scoped_lower.ends_with(&suffix)
                || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
            {
                3
            } else if !has_exact_sym
                && (callee_lower.contains(&q_lower) || scoped_lower.contains(&q_lower))
            {
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
    let resolved_count = hits
        .iter()
        .filter(|h| h.tier != "external_or_macro")
        .count();
    let ext_count = total - resolved_count;
    let mut out = format!(
        "=== Callers of '{}' ({} call sites: {} resolved, {} external/macro) ===\n",
        symbol, total, resolved_count, ext_count
    );
    let mut snippet_cache = SourceSnippetCache::default();
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
            if let Some(snippet) = snippet_cache.read_snippet(&h.bundle_dir, &h.file, start, end) {
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
    let has_exact_sym = bundles_have_exact_symbol(bundles, q_trim, &q_lower)?;
    let suffix = format!("::{q_lower}");

    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "calls.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 8 {
                continue;
            }
            let caller_id = cols[0];
            let caller_name = cols[1];
            let id_view = parse_symbol_id(caller_id);
            let caller_lower = caller_name.to_ascii_lowercase();
            let scoped_lower = id_view.scoped.to_ascii_lowercase();
            let targets_file = query_targets_file(q_trim);

            let score = if caller_name == q_trim
                || id_view.scoped == q_trim
                || id_view.short == q_trim
                || caller_id == q_trim
            {
                4
            } else if caller_lower == q_lower
                || scoped_lower == q_lower
                || id_view.short.eq_ignore_ascii_case(q_trim)
                || scoped_lower.ends_with(&suffix)
                || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
            {
                3
            } else if !has_exact_sym
                && (caller_lower.contains(&q_lower) || scoped_lower.contains(&q_lower))
            {
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

    // Issue #42.2: Sort resolved project callees (`tier != "external_or_macro"`) ahead of
    // unresolved external/macro calls so genuine project dependencies always surface first.
    hits.sort_by(|a, b| {
        let resolved_a = a.tier != "external_or_macro";
        let resolved_b = b.tier != "external_or_macro";
        b.score
            .cmp(&a.score)
            .then_with(|| resolved_b.cmp(&resolved_a))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let total = hits.len();
    let resolved_count = hits
        .iter()
        .filter(|h| h.tier != "external_or_macro")
        .count();
    let ext_count = total - resolved_count;
    let mut out = format!(
        "=== Callees invoked by '{}' ({} call sites: {} resolved, {} external/macro) ===\n",
        symbol, total, resolved_count, ext_count
    );
    let mut snippet_cache = SourceSnippetCache::default();
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
            if let Some(snippet) = snippet_cache.read_snippet(&h.bundle_dir, &h.file, start, end) {
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
        doc_summary: String,
        score: u8,
    }

    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "types.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 11 {
                continue;
            }
            let type_id = cols[0];
            let name = cols[1];
            let fields = cols[7];
            let doc_summary = cols.get(11).copied().unwrap_or("");

            let id_view = parse_symbol_id(type_id);
            let name_lower = name.to_ascii_lowercase();
            let scoped_lower = id_view.scoped.to_ascii_lowercase();
            let fields_lower = fields.to_ascii_lowercase();
            let targets_file = query_targets_file(q_trim);

            let score = if q_lower.is_empty() {
                1
            } else if name == q_trim || id_view.scoped == q_trim || type_id == q_trim {
                5
            } else if name_lower == q_lower
                || scoped_lower == q_lower
                || (targets_file && type_id.eq_ignore_ascii_case(q_trim))
            {
                4
            } else if name_lower.starts_with(&q_lower)
                || scoped_lower.starts_with(&q_lower)
                || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
            {
                3
            } else if name_lower.contains(&q_lower)
                || scoped_lower.contains(&q_lower)
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
                doc_summary: doc_summary.to_string(),
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
    let mut snippet_cache = SourceSnippetCache::default();
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
        if !h.doc_summary.is_empty() {
            out.push_str(&format!("  doc   : {}\n", h.doc_summary));
        }

        if show_source {
            if let Some(snippet) =
                snippet_cache.read_snippet(&h.bundle_dir, &h.file, h.start_line, h.end_line)
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
    let q_lower = q_trim.to_ascii_lowercase();
    let q_hw = QueryHw::new(q_trim);

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
        let content = load_index_table(bundle_dir, "macros.tsv")?;
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

            let hex_exact = match (&q_hw.hex, &row_hex) {
                (Some(qh), Some(rh)) => qh.eq_ignore_ascii_case(rh),
                _ => false,
            };

            let score = if hex_exact {
                5
            } else if q_hw.is_hex {
                // Issue #9: When the query is an explicit hex address/mask (`0xFF`, `41C00004h`),
                // require exact numeric hex equality so `0xFF` never substring-match `0xFFFFFFFF`.
                0
            } else {
                let id_score = score_hw_identifier_match_prepared(name, &q_hw);
                let val_score = if !q_lower.is_empty()
                    && (ascii_contains_ignore_case(val.as_bytes(), q_lower.as_bytes())
                        || ascii_contains_ignore_case(desc.as_bytes(), q_lower.as_bytes()))
                {
                    1
                } else {
                    0
                };
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

    if hits.iter().any(|h| h.score >= 3) {
        hits.retain(|h| h.score >= 2);
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let total = hits.len();
    let mut out = String::new();
    let mut snippet_cache = SourceSnippetCache::default();
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
            if let Some(snippet) = snippet_cache.read_snippet(&h.bundle_dir, &h.file, start, end) {
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
        let content = load_index_table(bundle_dir, "sections.tsv")?;
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

    let total = hits.len();
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
                let body_trimmed = md_body
                    .strip_prefix("---\r\n")
                    .or_else(|| md_body.strip_prefix("---\n"))
                    .unwrap_or(&md_body);
                out.push_str("---\n");
                out.push_str(body_trimmed);
                if !body_trimmed.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("---\n");
            }
        }
    }

    if total > limit {
        out.push_str(&format!(
            "... +{} more module sections omitted (pass `--limit {}` to view all).\n",
            total - limit,
            total
        ));
    }

    Ok(out)
}

/// Queries the Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`),
/// normalizing hex literals (`0x400` <-> `400h`) and peripheral separators (`PERIPH_REG` <-> `PERIPH->REG` <-> `PERIPH.REG`).
pub fn query_xref(bundles: &[PathBuf], query: &str, limit: usize) -> Result<String> {
    let q_trim = query.trim();
    let q_lower = q_trim.to_ascii_lowercase();
    let q_hw = QueryHw::new(q_trim);

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
        let content = load_index_table(bundle_dir, "xref.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            if !q_hw.is_hex
                && !q_hw.fast_prefix.is_empty()
                && !ascii_contains_ignore_case(line.as_bytes(), q_hw.fast_prefix.as_bytes())
            {
                continue;
            }
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

            let hex_match = match &q_hw.hex {
                Some(qh) => {
                    normalize_hex_literal(sym).is_some_and(|sh| sh.eq_ignore_ascii_case(qh))
                        || normalize_hex_literal(target)
                            .is_some_and(|th| th.eq_ignore_ascii_case(qh))
                        || normalize_hex_literal(context)
                            .is_some_and(|ch| ch.eq_ignore_ascii_case(qh))
                }
                None => false,
            };

            let score = if hex_match {
                5
            } else if q_hw.is_hex {
                0
            } else {
                let sym_score = score_hw_identifier_match_prepared(sym, &q_hw);
                let target_score = score_hw_identifier_match_prepared(target, &q_hw);
                let ctx_score = if !q_lower.is_empty()
                    && ascii_contains_ignore_case(context.as_bytes(), q_lower.as_bytes())
                {
                    1
                } else {
                    0
                };
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

    if hits.iter().any(|h| h.score >= 3) {
        hits.retain(|h| h.score >= 2);
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
) -> Result<(FxHashMap<String, GraphSymMeta>, Vec<GraphCallEdge>)> {
    let mut syms: FxHashMap<String, GraphSymMeta> = FxHashMap::default();
    let sym_content = load_index_table(bundle_dir, "symbols.tsv")?;
    for line in sym_content.lines().skip(1) {
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

    let mut edges: Vec<GraphCallEdge> = Vec::new();
    let calls_content = load_index_table(bundle_dir, "calls.tsv")?;
    for line in calls_content.lines().skip(1) {
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

        // Skip unresolved external/macro pseudo-nodes when building call/impact BFS graph (Bug 8)
        if callee_id.starts_with("external::") || tier == "external_or_macro" {
            continue;
        }

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

    Ok((syms, edges))
}

fn match_symbol_ids_for_query(syms: &FxHashMap<String, GraphSymMeta>, query: &str) -> Vec<String> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return Vec::new();
    }
    let q_lower = q_trim.to_ascii_lowercase();
    let suffix = format!("::{q_lower}");
    let targets_file = query_targets_file(q_trim);

    let mut scored: Vec<(u8, String)> = Vec::new();
    for (id, meta) in syms {
        let id_view = parse_symbol_id(id);
        let name_lower = meta.name.to_ascii_lowercase();
        let scoped_lower = id_view.scoped.to_ascii_lowercase();
        let short_lower = id_view.short.to_ascii_lowercase();
        let score = if meta.name == q_trim
            || id_view.scoped == q_trim
            || id_view.short == q_trim
            || id == q_trim
        {
            4
        } else if name_lower == q_lower
            || scoped_lower == q_lower
            || short_lower == q_lower
            || scoped_lower.ends_with(&suffix)
            || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
        {
            3
        } else if name_lower.contains(&q_lower) || scoped_lower.contains(&q_lower) {
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
        let (syms, edges) = load_bundle_call_graph(bundle_dir)?;
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
                let def_coord = meta
                    .map(|m| format!(" at `{}:{}`", m.file, m.start_line))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  -> [{}] `{}` (`{}`) ({}){} via `{}:{}` [tier={}, layer={}, shard=`{}`]\n",
                    idx + 1,
                    edge.callee_name,
                    edge.callee_id,
                    kind,
                    def_coord,
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
        let (syms, edges) = load_bundle_call_graph(bundle_dir)?;
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
/// Supports `kind = "source"` (`--source` / `-S`) and automatic raw source fallback when
/// `kind = "all"` returns 0 index hits.
pub fn parallel_bundle_search(
    bundles: &[PathBuf],
    pattern: &str,
    kind: &str,
    ignore_case: bool,
    limit: usize,
) -> Result<Vec<SearchHit>> {
    // Issue #28: Fall back to literal escaped regex when `pattern` has unclosed regex metacharacters
    // such as `"fn("` or `"ARR["`.
    let re = match RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
    {
        Ok(compiled) => compiled,
        Err(_) => RegexBuilder::new(&regex::escape(pattern))
            .case_insensitive(ignore_case)
            .build()
            .map_err(|source| ChipsrcError::InvalidRegex {
                pattern: pattern.to_string(),
                source,
            })?,
    };

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
    let search_source_explicit = k.starts_with("src") || k.starts_with("source") || k == "code";
    let search_syms = !search_source_explicit && (k == "all" || k.starts_with("sym"));
    let search_types = !search_source_explicit && (k == "all" || k.starts_with("typ"));
    let search_calls = !search_source_explicit && (k == "all" || k.starts_with("call"));
    let search_macros =
        !search_source_explicit && (k == "all" || k.starts_with("mac") || k.starts_with("reg"));
    let search_xrefs = !search_source_explicit && (k == "all" || k.starts_with("xref"));
    let search_secs = !search_source_explicit && (k == "all" || k.starts_with("sec") || k == "md");

    let query_is_path_like = pattern.contains('/')
        || pattern.contains('\\')
        || pattern.ends_with(".rs")
        || pattern.ends_with(".c")
        || pattern.ends_with(".h")
        || pattern.ends_with(".cpp")
        || pattern.ends_with(".hpp")
        || pattern.ends_with(".py")
        || pattern.ends_with(".ts")
        || pattern.ends_with(".tsx")
        || pattern.ends_with(".js");
    let query_has_scope_sep = pattern.contains("::");

    let mut all_hits: Vec<SearchHit> = Vec::new();
    let mut seen_coords: FxHashSet<(String, String, usize)> = FxHashSet::default();

    for bundle_dir in bundles {
        let bundle_name = bundle_name_from_dir(bundle_dir);

        let tsv_targets = [
            (search_syms, "symbol", "symbols.tsv", 4usize, 5usize),
            (search_types, "type", "types.tsv", 4usize, 5usize),
            (search_macros, "macro", "macros.tsv", 4usize, 5usize),
            (search_calls, "call", "calls.tsv", 4usize, 5usize),
        ];

        for (enabled, hit_kind, filename, file_col, line_col) in tsv_targets {
            if !enabled || all_hits.len() >= limit {
                continue;
            }
            let content = load_index_table(bundle_dir, filename)?;
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
                let semantic_match = if query_is_path_like {
                    true
                } else {
                    match hit_kind {
                        "symbol" => {
                            cols.get(1).is_some_and(|c| matches_line(c))
                                || cols.get(7).is_some_and(|c| matches_line(c))
                                || cols.get(14).is_some_and(|c| matches_line(c))
                                || (query_has_scope_sep
                                    && cols.first().is_some_and(|c| matches_line(c)))
                        }
                        "type" => {
                            cols.get(1).is_some_and(|c| matches_line(c))
                                || cols.get(7).is_some_and(|c| matches_line(c))
                                || cols.get(11).is_some_and(|c| matches_line(c))
                                || (query_has_scope_sep
                                    && cols.first().is_some_and(|c| matches_line(c)))
                        }
                        "macro" => {
                            cols.first().is_some_and(|c| matches_line(c))
                                || cols.get(2).is_some_and(|c| matches_line(c))
                                || cols.get(3).is_some_and(|c| matches_line(c))
                                || cols.get(9).is_some_and(|c| matches_line(c))
                        }
                        "call" => {
                            cols.get(1).is_some_and(|c| matches_line(c))
                                || cols.get(2).is_some_and(|c| matches_line(c))
                                || (query_has_scope_sep
                                    && (cols.first().is_some_and(|c| matches_line(c))
                                        || cols.get(3).is_some_and(|c| matches_line(c))))
                        }
                        _ => true,
                    }
                };
                if !semantic_match {
                    continue;
                }
                let file = cols.get(file_col).copied().unwrap_or(filename).to_string();
                let line = cols
                    .get(line_col)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if !seen_coords.insert((bundle_name.clone(), file.clone(), line)) {
                    continue;
                }
                all_hits.push(SearchHit {
                    bundle_name: bundle_name.clone(),
                    kind: hit_kind.to_string(),
                    file,
                    line,
                    snippet: raw_line.replace('\t', " | "),
                });
            }
        }

        // Parallel scan across sections/*.md using Rayon (before xref.tsv so section hits aren't drowned out)
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
                if seen_coords.insert((bundle_name.clone(), hit.file.clone(), hit.line)) {
                    all_hits.push(hit);
                }
            }
        }

        // Search `xref.tsv` last (deduplicating against symbol/type/macro/call coordinates)
        if search_xrefs && all_hits.len() < limit {
            let content = load_index_table(bundle_dir, "xref.tsv")?;
            let has_match = simd_finder
                .as_ref()
                .is_none_or(|f| f.find(content.as_bytes()).is_some());
            if has_match {
                for raw_line in content.lines().skip(1) {
                    if all_hits.len() >= limit {
                        break;
                    }
                    if !matches_line(raw_line) {
                        continue;
                    }
                    let cols: Vec<&str> = raw_line.split('\t').collect();
                    let semantic_match = query_is_path_like
                        || cols.first().is_some_and(|c| matches_line(c))
                        || cols.get(3).is_some_and(|c| matches_line(c))
                        || cols.get(7).is_some_and(|c| matches_line(c));
                    if !semantic_match {
                        continue;
                    }
                    let file = cols.get(4).copied().unwrap_or("xref.tsv").to_string();
                    let line = cols
                        .get(5)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    if !seen_coords.insert((bundle_name.clone(), file.clone(), line)) {
                        continue;
                    }
                    all_hits.push(SearchHit {
                        bundle_name: bundle_name.clone(),
                        kind: "xref".to_string(),
                        file,
                        line,
                        snippet: raw_line.replace('\t', " | "),
                    });
                }
            }
        }
    }

    // Issue #19: Full-text raw source search when `kind` is `"source"`/`"src"` OR when `kind == "all"`
    // produced 0 hits in the bundle index tables / section skeletons.
    if (search_source_explicit || (k == "all" && all_hits.is_empty())) && all_hits.len() < limit {
        for bundle_dir in bundles {
            if all_hits.len() >= limit {
                break;
            }
            let Some(meta) = load_meta_file(bundle_dir) else {
                continue;
            };
            let source_root = Path::new(&meta.metadata.source_root);
            if !source_root.is_dir() {
                continue;
            }
            let bundle_name = if !meta.metadata.repo_name.is_empty() {
                meta.metadata.repo_name.clone()
            } else {
                bundle_name_from_dir(bundle_dir)
            };

            let rel_files: Vec<String> = if !meta.metadata.file_stamps.is_empty() {
                meta.metadata
                    .file_stamps
                    .iter()
                    .map(|s| s.rel_path.clone())
                    .collect()
            } else if let Ok((scanned, _)) = scan_repository(
                source_root,
                meta.metadata.vendor_mode,
                DEFAULT_MAX_FILE_BYTES,
            ) {
                scanned.into_iter().map(|s| s.rel_path).collect()
            } else {
                Vec::new()
            };

            let src_hits: Vec<SearchHit> = rel_files
                .par_iter()
                .flat_map_iter(|rel_file| {
                    let full_path = source_root.join(rel_file);
                    let content = match fs::read_to_string(&full_path) {
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
                            kind: "source".to_string(),
                            file: rel_file.clone(),
                            line: idx + 1,
                            snippet: line.trim().to_string(),
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            for hit in src_hits {
                if all_hits.len() >= limit {
                    break;
                }
                all_hits.push(hit);
            }
        }
    }

    Ok(all_hits)
}

fn bundles_have_exact_symbol(bundles: &[PathBuf], q_trim: &str, q_lower: &str) -> Result<bool> {
    let suffix = format!("::{q_lower}");
    let mut found = false;
    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "symbols.tsv")?;
        if found || q_trim.is_empty() {
            continue;
        }
        for line in content.lines().skip(1) {
            let mut cols = line.split('\t');
            let Some(symbol_id) = cols.next() else {
                continue;
            };
            let Some(name) = cols.next() else {
                continue;
            };
            if name.eq_ignore_ascii_case(q_trim)
                || symbol_id.eq_ignore_ascii_case(q_trim)
                || symbol_id.to_ascii_lowercase().ends_with(&suffix)
            {
                found = true;
                break;
            }
        }
    }
    Ok(found)
}

/// Pre-parsed query representation for zero-allocation hardware/code identifier scoring.
struct QueryHw<'a> {
    raw: &'a str,
    canon: String,
    upper: String,
    splits: [Option<(&'a str, &'a str)>; 2],
    hex: Option<String>,
    is_hex: bool,
    fast_prefix: String,
}

impl<'a> QueryHw<'a> {
    fn new(query: &'a str) -> Self {
        let raw = query.trim();
        let lower = raw.to_ascii_lowercase();
        let hex = normalize_query_hex_literal(raw);
        let is_hex = hex.is_some() && (lower.starts_with("0x") || lower.ends_with('h'));
        let mut canon_buf = [0u8; 128];
        let canon = canon_hw_buf(raw, &mut canon_buf).to_string();
        let upper = raw.to_ascii_uppercase();
        let splits = split_periph_reg_array(raw);
        let fast_prefix = extract_fast_hw_prefix(raw);
        Self {
            raw,
            canon,
            upper,
            splits,
            hex,
            is_hex,
            fast_prefix,
        }
    }
}

fn extract_fast_hw_prefix(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('_');
    let first_tok: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if first_tok.len() < 3 {
        return String::new();
    }
    let upper = first_tok.to_ascii_uppercase();
    let stripped = strip_periph_instance_slice(&upper);
    if stripped.len() >= 3 {
        stripped.to_string()
    } else {
        upper
    }
}

#[inline]
fn ascii_contains_ignore_case(haystack: &[u8], needle_upper_or_lower: &[u8]) -> bool {
    let nlen = needle_upper_or_lower.len();
    if nlen == 0 {
        return true;
    }
    if haystack.len() < nlen {
        return false;
    }
    let first_lo = needle_upper_or_lower[0].to_ascii_lowercase();
    let first_hi = needle_upper_or_lower[0].to_ascii_uppercase();
    let max_start = haystack.len() - nlen;
    let mut i = 0;
    while i <= max_start {
        let b = haystack[i];
        if (b == first_lo || b == first_hi)
            && haystack[i..i + nlen].eq_ignore_ascii_case(needle_upper_or_lower)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Normalizes and scores hardware/code identifier matches across `PERIPH_REG`, `PERIPH->REG`, `PERIPH.REG`, and `PERIPH::REG`.
#[cfg(test)]
fn score_hw_identifier_match(candidate: &str, query: &str) -> u8 {
    let q_hw = QueryHw::new(query);
    score_hw_identifier_match_prepared(candidate, &q_hw)
}

fn score_hw_identifier_match_prepared(candidate: &str, q: &QueryHw<'_>) -> u8 {
    let c_trim = candidate.trim();
    if c_trim.is_empty() || q.raw.is_empty() {
        return 0;
    }

    if c_trim.eq_ignore_ascii_case(q.raw) {
        return 4;
    }

    let mut c_canon_buf = [0u8; 128];
    let c_canon = canon_hw_buf(c_trim, &mut c_canon_buf);
    if !c_canon.is_empty() && c_canon == q.canon {
        return 4;
    }

    let c_splits = split_periph_reg_array(c_trim);

    // Check peripheral prefix + register suffix splitting (both first and last `_` splits)
    for (cp, cr) in c_splits.into_iter().flatten() {
        for (qp, qr) in q.splits.into_iter().flatten() {
            if periph_stems_compatible(cp, qp) && cr.eq_ignore_ascii_case(qr) {
                return 3;
            }
        }
    }

    // Check if query is a peripheral name (e.g. "GPIOA" or "GPIO") matching "GPIOA->MODER" or "GPIOA_MODER"
    for (cp, cr) in c_splits.into_iter().flatten() {
        if cp.eq_ignore_ascii_case(q.raw) || cr.eq_ignore_ascii_case(q.raw) {
            return 3;
        }
        if periph_stems_compatible(cp, q.raw) {
            return 2;
        }
    }

    if ascii_contains_ignore_case(c_trim.as_bytes(), q.upper.as_bytes())
        || (!q.canon.is_empty() && c_canon.contains(q.canon.as_str()))
    {
        return 2;
    }

    0
}

fn canon_hw_buf<'a>(s: &str, buf: &'a mut [u8; 128]) -> &'a str {
    let bytes = s.trim().trim_start_matches('_').as_bytes();
    let mut len = 0usize;
    let mut i = 0usize;
    while i < bytes.len() && len < buf.len() {
        if i + 1 < bytes.len()
            && ((bytes[i] == b'-' && bytes[i + 1] == b'>')
                || (bytes[i] == b':' && bytes[i + 1] == b':'))
        {
            buf[len] = b'_';
            len += 1;
            i += 2;
        } else if bytes[i] == b'.' {
            buf[len] = b'_';
            len += 1;
            i += 1;
        } else {
            buf[len] = bytes[i].to_ascii_uppercase();
            len += 1;
            i += 1;
        }
    }
    std::str::from_utf8(&buf[..len]).unwrap_or("")
}

fn split_periph_reg_array(s: &str) -> [Option<(&str, &str)>; 2] {
    let trimmed = s.trim().trim_start_matches('_');
    if let Some(pair) = trimmed
        .split_once("->")
        .or_else(|| trimmed.split_once('.'))
        .or_else(|| trimmed.split_once("::"))
    {
        return [Some(pair), None];
    }
    let first = trimmed.split_once('_');
    let last = trimmed.rsplit_once('_').filter(|&l| Some(l) != first);
    [first, last]
}

fn strip_periph_instance_slice(tok: &str) -> &str {
    if tok.len() >= 4 && tok.ends_with(['X', 'x']) {
        return &tok[..tok.len() - 1];
    }
    if tok.len() == 5
        && tok[..4].eq_ignore_ascii_case("GPIO")
        && tok.as_bytes()[4].is_ascii_alphabetic()
    {
        return &tok[..4];
    }
    let trimmed = tok.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.len() >= 3 {
        trimmed
    } else {
        tok
    }
}

fn periph_stems_compatible(a: &str, b: &str) -> bool {
    let a_trim = a.trim().trim_start_matches('_');
    let b_trim = b.trim().trim_start_matches('_');
    if a_trim.eq_ignore_ascii_case(b_trim) {
        return true;
    }
    let sa = strip_periph_instance_slice(a_trim);
    let sb = strip_periph_instance_slice(b_trim);
    sa.len() >= 3
        && sa.eq_ignore_ascii_case(sb)
        && (a_trim.len() == sa.len()
            || b_trim.len() == sb.len()
            || a_trim.ends_with(['x', 'X'])
            || b_trim.ends_with(['x', 'X']))
}

/// Caches `source_root` per bundle and file line vectors across hits within a single query
/// so `--show` never re-reads `meta.json` or the same source file multiple times (Issue #43).
#[derive(Default)]
struct SourceSnippetCache {
    roots: FxHashMap<PathBuf, PathBuf>,
    files: FxHashMap<PathBuf, Vec<String>>,
}

impl SourceSnippetCache {
    fn read_snippet(
        &mut self,
        bundle_dir: &Path,
        rel_file: &str,
        start_line: usize,
        end_line: usize,
    ) -> Option<String> {
        let root_path = if let Some(r) = self.roots.get(bundle_dir) {
            r.clone()
        } else {
            let meta = load_meta_file(bundle_dir)?;
            let r = PathBuf::from(meta.metadata.source_root);
            self.roots.insert(bundle_dir.to_path_buf(), r.clone());
            r
        };

        let full_path = if root_path.join(rel_file).is_file() {
            root_path.join(rel_file)
        } else if Path::new(rel_file).is_file() {
            PathBuf::from(rel_file)
        } else {
            return None;
        };

        if !self.files.contains_key(&full_path) {
            let content = fs::read_to_string(&full_path).ok()?;
            let lines: Vec<String> = content.lines().map(ToOwned::to_owned).collect();
            self.files.insert(full_path.clone(), lines);
        }
        let all_lines = self.files.get(&full_path)?;
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
}

fn is_valid_bundle_dir(dir: &Path) -> bool {
    dir.is_dir()
        && ((dir.join("meta.json").is_file()
            && (dir.join("INDEX.md").is_file()
                || dir.join("index").is_dir()
                || dir.join("sections").is_dir()
                || dir.join("cache").is_dir()))
            || (dir.join("INDEX.md").is_file()
                && dir.join("index").is_dir()
                && dir.join("cache").is_dir()))
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

/// Executes a structured JSON query for `subcommand` (`sym`, `callers`, `callees`, `type`,
/// `macro`, `section`, `xref`, `path`, `impact`) across `bundles`.
pub fn query_subcommand_json(
    subcommand: &str,
    bundles: &[PathBuf],
    query: &str,
    secondary_query: Option<&str>,
    kind_filter: Option<&str>,
    max_depth: usize,
    limit: usize,
) -> Result<String> {
    let q_trim = query.trim();
    let q_lower = q_trim.to_ascii_lowercase();

    match subcommand {
        "sym" => {
            let kind_lower = kind_filter.map(|k| k.trim().to_ascii_lowercase());
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "symbols.tsv")?;
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
                        if !kind.eq_ignore_ascii_case(kf)
                            && !kind.to_ascii_lowercase().starts_with(kf)
                        {
                            continue;
                        }
                    }
                    let id_view = parse_symbol_id(symbol_id);
                    let name_lower = name.to_ascii_lowercase();
                    let scoped_lower = id_view.scoped.to_ascii_lowercase();
                    let sig_lower = cols[7].to_ascii_lowercase();
                    let targets_file = query_targets_file(q_trim);
                    let score = if q_lower.is_empty() {
                        1u8
                    } else if name == q_trim
                        || id_view.scoped == q_trim
                        || id_view.short == q_trim
                        || symbol_id == q_trim
                    {
                        5
                    } else if name_lower == q_lower
                        || scoped_lower == q_lower
                        || id_view.short.eq_ignore_ascii_case(q_trim)
                        || (targets_file && symbol_id.eq_ignore_ascii_case(q_trim))
                    {
                        4
                    } else if name_lower.starts_with(&q_lower)
                        || scoped_lower.ends_with(&format!("::{q_lower}"))
                        || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
                    {
                        3
                    } else if name_lower.contains(&q_lower)
                        || scoped_lower.contains(&q_lower)
                        || sig_lower.contains(&q_lower)
                    {
                        2
                    } else {
                        0
                    };
                    if score == 0 {
                        continue;
                    }
                    items.push((
                        score,
                        serde_json::json!({
                            "bundle": bundle_name,
                            "symbol_id": symbol_id,
                            "name": name,
                            "kind": kind,
                            "visibility": cols[3],
                            "file": cols[4],
                            "start_line": cols[5].parse::<usize>().unwrap_or(1),
                            "end_line": cols[6].parse::<usize>().unwrap_or(1),
                            "signature": cols[7],
                            "pagerank": cols[8].parse::<f64>().unwrap_or(0.0),
                            "in_degree": cols[9].parse::<usize>().unwrap_or(0),
                            "out_degree": cols[10].parse::<usize>().unwrap_or(0),
                            "arch_layer": cols[11],
                            "scope": cols[12],
                            "section_id": cols[13],
                            "doc_summary": cols.get(14).copied().unwrap_or(""),
                            "hub_score": cols.get(15).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0),
                            "authority_score": cols.get(16).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0),
                        }),
                    ));
                }
            }
            if items.iter().any(|(s, _)| *s >= 4) {
                items.retain(|(s, _)| *s >= 3);
            }
            items.sort_by_key(|a| std::cmp::Reverse(a.0));
            let out: Vec<serde_json::Value> =
                items.into_iter().take(limit).map(|(_, v)| v).collect();
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string()))
        }
        "callers" | "callees" => {
            let is_callers = subcommand == "callers";
            let has_exact_sym = bundles_have_exact_symbol(bundles, q_trim, &q_lower)?;
            let suffix = format!("::{q_lower}");
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "calls.tsv")?;
                let bundle_name = bundle_name_from_dir(bundle_dir);
                for line in content.lines().skip(1) {
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() < 8 {
                        continue;
                    }
                    let (target_name, target_id) = if is_callers {
                        (cols[2], cols[3])
                    } else {
                        (cols[1], cols[0])
                    };
                    let id_view = parse_symbol_id(target_id);
                    let t_lower = target_name.to_ascii_lowercase();
                    let scoped_lower = id_view.scoped.to_ascii_lowercase();
                    let targets_file = query_targets_file(q_trim);
                    let score = if target_name == q_trim
                        || id_view.scoped == q_trim
                        || id_view.short == q_trim
                        || target_id == q_trim
                    {
                        4u8
                    } else if t_lower == q_lower
                        || scoped_lower == q_lower
                        || id_view.short.eq_ignore_ascii_case(q_trim)
                        || scoped_lower.ends_with(&suffix)
                        || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
                    {
                        3
                    } else if !has_exact_sym
                        && (t_lower.contains(&q_lower) || scoped_lower.contains(&q_lower))
                    {
                        2
                    } else {
                        0
                    };
                    if score == 0 {
                        continue;
                    }
                    items.push((
                        score,
                        serde_json::json!({
                            "bundle": bundle_name,
                            "caller_id": cols[0],
                            "caller_name": cols[1],
                            "callee_name": cols[2],
                            "callee_id": cols[3],
                            "file": cols[4],
                            "line": cols[5].parse::<usize>().unwrap_or(1),
                            "tier": cols[6],
                            "section_id": cols[7],
                        }),
                    ));
                }
            }
            if items.iter().any(|(s, _)| *s >= 3) {
                items.retain(|(s, _)| *s >= 3);
            }
            items.sort_by_key(|a| std::cmp::Reverse(a.0));
            let out: Vec<serde_json::Value> =
                items.into_iter().take(limit).map(|(_, v)| v).collect();
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string()))
        }
        "type" => {
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "types.tsv")?;
                let bundle_name = bundle_name_from_dir(bundle_dir);
                for line in content.lines().skip(1) {
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() < 11 {
                        continue;
                    }
                    let type_id = cols[0];
                    let name = cols[1];
                    let fields = cols[7];
                    let id_view = parse_symbol_id(type_id);
                    let name_lower = name.to_ascii_lowercase();
                    let scoped_lower = id_view.scoped.to_ascii_lowercase();
                    let fields_lower = fields.to_ascii_lowercase();
                    let targets_file = query_targets_file(q_trim);
                    let score = if q_lower.is_empty() {
                        1u8
                    } else if name == q_trim || id_view.scoped == q_trim || type_id == q_trim {
                        5
                    } else if name_lower == q_lower
                        || scoped_lower == q_lower
                        || (targets_file && type_id.eq_ignore_ascii_case(q_trim))
                    {
                        4
                    } else if name_lower.starts_with(&q_lower)
                        || (targets_file && id_view.file.to_ascii_lowercase().contains(&q_lower))
                    {
                        3
                    } else if name_lower.contains(&q_lower)
                        || scoped_lower.contains(&q_lower)
                        || fields_lower.contains(&q_lower)
                    {
                        2
                    } else {
                        0
                    };
                    if score == 0 {
                        continue;
                    }
                    items.push((
                        score,
                        serde_json::json!({
                            "bundle": bundle_name,
                            "type_id": type_id,
                            "name": name,
                            "kind": cols[2],
                            "visibility": cols[3],
                            "file": cols[4],
                            "start_line": cols[5].parse::<usize>().unwrap_or(1),
                            "end_line": cols[6].parse::<usize>().unwrap_or(1),
                            "fields_summary": fields,
                            "arch_layer": cols[8],
                            "scope": cols[9],
                            "section_id": cols[10],
                            "doc_summary": cols.get(11).copied().unwrap_or(""),
                        }),
                    ));
                }
            }
            if items.iter().any(|(s, _)| *s >= 4) {
                items.retain(|(s, _)| *s >= 3);
            }
            items.sort_by_key(|a| std::cmp::Reverse(a.0));
            let out: Vec<serde_json::Value> =
                items.into_iter().take(limit).map(|(_, v)| v).collect();
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string()))
        }
        "macro" => {
            let q_hw = QueryHw::new(q_trim);
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "macros.tsv")?;
                let bundle_name = bundle_name_from_dir(bundle_dir);
                for line in content.lines().skip(1) {
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() < 10 {
                        continue;
                    }
                    let name = cols[0];
                    let val = cols[2];
                    let hex_col = cols[3];
                    let desc = cols[9];
                    let row_hex = if hex_col != "-" && !hex_col.is_empty() {
                        normalize_hex_literal(hex_col)
                    } else {
                        normalize_hex_literal(val)
                    };
                    let hex_exact = match (&q_hw.hex, &row_hex) {
                        (Some(qh), Some(rh)) => qh.eq_ignore_ascii_case(rh),
                        _ => false,
                    };
                    let score = if hex_exact {
                        5u8
                    } else if q_hw.is_hex {
                        0
                    } else {
                        let id_score = score_hw_identifier_match_prepared(name, &q_hw);
                        let val_score = if !q_lower.is_empty()
                            && (ascii_contains_ignore_case(val.as_bytes(), q_lower.as_bytes())
                                || ascii_contains_ignore_case(desc.as_bytes(), q_lower.as_bytes()))
                        {
                            1
                        } else {
                            0
                        };
                        id_score.max(val_score)
                    };
                    if score == 0 {
                        continue;
                    }
                    items.push((
                        score,
                        serde_json::json!({
                            "bundle": bundle_name,
                            "name": name,
                            "kind": cols[1],
                            "value": val,
                            "hex_addr": hex_col,
                            "file": cols[4],
                            "line": cols[5].parse::<usize>().unwrap_or(1),
                            "arch_layer": cols[6],
                            "scope": cols[7],
                            "section_id": cols[8],
                            "description": desc,
                        }),
                    ));
                }
            }
            if items.iter().any(|(s, _)| *s >= 3) {
                items.retain(|(s, _)| *s >= 2);
            }
            items.sort_by_key(|a| std::cmp::Reverse(a.0));
            let out: Vec<serde_json::Value> =
                items.into_iter().take(limit).map(|(_, v)| v).collect();
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string()))
        }
        "section" => {
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "sections.tsv")?;
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
                        1u8
                    } else if sec_lower == q_lower || mod_lower == q_lower || layer_lower == q_lower
                    {
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
                    items.push((
                        score,
                        section_id.to_string(),
                        serde_json::json!({
                            "bundle": bundle_name,
                            "section_id": section_id,
                            "title": title,
                            "module_path": module_path,
                            "arch_layer": arch_layer,
                            "scope": scope,
                            "file_count": cols[5].parse::<usize>().unwrap_or(0),
                            "symbol_count": cols[6].parse::<usize>().unwrap_or(0),
                            "type_count": cols[7].parse::<usize>().unwrap_or(0),
                            "macro_count": cols[8].parse::<usize>().unwrap_or(0),
                            "token_estimate": cols[9].parse::<usize>().unwrap_or(0),
                            "markdown_file": cols[10],
                        }),
                    ));
                }
            }
            items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            let out: Vec<serde_json::Value> =
                items.into_iter().take(limit).map(|(_, _, v)| v).collect();
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string()))
        }
        "xref" => {
            let q_hw = QueryHw::new(q_trim);
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "xref.tsv")?;
                let bundle_name = bundle_name_from_dir(bundle_dir);
                for line in content.lines().skip(1) {
                    if !q_hw.is_hex
                        && !q_hw.fast_prefix.is_empty()
                        && !ascii_contains_ignore_case(line.as_bytes(), q_hw.fast_prefix.as_bytes())
                    {
                        continue;
                    }
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() < 8 {
                        continue;
                    }
                    let sym = cols[0];
                    let target = cols[3];
                    let context = cols[7];
                    let hex_match = match &q_hw.hex {
                        Some(qh) => {
                            normalize_hex_literal(sym).is_some_and(|sh| sh.eq_ignore_ascii_case(qh))
                                || normalize_hex_literal(target)
                                    .is_some_and(|th| th.eq_ignore_ascii_case(qh))
                                || normalize_hex_literal(context)
                                    .is_some_and(|ch| ch.eq_ignore_ascii_case(qh))
                        }
                        None => false,
                    };
                    let score = if hex_match {
                        5u8
                    } else if q_hw.is_hex {
                        0
                    } else {
                        let sym_score = score_hw_identifier_match_prepared(sym, &q_hw);
                        let target_score = score_hw_identifier_match_prepared(target, &q_hw);
                        let ctx_score = if !q_lower.is_empty()
                            && ascii_contains_ignore_case(context.as_bytes(), q_lower.as_bytes())
                        {
                            1
                        } else {
                            0
                        };
                        sym_score.max(target_score).max(ctx_score)
                    };
                    if score == 0 {
                        continue;
                    }
                    items.push((
                        score,
                        serde_json::json!({
                            "bundle": bundle_name,
                            "symbol": sym,
                            "category": cols[1],
                            "relation": cols[2],
                            "target": target,
                            "file": cols[4],
                            "line": cols[5].parse::<usize>().unwrap_or(1),
                            "section_id": cols[6],
                            "context": context,
                        }),
                    ));
                }
            }
            if items.iter().any(|(s, _)| *s >= 3) {
                items.retain(|(s, _)| *s >= 2);
            }
            items.sort_by_key(|a| std::cmp::Reverse(a.0));
            let out: Vec<serde_json::Value> =
                items.into_iter().take(limit).map(|(_, v)| v).collect();
            Ok(serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string()))
        }
        "path" => {
            let to_q = secondary_query.unwrap_or("");
            let text = query_call_path(bundles, query, to_q, max_depth)?;
            let found = !text.starts_with("No call path found");
            let payload = serde_json::json!({
                "from": query,
                "to": to_q,
                "max_depth": max_depth,
                "found": found,
                "summary": text.trim(),
            });
            Ok(serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()))
        }
        "impact" => {
            let text = query_impact(bundles, query, max_depth, limit)?;
            let found = !text.starts_with("No symbol or call edges matched");
            let payload = serde_json::json!({
                "symbol": query,
                "max_depth": max_depth,
                "found": found,
                "summary": text.trim(),
            });
            Ok(serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()))
        }
        _ => Ok("[]".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BundleMetaFile, RepoMetadata, SanityReport, VendorMode};

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("chipsrc_query_{label}_{}", std::process::id()));
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
    fn test_hw_identifier_and_hex_matching() {
        assert_eq!(score_hw_identifier_match("GPIOA->MODER", "GPIOA_MODER"), 4);
        assert_eq!(score_hw_identifier_match("GPIOA_MODER", "GPIOA.MODER"), 4);
        assert_eq!(score_hw_identifier_match("GPIOA->MODER", "GPIOA"), 3);
        assert_eq!(score_hw_identifier_match("GPIOx_MODER", "GPIOA->MODER"), 3);
        assert_eq!(score_hw_identifier_match("GPIOZ_MODER", "GPIOx->MODER"), 3);
        assert_eq!(
            score_hw_identifier_match("__HAL_TIM_GET_COUNTER", "HAL_TIM_GET_COUNTER"),
            4
        );
        assert_eq!(score_hw_identifier_match("TIM1->CCR1", "UART0_DR"), 0);
    }

    #[test]
    fn test_query_symbols_macros_and_parallel_search_with_show() {
        let tmp = TestTempDir::new("main");
        let src_dir = tmp.0.join("src");
        let bundle_dir = tmp.0.join("output").join("demo");
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
                source_root: tmp.0.display().to_string(),
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

        let syms_tsv = "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\tdoc_summary\n\
src/drv.c::lock_actuator\tlock_actuator\tfn\tpub\tsrc/drv.c\t2\t4\tvoid lock_actuator(int id)\t0.500000\t1\t0\tdrvs\tfirst_party\t01-src\tLocks the actuator.\n";
        fs::write(index_dir.join("symbols.tsv"), syms_tsv).unwrap();

        let macros_tsv = "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription\n\
REG_CTRL\tmmio_addr\t0x41C00004UL\t0x41C00004\tsrc/drv.c\t1\tdrvs\tfirst_party\t01-src\tMMIO register\n\
MASK_ALL\tbitmask\t0xFFFFFFFFUL\t0xFFFFFFFF\tsrc/drv.c\t1\tdrvs\tfirst_party\t01-src\tAll bits\n\
GPIOA->MODER\treg_access\tGPIOA->MODER = id;\t-\tsrc/drv.c\t3\tdrvs\tfirst_party\t01-src\tRegister access\n";
        fs::write(index_dir.join("macros.tsv"), macros_tsv).unwrap();
        fs::write(
            index_dir.join("types.tsv"),
            "type_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tfields_summary\tarch_layer\tscope\tsection_id\tdoc_summary\n",
        )
        .unwrap();
        fs::write(
            index_dir.join("calls.tsv"),
            "caller_id\tcaller_name\tcallee_name\tcallee_id\tfile\tline\ttier\tsection_id\n",
        )
        .unwrap();
        fs::write(
            index_dir.join("sections.tsv"),
            "section_id\ttitle\tmodule_path\tarch_layer\tscope\tfile_count\tsymbol_count\ttype_count\tmacro_count\ttoken_estimate\tmd_file\n",
        )
        .unwrap();
        fs::write(
            index_dir.join("xref.tsv"),
            "symbol\tcategory\trelation\ttarget\tfile\tline\tsection_id\tcontext\n",
        )
        .unwrap();

        let bundles = resolve_bundles(&bundle_dir).unwrap();
        assert_eq!(bundles.len(), 1);

        // Non-existent multi-segment path must return BundleNotFound (Issue #23)
        assert!(resolve_bundles(Path::new("nonexistent_dir/demo")).is_err());

        let sym_out = query_symbols(&bundles, "lock_actuator", None, true, 10).unwrap();
        assert!(sym_out.contains("void lock_actuator(int id)"));
        assert!(sym_out.contains("doc: Locks the actuator."));
        assert!(sym_out.contains("GPIOA->MODER = id;"));

        let mac_hex_out = query_macros(&bundles, "41C00004h", false, 10).unwrap();
        assert!(mac_hex_out.contains("REG_CTRL"));

        // Exact hex query `0xFF` or `FFh` must NOT substring-match `0xFFFFFFFF` (Issue #9)
        let mac_ff_out = query_macros(&bundles, "FFh", false, 10).unwrap();
        assert!(!mac_ff_out.contains("MASK_ALL"));

        let mac_periph_out = query_macros(&bundles, "GPIOA_MODER", false, 10).unwrap();
        assert!(mac_periph_out.contains("GPIOA->MODER"));

        let hits = parallel_bundle_search(&bundles, "lock_actuator", "all", false, 10).unwrap();
        assert!(!hits.is_empty());

        // Literal search with unclosed regex parenthesis must not fail (Issue #28)
        let paren_hits =
            parallel_bundle_search(&bundles, "lock_actuator(", "source", false, 10).unwrap();
        assert!(!paren_hits.is_empty());
    }
}
