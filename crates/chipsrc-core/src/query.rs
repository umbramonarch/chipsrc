use crate::error::{ChipsrcError, Result};
use crate::mmio::{normalize_hex_literal, normalize_query_hex_literal};
use crate::model::{
    BundleStatusEntry, LanguageKind, SearchHit, CACHE_SCHEMA_VERSION, DEFAULT_MAX_FILE_BYTES,
};
use crate::scanner::{
    canonical_repo_root_and_name, check_files_changed, check_meta_files_changed,
    first_missing_bundle_artifact_with, has_valid_tsv_header, load_cache_file_from_manifest,
    load_cache_manifest_any_version, load_meta_file, scan_repository, BundleArtifactSources,
};
use memchr::memmem;
use rayon::prelude::*;
use regex::RegexBuilder;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

/// Resolves target into one or more indexed bundle directories.
pub fn resolve_bundles(target: &Path) -> Result<Vec<PathBuf>> {
    resolve_bundles_internal(target, true)
}

/// Discovers all indexed bundles under workspace without filtering to a single source root.
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

/// Resolves positional CLI target_or_query and optional query into bundles and query string.
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

/// Structured zero-copy view of a canonical symbol ID.
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

/// Splits a canonical symbol or type ID into file, scoped, and short components.
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

/// Returns true when query explicitly targets a file path.
pub fn query_targets_file(q: &str) -> bool {
    let t = q.trim();
    t.contains('/')
        || t.contains('\\')
        || t.rsplit_once('.')
            .is_some_and(|(_, ext)| LanguageKind::from_extension(ext).is_some())
}

/// Scans workspace for indexed bundles and checks live freshness against source files.
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
        let meta_file_opt = load_meta_file(&bundle_dir);
        let manifest = load_cache_manifest_any_version(&bundle_dir);
        let missing_artifact = first_missing_bundle_artifact_with(
            &bundle_dir,
            BundleArtifactSources {
                meta: meta_file_opt.as_ref(),
                manifest: manifest
                    .as_ref()
                    .filter(|m| m.schema_version == CACHE_SCHEMA_VERSION),
                meta_attempted: true,
                manifest_attempted: true,
            },
        );
        let has_valid_cache = manifest
            .as_ref()
            .is_some_and(|m| m.schema_version == CACHE_SCHEMA_VERSION && !m.files.is_empty());
        let Some(meta_file) = meta_file_opt else {
            let bundle_name = bundle_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("bundle")
                .to_string();
            let source_root = manifest
                .as_ref()
                .map(|m| m.repo_root.clone())
                .unwrap_or_default();
            let total_files = manifest.as_ref().map(|m| m.files.len().max(1)).unwrap_or(1);
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
            if !has_valid_cache || meta.file_stamps.is_empty() {
                meta.total_files.max(1)
            } else if let Some(count) =
                check_meta_files_changed(source_path, &meta, DEFAULT_MAX_FILE_BYTES)
            {
                count
            } else if let Some(cache) = manifest
                .as_ref()
                .filter(|m| m.schema_version == CACHE_SCHEMA_VERSION)
                .and_then(|m| load_cache_file_from_manifest(&bundle_dir, m))
            {
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
        } else if !has_valid_cache {
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

/// Loads a required TSV table from bundle_dir, returning an error if missing or invalid.
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

fn load_index_table_bytes(bundle_dir: &Path, name: &str) -> Result<Vec<u8>> {
    let rel = if name.starts_with("index/") {
        name.to_string()
    } else {
        format!("index/{name}")
    };
    let path = bundle_dir.join(&rel);
    let incomplete = || ChipsrcError::IncompleteBundle {
        bundle: bundle_dir.to_path_buf(),
        missing: rel.clone(),
    };
    let bytes = fs::read(&path).map_err(|_| incomplete())?;
    let first_end = memchr::memchr(b'\n', &bytes).unwrap_or(bytes.len());
    let first = &bytes[..first_end];
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    match std::str::from_utf8(first) {
        Ok(header) if has_valid_tsv_header(&rel, header) => Ok(bytes),
        _ => Err(incomplete()),
    }
}

/// Queries functions, methods, constructors, entrypoints, and ISRs across bundles.
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

    let colon_suffix = format!("::{q_lower}");
    let targets_file = query_targets_file(q_trim);

    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "symbols.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            if !q_lower.is_empty()
                && !ascii_contains_ignore_case(line.as_bytes(), q_lower.as_bytes())
            {
                continue;
            }
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
            } else if scoped_lower.ends_with(&colon_suffix)
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

/// Queries all static callers of symbol across bundles.
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

/// Queries all static callees invoked by symbol across bundles.
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

/// Queries structs, enums, unions, traits, interfaces, classes, and typedefs across bundles.
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

    let targets_file = query_targets_file(q_trim);

    for bundle_dir in bundles {
        let content = load_index_table(bundle_dir, "types.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);

        for line in content.lines().skip(1) {
            if !q_lower.is_empty()
                && !ascii_contains_ignore_case(line.as_bytes(), q_lower.as_bytes())
            {
                continue;
            }
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

struct MacroRow {
    bundle_dir: PathBuf,
    bundle_name: String,
    score: u8,
    file: String,
    line: usize,
    raw: String,
}

impl MacroRow {
    #[inline]
    fn field(&self, idx: usize) -> &str {
        self.raw.split('\t').nth(idx).unwrap_or("")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MacroScanMode {
    Strong,
    Full,
}

fn collect_macro_rows(bundles: &[PathBuf], query: &str) -> Result<Vec<MacroRow>> {
    let q_trim = query.trim();
    let q_lower = q_trim.to_ascii_lowercase();
    let q_hw = QueryHw::new(q_trim);

    let mut hits = scan_macro_rows(bundles, &q_hw, &q_lower, MacroScanMode::Strong)?;
    let has_strong = hits.iter().any(|h| h.score >= 3);
    if q_hw.is_hex || has_strong {
        if has_strong {
            hits.retain(|h| h.score >= 2);
        }
        return Ok(hits);
    }
    scan_macro_rows(bundles, &q_hw, &q_lower, MacroScanMode::Full)
}

const MACRO_PARALLEL_SCAN_BYTES: usize = 4 * 1024 * 1024;

const MACRO_SCAN_CHUNKS: usize = 8;

fn scan_macro_rows(
    bundles: &[PathBuf],
    q_hw: &QueryHw<'_>,
    q_lower: &str,
    mode: MacroScanMode,
) -> Result<Vec<MacroRow>> {
    let prefilter = MacroRowPrefilter::new(q_hw, mode);
    let mut hits = Vec::new();

    for bundle_dir in bundles {
        let content = load_index_table_bytes(bundle_dir, "macros.tsv")?;
        let bundle_name = bundle_name_from_dir(bundle_dir);
        let body_start = memchr::memchr(b'\n', &content).map_or(content.len(), |idx| idx + 1);
        let body = &content[body_start..];
        if body.len() < MACRO_PARALLEL_SCAN_BYTES {
            scan_macro_rows_chunk(
                body,
                bundle_dir,
                &bundle_name,
                &prefilter,
                q_hw,
                q_lower,
                &mut hits,
            );
        } else {
            let parts: Vec<Vec<MacroRow>> = macro_scan_bounds(body)
                .par_iter()
                .map(|&(start, end)| {
                    let mut chunk_hits = Vec::new();
                    scan_macro_rows_chunk(
                        &body[start..end],
                        bundle_dir,
                        &bundle_name,
                        &prefilter,
                        q_hw,
                        q_lower,
                        &mut chunk_hits,
                    );
                    chunk_hits
                })
                .collect();
            for part in parts {
                hits.extend(part);
            }
        }
    }

    Ok(hits)
}

fn macro_scan_bounds(body: &[u8]) -> Vec<(usize, usize)> {
    let mut bounds: Vec<usize> = Vec::with_capacity(MACRO_SCAN_CHUNKS + 1);
    bounds.push(0);
    let target = body.len() / MACRO_SCAN_CHUNKS;
    for k in 1..MACRO_SCAN_CHUNKS {
        let pos = k * target;
        let Some(newline) = memchr::memchr(b'\n', &body[pos..]) else {
            break;
        };
        let next = pos + newline + 1;
        if next > *bounds.last().unwrap_or(&0) && next < body.len() {
            bounds.push(next);
        }
    }
    bounds.push(body.len());
    bounds.windows(2).map(|w| (w[0], w[1])).collect()
}

fn scan_macro_rows_chunk(
    chunk: &[u8],
    bundle_dir: &Path,
    bundle_name: &str,
    prefilter: &MacroRowPrefilter,
    q_hw: &QueryHw<'_>,
    q_lower: &str,
    hits: &mut Vec<MacroRow>,
) {
    let mut line_start = 0usize;
    for newline in memchr::memchr_iter(b'\n', chunk) {
        let raw = &chunk[line_start..newline];
        push_macro_row(raw, bundle_dir, bundle_name, prefilter, q_hw, q_lower, hits);
        line_start = newline + 1;
    }
    if line_start < chunk.len() {
        push_macro_row(
            &chunk[line_start..],
            bundle_dir,
            bundle_name,
            prefilter,
            q_hw,
            q_lower,
            hits,
        );
    }
}

fn push_macro_row(
    raw: &[u8],
    bundle_dir: &Path,
    bundle_name: &str,
    prefilter: &MacroRowPrefilter,
    q_hw: &QueryHw<'_>,
    q_lower: &str,
    hits: &mut Vec<MacroRow>,
) {
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    if raw.is_empty() || !prefilter.may_match(raw) {
        return;
    }
    let Ok(line) = std::str::from_utf8(raw) else {
        return;
    };
    let mut cols = line.split('\t');
    let (Some(name), Some(_kind), Some(val), Some(hex_col)) =
        (cols.next(), cols.next(), cols.next(), cols.next())
    else {
        return;
    };
    let (Some(file), Some(line_no), Some(_arch_layer), Some(_scope), Some(_section_id)) = (
        cols.next(),
        cols.next(),
        cols.next(),
        cols.next(),
        cols.next(),
    ) else {
        return;
    };
    let Some(desc) = cols.next() else {
        return;
    };
    let score = score_macro_row(name, val, hex_col, desc, q_hw, q_lower);
    if score == 0 {
        return;
    }
    hits.push(MacroRow {
        bundle_dir: bundle_dir.to_path_buf(),
        bundle_name: bundle_name.to_string(),
        score,
        file: file.to_string(),
        line: line_no.parse().unwrap_or(1),
        raw: line.to_string(),
    });
}

/// Queries macros, constants, bitmasks, and MMIO register accesses across bundles.
pub fn query_macros(
    bundles: &[PathBuf],
    query: &str,
    show_source: bool,
    limit: usize,
) -> Result<String> {
    let mut hits = collect_macro_rows(bundles, query)?;

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
    let mut snippet_cache = SourceSnippetCache::default();
    for h in hits.drain(..).take(limit) {
        let hex_addr = h.field(3);
        let hex_info = if hex_addr != "-" && !hex_addr.is_empty() {
            format!(" [hex={hex_addr}]")
        } else {
            String::new()
        };
        out.push_str(&format!(
            "[{}] `{}` ({}){} = `{}` | `{}:{}` | layer={} scope={} shard=`{}` ({})\n",
            h.bundle_name,
            h.field(0),
            h.field(1),
            hex_info,
            h.field(2),
            h.file,
            h.line,
            h.field(6),
            h.field(7),
            h.field(8),
            h.field(9)
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

/// Lists or inspects architectural module shards across bundles.
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

/// Queries the Unified Code + Hardware Cross-Reference Graph across bundles.
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

/// Computes the shortest static call path between symbols using breadth-first search.
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

/// Computes the reverse-BFS blast radius of modifying a symbol.
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

/// Parallel search across indexed bundles supporting literal, regex, source, and concept queries.
pub fn parallel_bundle_search(
    bundles: &[PathBuf],
    pattern: &str,
    kind: &str,
    ignore_case: bool,
    limit: usize,
) -> Result<Vec<SearchHit>> {
    let k = kind.trim().to_ascii_lowercase();

    if k == "concept" || k == "concepts" {
        return concept_search(bundles, pattern, limit);
    }

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

    if all_hits.is_empty() && !search_source_explicit && concept_query_terms(pattern).len() >= 2 {
        all_hits = concept_search(bundles, pattern, limit)?;
    }

    Ok(all_hits)
}

const CONCEPT_STOPWORDS: [&str; 37] = [
    "a", "an", "and", "any", "are", "as", "at", "be", "been", "but", "by", "do", "does", "for",
    "from", "if", "in", "into", "is", "it", "no", "not", "of", "on", "or", "per", "so", "such",
    "than", "that", "the", "then", "this", "to", "via", "was", "with",
];

const CONCEPT_BM25_K1: f64 = 1.2;
const CONCEPT_BM25_B: f64 = 0.75;

const CONCEPT_SNIPPET_MAX_CHARS: usize = 160;

/// Splits text into lowercase concept terms using word boundary and casing rules.
pub fn tokenize_concept(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for word in text.split(|c: char| !c.is_alphanumeric()) {
        if word.is_empty() {
            continue;
        }
        let mut chars = word.char_indices().peekable();
        let mut start = 0usize;
        let mut previous: Option<char> = None;
        while let Some((byte_idx, current)) = chars.next() {
            if let Some(prev) = previous {
                let next = chars.peek().map(|(_, next)| *next);
                let split = (prev.is_lowercase() && current.is_uppercase())
                    || (prev.is_uppercase()
                        && current.is_uppercase()
                        && next.is_some_and(char::is_lowercase));
                if split {
                    push_concept_token(&word[start..byte_idx], &mut tokens);
                    start = byte_idx;
                }
            }
            previous = Some(current);
        }
        push_concept_token(&word[start..], &mut tokens);
    }
    tokens
}

fn push_concept_token(raw: &str, out: &mut Vec<String>) {
    if raw.chars().nth(1).is_none() {
        return;
    }
    if CONCEPT_STOPWORDS
        .iter()
        .any(|stopword| raw.eq_ignore_ascii_case(stopword))
    {
        return;
    }
    out.push(stem_concept_term(raw.to_lowercase()));
}

fn stem_concept_term(mut token: String) -> String {
    for _ in 0..4 {
        match concept_suffix_keep_len(&token) {
            Some(keep) => token.truncate(keep),
            None => break,
        }
    }
    token
}

fn concept_suffix_keep_len(token: &str) -> Option<usize> {
    if token.chars().count() < 5 {
        return None;
    }
    for suffix in ["ing", "ed"] {
        if let Some(stem) = token.strip_suffix(suffix) {
            if stem.chars().count() >= 3 {
                return Some(stem.len());
            }
        }
    }
    if let Some(stem) = token.strip_suffix("es") {
        if stem.chars().count() >= 3 && ends_with_sibilant(stem) {
            return Some(stem.len());
        }
    }
    if !token.ends_with("ss") {
        if let Some(stem) = token.strip_suffix('s') {
            if stem.chars().count() >= 3 {
                return Some(stem.len());
            }
        }
    }
    None
}

fn ends_with_sibilant(stem: &str) -> bool {
    stem.ends_with('s')
        || stem.ends_with('x')
        || stem.ends_with('z')
        || stem.ends_with("ch")
        || stem.ends_with("sh")
}

fn concept_query_terms(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen: FxHashSet<String> = FxHashSet::default();
    for token in tokenize_concept(query) {
        if seen.insert(token.clone()) {
            terms.push(token);
        }
    }
    terms
}

struct ConceptDocument {
    bundle_name: String,
    kind: &'static str,
    id: String,
    file: String,
    line: usize,
    name: String,
    detail: String,
    pagerank: f64,
    terms: FxHashMap<String, f64>,
    len: f64,
}

fn push_concept_field(terms: &mut FxHashMap<String, f64>, len: &mut f64, text: &str, weight: f64) {
    if text.is_empty() {
        return;
    }
    for token in tokenize_concept(text) {
        *terms.entry(token).or_insert(0.0) += weight;
        *len += weight;
    }
}

struct ConceptRow<'a> {
    bundle_name: &'a str,
    kind: &'static str,
    id: &'a str,
    name: &'a str,
    file: &'a str,
    line: usize,
    pagerank: f64,
    primary_field: &'a str,
    doc_field: &'a str,
}

fn build_concept_document(row: ConceptRow<'_>) -> Option<ConceptDocument> {
    if row.name.is_empty() {
        return None;
    }
    let mut terms: FxHashMap<String, f64> = FxHashMap::default();
    let mut len = 0.0;
    push_concept_field(&mut terms, &mut len, row.name, 3.0);
    push_concept_field(&mut terms, &mut len, row.doc_field, 2.0);
    push_concept_field(&mut terms, &mut len, row.primary_field, 1.0);
    let file_stem = Path::new(row.file)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(row.file);
    push_concept_field(&mut terms, &mut len, file_stem, 1.0);
    if terms.is_empty() {
        return None;
    }
    let detail = if !row.primary_field.trim().is_empty() {
        row.primary_field.trim()
    } else if !row.doc_field.trim().is_empty() {
        row.doc_field.trim()
    } else {
        row.file
    };
    Some(ConceptDocument {
        bundle_name: row.bundle_name.to_string(),
        kind: row.kind,
        id: row.id.to_string(),
        file: row.file.to_string(),
        line: row.line,
        name: row.name.to_string(),
        detail: detail.to_string(),
        pagerank: row.pagerank,
        terms,
        len,
    })
}

fn concept_snippet(name: &str, detail: &str) -> String {
    let snippet = format!("{name} — {detail}");
    if snippet.chars().count() <= CONCEPT_SNIPPET_MAX_CHARS {
        return snippet;
    }
    let mut truncated: String = snippet
        .chars()
        .take(CONCEPT_SNIPPET_MAX_CHARS - 3)
        .collect();
    truncated.push_str("...");
    truncated
}

const CONCEPT_MAX_TSV_COLUMNS: usize = 17;

fn concept_row_columns(raw_line: &str) -> [&str; CONCEPT_MAX_TSV_COLUMNS] {
    let mut cols = [""; CONCEPT_MAX_TSV_COLUMNS];
    for (idx, value) in raw_line.split('\t').enumerate() {
        if idx >= cols.len() {
            break;
        }
        cols[idx] = value;
    }
    cols
}

fn collect_concept_documents(bundles: &[PathBuf]) -> Result<Vec<ConceptDocument>> {
    let mut docs = Vec::new();
    for bundle_dir in bundles {
        let bundle_name = bundle_name_from_dir(bundle_dir);

        let symbols = load_index_table(bundle_dir, "symbols.tsv")?;
        for raw_line in symbols.lines().skip(1) {
            if raw_line.trim().is_empty() {
                continue;
            }
            let cols = concept_row_columns(raw_line);
            let name = cols[1];
            if name.is_empty() {
                continue;
            }
            let id = if cols[0].is_empty() { name } else { cols[0] };
            let line = cols[5].parse::<usize>().unwrap_or(0);
            let pagerank = cols[8].parse::<f64>().unwrap_or(0.0);
            if let Some(doc) = build_concept_document(ConceptRow {
                bundle_name: &bundle_name,
                kind: "symbol",
                id,
                name,
                file: cols[4],
                line,
                pagerank,
                primary_field: cols[7],
                doc_field: cols[14],
            }) {
                docs.push(doc);
            }
        }

        let types = load_index_table(bundle_dir, "types.tsv")?;
        for raw_line in types.lines().skip(1) {
            if raw_line.trim().is_empty() {
                continue;
            }
            let cols = concept_row_columns(raw_line);
            let name = cols[1];
            if name.is_empty() {
                continue;
            }
            let id = if cols[0].is_empty() { name } else { cols[0] };
            let line = cols[5].parse::<usize>().unwrap_or(0);
            if let Some(doc) = build_concept_document(ConceptRow {
                bundle_name: &bundle_name,
                kind: "type",
                id,
                name,
                file: cols[4],
                line,
                pagerank: 0.0,
                primary_field: cols[7],
                doc_field: cols[11],
            }) {
                docs.push(doc);
            }
        }

        let macros = load_index_table(bundle_dir, "macros.tsv")?;
        for raw_line in macros.lines().skip(1) {
            if raw_line.trim().is_empty() {
                continue;
            }
            let cols = concept_row_columns(raw_line);
            let name = cols[0];
            if name.is_empty() {
                continue;
            }
            let line = cols[5].parse::<usize>().unwrap_or(0);
            if let Some(doc) = build_concept_document(ConceptRow {
                bundle_name: &bundle_name,
                kind: "macro",
                id: name,
                name,
                file: cols[4],
                line,
                pagerank: 0.0,
                primary_field: cols[2],
                doc_field: cols[9],
            }) {
                docs.push(doc);
            }
        }
    }
    Ok(docs)
}

/// Deterministic BM25 concept search over the symbol, type, and macro tables of every bundle.
pub fn concept_search(bundles: &[PathBuf], query: &str, limit: usize) -> Result<Vec<SearchHit>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let query_terms = concept_query_terms(query);
    if query_terms.is_empty() {
        return Ok(Vec::new());
    }
    let documents = collect_concept_documents(bundles)?;
    if documents.is_empty() {
        return Ok(Vec::new());
    }
    let doc_count = documents.len() as f64;
    let total_len: f64 = documents.iter().map(|doc| doc.len).sum();
    if total_len <= 0.0 {
        return Ok(Vec::new());
    }
    let avg_len = total_len / doc_count;

    let mut doc_freq: FxHashMap<&str, usize> = FxHashMap::default();
    for term in &query_terms {
        let freq = documents
            .iter()
            .filter(|doc| doc.terms.contains_key(term.as_str()))
            .count();
        doc_freq.insert(term.as_str(), freq);
    }

    let mut scored: Vec<(f64, &ConceptDocument)> = Vec::new();
    for doc in &documents {
        let mut score = 0.0_f64;
        let mut matched = 0usize;
        for term in &query_terms {
            let Some(&freq) = doc_freq.get(term.as_str()) else {
                continue;
            };
            if freq == 0 {
                continue;
            }
            let idf = (1.0 + (doc_count - freq as f64 + 0.5) / (freq as f64 + 0.5)).ln();
            if idf <= 0.0 {
                continue;
            }
            let tf = doc.terms.get(term.as_str()).copied().unwrap_or(0.0);
            if tf <= 0.0 {
                continue;
            }
            matched += 1;
            let norm =
                CONCEPT_BM25_K1 * (1.0 - CONCEPT_BM25_B + CONCEPT_BM25_B * (doc.len / avg_len));
            score += idf * (tf * (CONCEPT_BM25_K1 + 1.0)) / (tf + norm);
        }
        if matched == 0 {
            continue;
        }
        let coverage = matched as f64 / query_terms.len() as f64;
        score *= coverage * coverage;
        if score > 0.0 {
            scored.push((score, doc));
        }
    }

    scored.sort_by(|(score_a, doc_a), (score_b, doc_b)| {
        score_b
            .total_cmp(score_a)
            .then_with(|| doc_b.pagerank.total_cmp(&doc_a.pagerank))
            .then_with(|| doc_a.id.cmp(&doc_b.id))
            .then_with(|| doc_a.bundle_name.cmp(&doc_b.bundle_name))
            .then_with(|| doc_a.file.cmp(&doc_b.file))
            .then_with(|| doc_a.line.cmp(&doc_b.line))
    });

    let mut seen_coords: FxHashSet<(String, &'static str, String, usize)> = FxHashSet::default();
    let mut hits = Vec::new();
    for (_, doc) in scored {
        if hits.len() >= limit {
            break;
        }
        if !seen_coords.insert((
            doc.bundle_name.clone(),
            doc.kind,
            doc.file.clone(),
            doc.line,
        )) {
            continue;
        }
        hits.push(SearchHit {
            bundle_name: doc.bundle_name.clone(),
            kind: doc.kind.to_string(),
            file: doc.file.clone(),
            line: doc.line,
            snippet: concept_snippet(&doc.name, &doc.detail),
        });
    }
    Ok(hits)
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
    for i in memchr::memchr2_iter(first_lo, first_hi, haystack) {
        if i > max_start {
            return false;
        }
        if haystack[i..i + nlen].eq_ignore_ascii_case(needle_upper_or_lower) {
            return true;
        }
    }
    false
}

fn last_alnum_run(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 && !bytes[end - 1].is_ascii_alphanumeric() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
        start -= 1;
    }
    Some(&s[start..end])
}

fn line_contains_hex_digits(haystack: &[u8], digits: &[u8]) -> bool {
    if digits.is_empty() {
        return true;
    }
    let first = digits[0];
    let first_lo = first.to_ascii_lowercase();
    let first_hi = first.to_ascii_uppercase();
    'candidates: for start in memchr::memchr2_iter(first_lo, first_hi, haystack) {
        let mut j = start;
        let mut k = 0usize;
        while k < digits.len() && j < haystack.len() {
            let b = haystack[j];
            if b == b'_' {
                j += 1;
                continue;
            }
            if !b.is_ascii_hexdigit() || b.to_ascii_uppercase() != digits[k] {
                continue 'candidates;
            }
            k += 1;
            j += 1;
        }
        if k == digits.len() {
            return true;
        }
    }
    false
}

struct MacroRowPrefilter {
    name_needles: Vec<Vec<u8>>,
    value_needle: Option<Vec<u8>>,
    hex_digits: Option<Vec<u8>>,
    hex_only: bool,
}

impl MacroRowPrefilter {
    fn new(q: &QueryHw<'_>, mode: MacroScanMode) -> Self {
        let mut name_needles: Vec<Vec<u8>> = Vec::with_capacity(3);
        let mut push = |needle: &str| {
            if needle.is_empty() {
                return;
            }
            let lower = needle.to_ascii_lowercase();
            let bytes = lower.into_bytes();
            if !name_needles.contains(&bytes) {
                name_needles.push(bytes);
            }
        };
        push(q.raw);
        let normalized = q.raw.trim().trim_start_matches('_');
        push(normalized);
        let stem = strip_periph_instance_slice(normalized);
        if stem.len() >= 3 {
            push(stem);
        }
        for (_periph, reg) in q.splits.into_iter().flatten() {
            push(reg);
            if let Some(last) = last_alnum_run(reg) {
                push(last);
            }
        }
        if let Some(last) = last_alnum_run(normalized) {
            push(last);
        }
        name_needles.sort_by_key(|n| std::cmp::Reverse(n.len()));

        let hex_digits = q.hex.as_deref().and_then(|hex| {
            let body = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X"))?;
            let digits: Vec<u8> = body
                .bytes()
                .filter(|b| *b != b'_')
                .map(|b| b.to_ascii_uppercase())
                .collect();
            if digits.is_empty() || !body.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_') {
                None
            } else {
                Some(digits)
            }
        });

        let value_needle = (mode == MacroScanMode::Full && !q.raw.is_empty())
            .then(|| q.raw.to_ascii_lowercase().into_bytes());

        Self {
            hex_only: q.is_hex && hex_digits.is_some(),
            name_needles,
            value_needle,
            hex_digits,
        }
    }

    #[inline]
    fn may_match(&self, line: &[u8]) -> bool {
        if self.hex_only {
            return self
                .hex_digits
                .as_deref()
                .is_some_and(|d| line_contains_hex_digits(line, d));
        }
        let name_end = memchr::memchr(b'\t', line).unwrap_or(line.len());
        let (name, rest) = line.split_at(name_end);
        if self
            .name_needles
            .iter()
            .any(|needle| ascii_contains_ignore_case(name, needle))
        {
            return true;
        }
        if let Some(needle) = self.value_needle.as_deref() {
            if ascii_contains_ignore_case(rest, needle) {
                return true;
            }
        }
        self.hex_digits
            .as_deref()
            .is_some_and(|d| line_contains_hex_digits(rest, d))
    }
}

#[inline]
fn score_macro_row(
    name: &str,
    val: &str,
    hex_col: &str,
    desc: &str,
    q: &QueryHw<'_>,
    q_lower: &str,
) -> u8 {
    let hex_exact = if q.hex.is_some() {
        let row_hex = if hex_col != "-" && !hex_col.is_empty() {
            normalize_hex_literal(hex_col)
        } else {
            normalize_hex_literal(val)
        };
        match (&q.hex, &row_hex) {
            (Some(qh), Some(rh)) => qh.eq_ignore_ascii_case(rh),
            _ => false,
        }
    } else {
        false
    };

    if hex_exact {
        return 5;
    }
    if q.is_hex {
        return 0;
    }

    let id_score = score_hw_identifier_match_prepared(name, q);
    let val_score = if !q_lower.is_empty()
        && (ascii_contains_ignore_case(val.as_bytes(), q_lower.as_bytes())
            || ascii_contains_ignore_case(desc.as_bytes(), q_lower.as_bytes()))
    {
        1
    } else {
        0
    };
    id_score.max(val_score)
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

    for (cp, cr) in c_splits.into_iter().flatten() {
        for (qp, qr) in q.splits.into_iter().flatten() {
            if periph_stems_compatible(cp, qp) && cr.eq_ignore_ascii_case(qr) {
                return 3;
            }
        }
    }

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
        && tok
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GPIO"))
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

#[derive(serde::Deserialize)]
struct BundleNameProbe {
    #[serde(default)]
    metadata: BundleNameMetadata,
}

#[derive(Default, serde::Deserialize)]
struct BundleNameMetadata {
    #[serde(default)]
    repo_name: String,
}

fn bundle_name_from_dir(bundle_dir: &Path) -> String {
    if let Some(name) = bundle_repo_name(bundle_dir) {
        if !name.is_empty() {
            return name;
        }
    }
    bundle_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bundle")
        .to_string()
}

fn bundle_repo_name(bundle_dir: &Path) -> Option<String> {
    use std::io::Read;

    let meta_path = bundle_dir.join("meta.json");
    if let Ok(mut file) = fs::File::open(&meta_path) {
        let mut prefix = vec![0u8; 64 * 1024];
        if let Ok(n) = file.read(&mut prefix) {
            prefix.truncate(n);
            if let Some(name) = repo_name_from_meta_prefix(&prefix) {
                return Some(name);
            }
        }
    }

    let bytes = fs::read(&meta_path).ok()?;
    let probe: BundleNameProbe = serde_json::from_slice(&bytes).ok()?;
    Some(probe.metadata.repo_name)
}

fn repo_name_from_meta_prefix(bytes: &[u8]) -> Option<String> {
    let key = b"\"repo_name\"";
    let pos = memchr::memmem::find(bytes, key)?;
    let meta_key = b"\"metadata\"";
    let meta_pos = memchr::memmem::find(&bytes[..pos], meta_key)?;
    if meta_pos + meta_key.len() >= pos {
        return None;
    }
    let mut i = pos + key.len();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let start = i;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => return None,
            b'"' => {
                return std::str::from_utf8(&bytes[start..i])
                    .ok()
                    .map(str::to_string)
            }
            b if b < 0x20 => return None,
            _ => i += 1,
        }
    }
    None
}

/// Executes a structured JSON query for a subcommand across bundles.
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
            let colon_suffix = format!("::{q_lower}");
            let targets_file = query_targets_file(q_trim);
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "symbols.tsv")?;
                let bundle_name = bundle_name_from_dir(bundle_dir);
                for line in content.lines().skip(1) {
                    if !q_lower.is_empty()
                        && !ascii_contains_ignore_case(line.as_bytes(), q_lower.as_bytes())
                    {
                        continue;
                    }
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
                        || scoped_lower.ends_with(&colon_suffix)
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
            let targets_file = query_targets_file(q_trim);
            let mut items = Vec::new();
            for bundle_dir in bundles {
                let content = load_index_table(bundle_dir, "types.tsv")?;
                let bundle_name = bundle_name_from_dir(bundle_dir);
                for line in content.lines().skip(1) {
                    if !q_lower.is_empty()
                        && !ascii_contains_ignore_case(line.as_bytes(), q_lower.as_bytes())
                    {
                        continue;
                    }
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
            let mut hits = collect_macro_rows(bundles, q_trim)?;
            hits.sort_by_key(|h| std::cmp::Reverse(h.score));
            let out: Vec<serde_json::Value> = hits
                .iter()
                .take(limit)
                .map(|h| {
                    serde_json::json!({
                        "bundle": h.bundle_name,
                        "name": h.field(0),
                        "kind": h.field(1),
                        "value": h.field(2),
                        "hex_addr": h.field(3),
                        "file": h.file,
                        "line": h.line,
                        "arch_layer": h.field(6),
                        "scope": h.field(7),
                        "section_id": h.field(8),
                        "description": h.field(9),
                    })
                })
                .collect();
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
