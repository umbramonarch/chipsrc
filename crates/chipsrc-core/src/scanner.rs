//! Layer 1 — Parallel `.gitignore`-aware repository scanner, scope/layer classifier,
//! deterministic BLAKE3 fingerprinting, and logical module shard assignment.

use crate::error::{ChipsrcError, Result};
use crate::model::{
    ArchLayer, BundleMetaFile, CacheManifest, FileScope, FileStamp, IncrementalAstCache,
    LanguageKind, ParsedFileUnit, RepoBlueprint, RepoMetadata, ScannedFile, VendorMode,
    CACHE_SCHEMA_VERSION,
};
use ignore::WalkBuilder;
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Excluded build/artifact/cache and generated documentation/static-asset directories
/// skipped unconditionally during walking (`_static`, `_build`, `doxygen`, ... contain bundled
/// JS/CSS/HTML documentation assets rather than project source code).
const IGNORED_DIRS: &[&str] = &[
    ".git",
    "target",
    "output",
    "out",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "_build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "_static",
    "doxygen",
    "coverage",
    "htmlcov",
    ".tox",
    ".nox",
    "wheelhouse",
    ".astro",
    ".vercel",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
];

/// Directory components indicating third-party / vendor SDK ownership (exact segment match).
const VENDOR_COMPONENTS: &[&str] = &[
    "vendor",
    "vendors",
    "third_party",
    "3rdparty",
    "third-party",
    "external",
    "externals",
    "sdk",
    "sdks",
    "cmsis",
    "hal",
    "driverlib",
    "middlewares",
    "middleware",
    "submodules",
    "deps",
    "bundled",
    "svd",
];

/// Root-level directory names holding external reference material or third-party drops.
const ROOT_VENDOR_DIRS: &[&str] = &["references", "reference"];

/// Structural sub-tokens inside composite directory names (e.g. `My_DriverLib`, `CMSIS_CORE`,
/// `hal_driver`, `mcu_sdk`, `STM32Cube`) that indicate vendor/SDK ownership without hardcoding
/// specific chip part numbers.
const VENDOR_COMPOSITE_SUBTOKENS: &[&str] = &[
    "driverlib",
    "cmsis",
    "thirdparty",
    "3rdparty",
    "vendor",
    "svd",
    "sdk",
    "bundled",
    "submodules",
    "middlewares",
];

/// Path components indicating test / benchmark / evaluation code.
const TEST_COMPONENTS: &[&str] = &["tests", "test", "evals", "benches"];

/// Exact filenames (without `.js`) of generated documentation scripts emitted by Doxygen/Sphinx/JSDoc.
const BUNDLED_DOC_JS_STEMS: &[&str] = &[
    "jquery",
    "modernizr",
    "underscore",
    "prettify",
    "searchdata",
    "navtree",
    "navtreedata",
    "dynsections",
];

/// Versioned/variant prefixes of bundled third-party JavaScript libraries (`jquery-3.6.0.js`,
/// `modernizr-2.8.3.min.js`, `navtreeindex0.js`).
const BUNDLED_VERSIONED_JS_PREFIXES: &[&str] = &[
    "jquery-",
    "modernizr-",
    "underscore-",
    "bootstrap-",
    "bootstrap.",
    "mermaid-",
    "mermaid.",
    "prettify-",
    "navtreeindex",
];

/// Returns `true` for minified or documentation-generator bundled third-party JavaScript assets,
/// which carry no first-party source structure worth indexing.
fn is_bundled_js_asset(lower_filename: &str) -> bool {
    let Some(stem) = lower_filename
        .strip_suffix(".js")
        .or_else(|| lower_filename.strip_suffix(".mjs"))
        .or_else(|| lower_filename.strip_suffix(".cjs"))
    else {
        return false;
    };

    stem.ends_with(".min")
        || stem.ends_with(".bundle")
        || BUNDLED_DOC_JS_STEMS.contains(&stem)
        || BUNDLED_VERSIONED_JS_PREFIXES
            .iter()
            .any(|prefix| stem.starts_with(prefix))
}

/// Returns `true` when `rel_path` sits under a `docs|doc|documentation|html` segment AND either
/// a later directory segment is `search|html|_static|assets` or the file is a generated Doxygen/search JS file.
fn is_generated_doc_asset(rel_path: &str, lower_filename: &str) -> bool {
    let parts: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
    let dir_segments = &parts[..parts.len().saturating_sub(1)];
    let Some(doc_idx) = dir_segments.iter().position(|seg| {
        matches!(
            seg.to_ascii_lowercase().as_str(),
            "docs" | "doc" | "documentation" | "html"
        )
    }) else {
        return false;
    };

    if dir_segments[doc_idx + 1..].iter().any(|seg| {
        matches!(
            seg.to_ascii_lowercase().as_str(),
            "search" | "html" | "_static" | "assets"
        )
    }) {
        return true;
    }

    lower_filename.ends_with(".min.js")
        || (lower_filename.starts_with("search") && lower_filename.ends_with(".js"))
        || (lower_filename.starts_with("all_") && lower_filename.ends_with(".js"))
        || lower_filename == "menudata.js"
        || (lower_filename.starts_with("navtree") && lower_filename.ends_with(".js"))
}

/// Loads `<repo_path>/.chipsrc.json` if present, returning `Ok(Some((blueprint, hash)))`,
/// `Ok(None)` when absent, or `Err(message)` (after emitting a `[warn]` to stderr) when invalid.
pub fn load_repo_blueprint_result(
    repo_path: &Path,
) -> std::result::Result<Option<(RepoBlueprint, String)>, String> {
    let bp_path = repo_path.join(".chipsrc.json");
    if !bp_path.is_file() {
        return Ok(None);
    }
    let bytes = match fs::read(&bp_path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("    [warn] Failed to read .chipsrc.json: {err}");
            return Err(err.to_string());
        }
    };
    let bp: RepoBlueprint = match serde_json::from_slice(&bytes) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("    [warn] Failed to parse .chipsrc.json: {err}");
            return Err(err.to_string());
        }
    };
    let full_hash = blake3::hash(&bytes).to_hex();
    let hash = full_hash[..16].to_string();
    Ok(Some((bp, hash)))
}

/// Loads `<repo_path>/.chipsrc.json` if present, returning the parsed [`RepoBlueprint`]
/// together with its 16-character BLAKE3 content hash.
pub fn load_repo_blueprint(repo_path: &Path) -> Option<(RepoBlueprint, String)> {
    load_repo_blueprint_result(repo_path).ok().flatten()
}

/// Finds the longest normalized path prefix in `map` that matches `rel_path`.
fn match_longest_prefix<'a, V>(
    rel_path: &str,
    map: &'a BTreeMap<String, V>,
) -> Option<(String, &'a V)> {
    let norm_path = rel_path.replace('\\', "/");
    let trimmed_path = norm_path.trim_matches('/');
    let mut best: Option<(usize, String, &'a V)> = None;

    for (raw_prefix, val) in map {
        let clean_prefix = raw_prefix
            .replace('\\', "/")
            .trim_start_matches("./")
            .trim_end_matches("/**")
            .trim_end_matches("/*")
            .trim_matches('/')
            .to_string();
        if clean_prefix.is_empty() {
            continue;
        }
        let matched = trimmed_path == clean_prefix
            || trimmed_path
                .strip_prefix(clean_prefix.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if matched {
            let len = clean_prefix.len();
            if best.as_ref().is_none_or(|(best_len, _, _)| len > *best_len) {
                best = Some((len, clean_prefix, val));
            }
        }
    }

    best.map(|(_, prefix, val)| (prefix, val))
}

fn path_matches_ignore_dirs(rel_path: &str, ignore_dirs: &[String]) -> bool {
    if ignore_dirs.is_empty() {
        return false;
    }
    let norm = rel_path.replace('\\', "/");
    let trimmed = norm.trim_matches('/');
    for raw_ig in ignore_dirs {
        let ig = raw_ig
            .replace('\\', "/")
            .trim_start_matches("./")
            .trim_end_matches("/**")
            .trim_end_matches("/*")
            .trim_matches('/')
            .to_string();
        if ig.is_empty() {
            continue;
        }
        if trimmed == ig
            || trimmed
                .strip_prefix(ig.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
            || trimmed.split('/').any(|seg| seg.eq_ignore_ascii_case(&ig))
        {
            return true;
        }
    }
    false
}

/// Counts logical source lines in `bytes`: the number of `\n` bytes plus `1` when `bytes` is
/// non-empty and does not end with `\n` (an empty buffer has `0` lines).
pub fn count_source_lines(bytes: &[u8]) -> usize {
    memchr::memchr_iter(b'\n', bytes).count()
        + usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n"))
}

/// Walks `repo_path` respecting `.gitignore`, `.claudeignore`, and `.chipsrc.json`, skips generated
/// documentation assets and minified/bundled third-party JavaScript, classifies each
/// supported source file by language, ownership scope, and architectural layer, and returns the
/// sorted file list along with a 16-character BLAKE3 repository fingerprint.
pub fn scan_repository(
    repo_path: &Path,
    vendor_mode: VendorMode,
    max_file_bytes: u64,
) -> Result<(Vec<ScannedFile>, String)> {
    if !repo_path.is_dir() {
        return Err(ChipsrcError::InvalidRepoPath(repo_path.to_path_buf()));
    }

    let blueprint_opt = load_repo_blueprint(repo_path);
    let custom_ignore_dirs: Vec<String> = blueprint_opt
        .as_ref()
        .map(|(bp, _)| {
            bp.ignore_dirs
                .iter()
                .map(|ig| {
                    ig.replace('\\', "/")
                        .trim_start_matches("./")
                        .trim_end_matches("/**")
                        .trim_end_matches("/*")
                        .trim_matches('/')
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default();

    let mut walker = WalkBuilder::new(repo_path);
    walker
        .parents(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .require_git(false)
        .ignore(true)
        .hidden(true)
        .add_custom_ignore_filename(".claudeignore")
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                if let Some(name) = entry.file_name().to_str() {
                    if IGNORED_DIRS.iter().any(|&ig| ig.eq_ignore_ascii_case(name)) {
                        return false;
                    }
                    if custom_ignore_dirs
                        .iter()
                        .any(|clean| clean.eq_ignore_ascii_case(name))
                    {
                        return false;
                    }
                }
            }
            true
        });

    let mut candidate_paths: Vec<(PathBuf, String, LanguageKind, u64, u64, u32)> = Vec::new();
    let bp_ref = blueprint_opt.as_ref().map(|(bp, _)| bp);

    for entry_res in walker.build() {
        let entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let abs_path = entry.path().to_path_buf();
        let ext = match abs_path.extension().and_then(|e| e.to_str()) {
            Some(e) => e,
            None => continue,
        };
        let Some(language) = LanguageKind::from_extension(ext) else {
            continue;
        };

        // Skip minified / bundled third-party documentation JavaScript assets.
        let lower_filename = abs_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.to_ascii_lowercase())
            .unwrap_or_default();
        if is_bundled_js_asset(&lower_filename) {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size_bytes = meta.len();
        if size_bytes == 0 || size_bytes > max_file_bytes {
            continue;
        }

        let (mtime_secs, mtime_nanos) = file_mtime_secs_nanos(&meta);

        let rel_path = match abs_path.strip_prefix(repo_path) {
            Ok(rel) => normalize_rel_path(rel),
            Err(_) => normalize_rel_path(&abs_path),
        };
        if rel_path.is_empty() {
            continue;
        }
        if is_generated_doc_asset(&rel_path, &lower_filename) {
            continue;
        }
        if let Some(bp) = bp_ref {
            if path_matches_ignore_dirs(&rel_path, &bp.ignore_dirs) {
                continue;
            }
        }

        candidate_paths.push((
            abs_path,
            rel_path,
            language,
            size_bytes,
            mtime_secs,
            mtime_nanos,
        ));
    }

    let mut scanned_files: Vec<ScannedFile> = candidate_paths
        .into_par_iter()
        .filter_map(
            |(abs_path, rel_path, language, size_bytes, mtime_secs, mtime_nanos)| {
                let bytes = fs::read(&abs_path).ok()?;
                if bytes.is_empty() {
                    return None;
                }

                let explicit_example_scope = bp_ref
                    .and_then(|bp| match_longest_prefix(&rel_path, &bp.scopes))
                    .is_some_and(|(matched_key, _)| {
                        matched_key.split('/').any(|seg| {
                            matches!(
                                seg.to_ascii_lowercase().as_str(),
                                "examples"
                                    | "example"
                                    | "samples"
                                    | "sample"
                                    | "demos"
                                    | "demo"
                                    | "templates"
                                    | "template"
                                    | "boards"
                                    | "board"
                            )
                        })
                    });
                let scope =
                    classify_file_scope_with_blueprint(&rel_path, size_bytes, &bytes, bp_ref);
                if scope == FileScope::VendorSdk {
                    if vendor_mode == VendorMode::None {
                        return None;
                    }
                    if !explicit_example_scope && is_vendor_example_or_demo_path(&rel_path) {
                        return None;
                    }
                }

                let arch_layer = classify_arch_layer_with_blueprint(&rel_path, scope, bp_ref);
                let line_count = count_source_lines(&bytes);
                let full_hash = blake3::hash(&bytes).to_hex();
                let blake3_hash = full_hash[..16].to_string();

                Some(ScannedFile {
                    rel_path,
                    abs_path,
                    language,
                    scope,
                    arch_layer,
                    size_bytes,
                    mtime_secs,
                    mtime_nanos,
                    blake3_hash,
                    line_count,
                })
            },
        )
        .collect();

    scanned_files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    if scanned_files.is_empty() && blueprint_opt.is_none() {
        return Err(ChipsrcError::NoSourceFilesFound(repo_path.to_path_buf()));
    }

    let mut repo_hasher = blake3::Hasher::new();
    if let Some((_, ref bp_hash)) = blueprint_opt {
        repo_hasher.update(b"blueprint:");
        repo_hasher.update(bp_hash.as_bytes());
        repo_hasher.update(b"\n");
    }
    for file in &scanned_files {
        repo_hasher.update(file.rel_path.as_bytes());
        repo_hasher.update(b":");
        repo_hasher.update(&file.size_bytes.to_le_bytes());
        repo_hasher.update(b":");
        repo_hasher.update(file.blake3_hash.as_bytes());
        repo_hasher.update(b"\n");
    }
    let fingerprint = repo_hasher.finalize().to_hex()[..16].to_string();

    Ok((scanned_files, fingerprint))
}

fn file_mtime_secs_nanos(meta: &fs::Metadata) -> (u64, u32) {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0))
}

/// Canonicalizes `repo_path` into a normalized forward-slash `source_root` and clean `repo_name`.
pub fn canonical_repo_root_and_name(repo_path: &Path) -> (String, String) {
    let canonical = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    let repo_name = canonical
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != ".")
        .unwrap_or("repo")
        .to_string();
    let raw_str = canonical.to_string_lossy();
    let clean_root = raw_str
        .strip_prefix(r"\\?\")
        .unwrap_or(&raw_str)
        .replace('\\', "/");
    (clean_root, repo_name)
}

/// Loads `meta.json` from `bundle_dir` if present and valid.
///
/// If any `file_stamps` entry in `meta.json` lacks the `mtime_nanos` field (e.g. a legacy
/// `2.0.0` bundle), `file_stamps` is cleared so callers trigger a one-time rebuild.
pub fn load_meta_file(bundle_dir: &Path) -> Option<BundleMetaFile> {
    let bytes = fs::read(bundle_dir.join("meta.json")).ok()?;
    let mut meta: BundleMetaFile = serde_json::from_slice(&bytes).ok()?;
    if !meta.metadata.file_stamps.is_empty() {
        let nanos_count = memchr::memmem::find_iter(&bytes, b"\"mtime_nanos\"").count();
        if nanos_count < meta.metadata.file_stamps.len() {
            meta.metadata.file_stamps.clear();
        }
    }
    Some(meta)
}

/// Loads `cache/manifest.json` from `bundle_dir` if present and matching `CACHE_SCHEMA_VERSION`.
pub fn load_cache_manifest(bundle_dir: &Path) -> Option<CacheManifest> {
    let manifest = load_cache_manifest_any_version(bundle_dir)?;
    if manifest.schema_version != CACHE_SCHEMA_VERSION {
        return None;
    }
    Some(manifest)
}

/// Loads `cache/manifest.json` from `bundle_dir` regardless of `schema_version` (used to recover
/// `repo_root` and `vendor_mode` when `meta.json` is missing or truncated).
pub fn load_cache_manifest_any_version(bundle_dir: &Path) -> Option<CacheManifest> {
    let manifest_path = bundle_dir.join("cache").join("manifest.json");
    let bytes = fs::read(manifest_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Parses the bytes of a cache shard: either one compact `ParsedFileUnit` (`cache/<key>.json`) or
/// a packed JSON array of units (`cache/pack-<16hex>.json`).
fn parse_cache_shard_units(bytes: &[u8]) -> Option<Vec<ParsedFileUnit>> {
    let first = bytes.iter().copied().find(|b| !b.is_ascii_whitespace())?;
    if first == b'[' {
        serde_json::from_slice::<Vec<ParsedFileUnit>>(bytes).ok()
    } else {
        serde_json::from_slice::<ParsedFileUnit>(bytes)
            .ok()
            .map(|unit| vec![unit])
    }
}

/// Loads every parsed unit stored in one cache shard (`cache/<key>.json` or a packed
/// `cache/pack-<16hex>.json`) and restores its per-file fields.
///
/// Shards store the owning path once (the unit's `scanned.rel_path`) and omit it from every
/// symbol/type/macro/import/call/xref row, so the per-file fields are re-attached here.
pub fn load_cache_shard_units(bundle_dir: &Path, shard_rel: &str) -> Option<Vec<ParsedFileUnit>> {
    let bytes = fs::read(bundle_dir.join(shard_rel)).ok()?;
    let mut units = parse_cache_shard_units(&bytes)?;
    for unit in &mut units {
        unit.restore_per_file_fields();
    }
    Some(units)
}

/// Loads a single per-file AST cache shard (`cache/<blake3_hash>.json`) from `bundle_dir`.
///
/// Packed shards hold several units; use [`load_cache_shard_unit`] or [`load_cache_units`] for
/// those. A pack with exactly one unit is accepted here for convenience.
pub fn load_cache_shard(bundle_dir: &Path, shard_rel: &str) -> Option<ParsedFileUnit> {
    let mut units = load_cache_shard_units(bundle_dir, shard_rel)?;
    if units.len() == 1 {
        units.pop()
    } else {
        None
    }
}

/// Loads the unit named `rel_path` from `shard_rel`, which may be a per-file shard or a packed
/// shard. Returns `None` when the shard is missing, unparsable, or does not contain that file.
pub fn load_cache_shard_unit(
    bundle_dir: &Path,
    shard_rel: &str,
    rel_path: &str,
) -> Option<ParsedFileUnit> {
    let mut units = load_cache_shard_units(bundle_dir, shard_rel)?;
    let index = units
        .iter()
        .position(|unit| unit.scanned.rel_path == rel_path)?;
    Some(units.swap_remove(index))
}

/// Loads the requested `(rel_path, shard_rel)` cache units, reading each shard file once even when
/// it is a packed shard shared by many files. Units that are missing or unparsable are omitted so
/// callers can fall back to reparsing those files.
pub fn load_cache_units(
    bundle_dir: &Path,
    requests: &[(String, String)],
) -> FxHashMap<String, ParsedFileUnit> {
    let mut by_shard: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (rel_path, shard_rel) in requests {
        by_shard
            .entry(shard_rel.as_str())
            .or_default()
            .push(rel_path.as_str());
    }
    let shards: Vec<(&str, Vec<&str>)> = by_shard.into_iter().collect();
    let loaded: Vec<Vec<(String, ParsedFileUnit)>> = shards
        .par_iter()
        .map(|(shard_rel, rel_paths)| {
            let Some(units) = load_cache_shard_units(bundle_dir, shard_rel) else {
                return Vec::new();
            };
            let mut wanted: FxHashSet<&str> = rel_paths.iter().copied().collect();
            let mut out = Vec::with_capacity(rel_paths.len().min(units.len()));
            for unit in units {
                if wanted.remove(unit.scanned.rel_path.as_str()) {
                    out.push((unit.scanned.rel_path.clone(), unit));
                    if wanted.is_empty() {
                        break;
                    }
                }
            }
            out
        })
        .collect();
    let mut by_rel_path = FxHashMap::default();
    by_rel_path.reserve(requests.len());
    for batch in loaded {
        for (rel_path, unit) in batch {
            by_rel_path.insert(rel_path, unit);
        }
    }
    by_rel_path
}

/// Returns `true` when `bundle_dir` has a valid `cache/manifest.json` matching `CACHE_SCHEMA_VERSION`.
pub fn has_bundle_cache(bundle_dir: &Path) -> bool {
    load_cache_manifest(bundle_dir).is_some()
}

/// Returns `true` when `content` (or the initial prefix of a TSV file) begins with the canonical
/// header line for `rel` (`index/<table_name>.tsv`).
pub fn has_valid_tsv_header(rel: &str, content: &str) -> bool {
    let expected_prefix = match rel.strip_prefix("index/").unwrap_or(rel) {
        "sections.tsv" => {
            "section_id\ttitle\tmodule_path\tarch_layer\tscope\tfile_count\tsymbol_count\ttype_count\tmacro_count\ttoken_estimate\tmd_file"
        }
        "symbols.tsv" => {
            "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\tdoc_summary"
        }
        "types.tsv" => {
            "type_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tfields_summary\tarch_layer\tscope\tsection_id\tdoc_summary"
        }
        "calls.tsv" => {
            "caller_id\tcaller_name\tcallee_name\tcallee_id\tfile\tline\ttier\tsection_id"
        }
        "macros.tsv" => {
            "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription"
        }
        "xref.tsv" => "symbol\tcategory\trelation\ttarget\tfile\tline\tsection_id\tcontext",
        _ => return !content.trim().is_empty(),
    };
    let Some(first_line) = content.lines().next() else {
        return false;
    };
    first_line.starts_with(expected_prefix)
}

fn read_tsv_header_line(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut buf = [0u8; 512];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let slice = &buf[..n];
    let line_end = memchr::memchr(b'\n', slice).unwrap_or(n);
    let line_bytes = slice[..line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&slice[..line_end]);
    std::str::from_utf8(line_bytes).ok().map(|s| s.to_string())
}

/// Pre-parsed bundle metadata that lets callers run the artifact-integrity gate without
/// re-reading `meta.json` or `cache/manifest.json` more than once per command.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundleArtifactSources<'a> {
    /// Result of `load_meta_file(bundle_dir)`; `None` means "read it here".
    pub meta: Option<&'a BundleMetaFile>,
    /// Result of `load_cache_manifest(bundle_dir)` (schema-validated); `None` means "read it here".
    pub manifest: Option<&'a CacheManifest>,
}

/// Returns the relative path of the first missing or invalid required bundle artifact in `bundle_dir`,
/// or `None` when the bundle is complete (`meta.json`, `INDEX.md`, all six `index/*.tsv` tables
/// with non-empty header lines, every `md_file` listed in column 11 of `index/sections.tsv`,
/// `cache/manifest.json`, and every shard listed in `cache/manifest.json`).
pub fn first_missing_bundle_artifact(bundle_dir: &Path) -> Option<String> {
    first_missing_bundle_artifact_with(bundle_dir, BundleArtifactSources::default())
}

/// Same as [`first_missing_bundle_artifact`], but reuses an already-parsed `meta.json` and/or
/// `cache/manifest.json` when the caller has them. Keeping the parses to one per command matters on
/// large bundles: the STM32CubeF4 `meta.json` is ~4 MB and `cache/manifest.json` ~2.5 MB.
pub fn first_missing_bundle_artifact_with(
    bundle_dir: &Path,
    sources: BundleArtifactSources<'_>,
) -> Option<String> {
    if !bundle_dir.is_dir() {
        return Some("bundle directory".to_string());
    }
    let local_meta = if sources.meta.is_none() {
        load_meta_file(bundle_dir)
    } else {
        None
    };
    if sources.meta.or(local_meta.as_ref()).is_none() {
        return Some("meta.json".to_string());
    }
    if !bundle_dir.join("INDEX.md").is_file() {
        return Some("INDEX.md".to_string());
    }

    let Ok(sections_tsv) = fs::read_to_string(bundle_dir.join("index/sections.tsv")) else {
        return Some("index/sections.tsv".to_string());
    };
    if !has_valid_tsv_header("index/sections.tsv", &sections_tsv) {
        return Some("index/sections.tsv".to_string());
    }

    const HEADER_CHECK_TSVS: [&str; 5] = [
        "index/symbols.tsv",
        "index/types.tsv",
        "index/calls.tsv",
        "index/macros.tsv",
        "index/xref.tsv",
    ];
    for rel in HEADER_CHECK_TSVS {
        let Some(header_line) = read_tsv_header_line(&bundle_dir.join(rel)) else {
            return Some(rel.to_string());
        };
        if !has_valid_tsv_header(rel, &header_line) {
            return Some(rel.to_string());
        }
    }

    let mut sec_lines = sections_tsv.lines();
    if sec_lines.next().is_none() {
        return Some("index/sections.tsv".to_string());
    }

    let sections_dir = bundle_dir.join("sections");
    let existing_sections: FxHashSet<String> = fs::read_dir(&sections_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    for line in sec_lines {
        if line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let Some(md_col_raw) = cols.nth(10) else {
            return Some("index/sections.tsv".to_string());
        };
        let md_col = md_col_raw.trim();
        if md_col.is_empty() {
            return Some("index/sections.tsv".to_string());
        }
        let rel_md = if md_col.starts_with("sections/") {
            md_col.to_string()
        } else {
            format!("sections/{md_col}")
        };
        let fname = rel_md.strip_prefix("sections/").unwrap_or(&rel_md);
        let present = if !fname.contains('/') && !fname.contains('\\') {
            existing_sections.contains(fname)
        } else {
            bundle_dir.join(&rel_md).is_file()
        };
        if !present {
            return Some(rel_md);
        }
    }

    let local_manifest = if sources.manifest.is_none() {
        load_cache_manifest(bundle_dir)
    } else {
        None
    };
    let Some(manifest) = sources.manifest.or(local_manifest.as_ref()) else {
        return Some("cache/manifest.json".to_string());
    };
    if manifest.files.is_empty() {
        return Some("cache/manifest.json".to_string());
    }

    let cache_dir = bundle_dir.join("cache");
    let existing_shards: FxHashSet<String> = fs::read_dir(&cache_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    for entry in manifest.files.values() {
        if entry.shard.is_empty() {
            return Some("cache/manifest.json".to_string());
        }
        let shard_fname = entry.shard.strip_prefix("cache/").unwrap_or(&entry.shard);
        let present = if !shard_fname.contains('/') && !shard_fname.contains('\\') {
            existing_shards.contains(shard_fname)
        } else {
            bundle_dir.join(&entry.shard).is_file()
        };
        if !present {
            return Some(entry.shard.clone());
        }
    }

    None
}

/// Returns `true` when `bundle_dir` contains all required bundle artifacts (`meta.json`, `INDEX.md`,
/// all six `index/*.tsv` tables, every `sections/*.md` referenced by `index/sections.tsv`,
/// `cache/manifest.json`, and every per-file cache shard listed in the manifest).
pub fn bundle_artifacts_complete(bundle_dir: &Path) -> bool {
    first_missing_bundle_artifact(bundle_dir).is_none()
}

/// Same as [`bundle_artifacts_complete`], reusing already-parsed metadata (see
/// [`BundleArtifactSources`]).
pub fn bundle_artifacts_complete_with(
    bundle_dir: &Path,
    sources: BundleArtifactSources<'_>,
) -> bool {
    first_missing_bundle_artifact_with(bundle_dir, sources).is_none()
}

/// Loads the incremental AST cache from an already-parsed `cache/manifest.json` plus its shards.
///
/// Callers that already parsed the manifest (e.g. `query::workspace_status`) use this to keep the
/// manifest parse to exactly one per bundle.
pub fn load_cache_file_from_manifest(
    bundle_dir: &Path,
    manifest: &CacheManifest,
) -> Option<IncrementalAstCache> {
    let requests: Vec<(String, String)> = manifest
        .files
        .iter()
        .map(|(rel_path, entry)| (rel_path.clone(), entry.shard.clone()))
        .collect();
    let mut loaded = load_cache_units(bundle_dir, &requests);
    let mut files = BTreeMap::new();
    for rel_path in manifest.files.keys() {
        let unit = loaded.remove(rel_path)?;
        files.insert(rel_path.clone(), unit);
    }
    Some(IncrementalAstCache {
        schema_version: manifest.schema_version.clone(),
        repo_root: manifest.repo_root.clone(),
        vendor_mode: manifest.vendor_mode,
        fingerprint: manifest.fingerprint.clone(),
        blueprint_hash: manifest.blueprint_hash.clone(),
        files,
    })
}

/// Loads the incremental AST cache from `bundle_dir/cache/manifest.json` + `cache/*.json` shards
/// (schema `2.1.0`).
pub fn load_cache_file(bundle_dir: &Path) -> Option<IncrementalAstCache> {
    if let Some(manifest) = load_cache_manifest(bundle_dir) {
        return load_cache_file_from_manifest(bundle_dir, &manifest);
    }

    let legacy_path = bundle_dir.join("cache.json");
    let bytes = fs::read(&legacy_path).ok()?;
    let mut cache: IncrementalAstCache = serde_json::from_slice(&bytes).ok()?;
    if cache.schema_version != CACHE_SCHEMA_VERSION {
        return None;
    }
    cache.schema_version = CACHE_SCHEMA_VERSION.to_string();
    let _ = fs::remove_file(&legacy_path);
    Some(cache)
}

/// Result of a fast stat-only freshness check against `meta.file_stamps`.
#[derive(Debug, Clone, Default)]
pub struct StampCheck {
    pub unchanged: bool,
    pub suspects: Vec<PathBuf>,
    pub suspect_rel_paths: Vec<String>,
    pub changed_count: usize,
    pub added: usize,
    pub deleted: usize,
    pub touched_mtimes: BTreeMap<String, (u64, u32)>,
    pub scanned_files: Option<Vec<ScannedFile>>,
    pub fingerprint: String,
}

/// Immutable shared state for the parallel stat-only stamp walk.
struct StampWalkCtx<'a> {
    repo_root: &'a Path,
    stamps: &'a [FileStamp],
    stamp_index: FxHashMap<&'a str, u32>,
    blueprint: Option<&'a RepoBlueprint>,
    vendor_mode: VendorMode,
    max_file_bytes: u64,
    blueprint_changed: bool,
}

/// Per-thread accumulator for [`stamp_check`]'s parallel walk. Each walker worker owns one and
/// hands it to the shared sink on drop, so no locking happens on the per-file hot path.
struct StampThreadAcc {
    built_files: Vec<ScannedFile>,
    suspects: Vec<PathBuf>,
    suspect_rel_paths: Vec<String>,
    touched_mtimes: Vec<(String, (u64, u32))>,
    seen_stamp_idx: Vec<u32>,
    added: usize,
    modified: usize,
    can_build_files: bool,
}

impl Default for StampThreadAcc {
    fn default() -> Self {
        StampThreadAcc {
            built_files: Vec::new(),
            suspects: Vec::new(),
            suspect_rel_paths: Vec::new(),
            touched_mtimes: Vec::new(),
            seen_stamp_idx: Vec::new(),
            added: 0,
            modified: 0,
            can_build_files: true,
        }
    }
}

impl StampWalkCtx<'_> {
    /// Classifies one walked file against the recorded stamps, appending results to `acc`.
    /// Unchanged files (matching size + whole-second mtime + sub-second mtime) are never opened.
    fn visit_file(&self, entry: &ignore::DirEntry, acc: &mut StampThreadAcc) {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            return;
        }
        let abs_path = entry.path();
        let Some(ext) = abs_path.extension().and_then(|e| e.to_str()) else {
            return;
        };
        let Some(language) = LanguageKind::from_extension(ext) else {
            return;
        };
        let file_name = entry.file_name().to_str().unwrap_or_default();
        let lower_filename = file_name.to_ascii_lowercase();
        if is_bundled_js_asset(&lower_filename) {
            return;
        }
        let Ok(fs_meta) = entry.metadata() else {
            return;
        };
        let size_bytes = fs_meta.len();
        if size_bytes == 0 || size_bytes > self.max_file_bytes {
            return;
        }
        let (mtime_secs, mtime_nanos) = file_mtime_secs_nanos(&fs_meta);

        let rel_path = match abs_path.strip_prefix(self.repo_root) {
            Ok(rel) => normalize_rel_path(rel),
            Err(_) => normalize_rel_path(abs_path),
        };
        if rel_path.is_empty() || is_generated_doc_asset(&rel_path, &lower_filename) {
            return;
        }
        if let Some(bp) = self.blueprint {
            if path_matches_ignore_dirs(&rel_path, &bp.ignore_dirs) {
                return;
            }
        }

        let Some(&stamp_idx) = self.stamp_index.get(rel_path.as_str()) else {
            // Candidate new file: check if it would be filtered by VendorMode::None or vendor
            // example rules, mirroring the full scanner's scope classification.
            let explicit_example_scope = self
                .blueprint
                .and_then(|bp| match_longest_prefix(&rel_path, &bp.scopes))
                .is_some_and(|(matched_key, _)| {
                    matched_key.split('/').any(|seg| {
                        matches!(
                            seg.to_ascii_lowercase().as_str(),
                            "examples"
                                | "example"
                                | "samples"
                                | "sample"
                                | "demos"
                                | "demo"
                                | "templates"
                                | "template"
                                | "boards"
                                | "board"
                        )
                    })
                });
            let dir_scope = classify_file_scope_with_blueprint(&rel_path, 0, b"", self.blueprint);
            if dir_scope == FileScope::VendorSdk
                && (self.vendor_mode == VendorMode::None
                    || (!explicit_example_scope && is_vendor_example_or_demo_path(&rel_path)))
            {
                return;
            }
            if size_bytes > 200 * 1024
                && (lower_filename.ends_with(".h") || lower_filename.ends_with(".hpp"))
            {
                if let Ok(bytes) = fs::read(abs_path) {
                    let scope = classify_file_scope_with_blueprint(
                        &rel_path,
                        size_bytes,
                        &bytes,
                        self.blueprint,
                    );
                    if scope == FileScope::VendorSdk
                        && (self.vendor_mode == VendorMode::None
                            || (!explicit_example_scope
                                && is_vendor_example_or_demo_path(&rel_path)))
                    {
                        return;
                    }
                }
            }
            // A file that only the vendor-side filters would have excluded is not a real change:
            // the full scan never indexes it either. Only files that survive the filters and are
            // genuinely new invalidate the reusable file list.
            acc.can_build_files = false;
            acc.suspects.push(abs_path.to_path_buf());
            acc.suspect_rel_paths.push(rel_path);
            acc.added += 1;
            return;
        };

        let stamp = &self.stamps[stamp_idx as usize];
        acc.seen_stamp_idx.push(stamp_idx);
        if !self.blueprint_changed
            && stamp.size_bytes == size_bytes
            && stamp.mtime_secs == mtime_secs
            && stamp.mtime_nanos == mtime_nanos
            && stamp.mtime_secs > 0
        {
            // Trusted stat-only hit: no fs::read needed!
            if stamp.line_count > 0 {
                acc.built_files.push(ScannedFile {
                    rel_path,
                    abs_path: abs_path.to_path_buf(),
                    language,
                    scope: stamp.scope,
                    arch_layer: stamp.arch_layer,
                    size_bytes,
                    mtime_secs,
                    mtime_nanos,
                    blake3_hash: stamp.blake3_hash.clone(),
                    line_count: stamp.line_count,
                });
            } else {
                acc.can_build_files = false;
            }
            return;
        }

        acc.suspects.push(abs_path.to_path_buf());
        acc.suspect_rel_paths.push(rel_path.clone());
        let Ok(bytes) = fs::read(abs_path) else {
            acc.modified += 1;
            acc.can_build_files = false;
            return;
        };
        let full_hash = blake3::hash(&bytes).to_hex();
        let blake3_hash = full_hash[..16].to_string();
        let scope =
            classify_file_scope_with_blueprint(&rel_path, size_bytes, &bytes, self.blueprint);
        let arch_layer = classify_arch_layer_with_blueprint(&rel_path, scope, self.blueprint);
        let line_count = count_source_lines(&bytes);
        if stamp.size_bytes == size_bytes
            && stamp.blake3_hash == blake3_hash
            && stamp.scope == scope
            && stamp.arch_layer == arch_layer
        {
            acc.touched_mtimes
                .push((rel_path.clone(), (mtime_secs, mtime_nanos)));
        } else {
            acc.modified += 1;
        }
        acc.built_files.push(ScannedFile {
            rel_path,
            abs_path: abs_path.to_path_buf(),
            language,
            scope,
            arch_layer,
            size_bytes,
            mtime_secs,
            mtime_nanos,
            blake3_hash,
            line_count,
        });
    }
}

/// Parallel walker visitor: classifies entries on the walker's worker threads.
struct StampVisitor<'a> {
    ctx: &'a StampWalkCtx<'a>,
    acc: StampThreadAcc,
    sink: &'a std::sync::Mutex<Vec<StampThreadAcc>>,
}

impl ignore::ParallelVisitor for StampVisitor<'_> {
    fn visit(
        &mut self,
        result: std::result::Result<ignore::DirEntry, ignore::Error>,
    ) -> ignore::WalkState {
        if let Ok(entry) = result {
            self.ctx.visit_file(&entry, &mut self.acc);
        }
        ignore::WalkState::Continue
    }
}

impl Drop for StampVisitor<'_> {
    fn drop(&mut self) {
        let acc = std::mem::take(&mut self.acc);
        if let Ok(mut sink) = self.sink.lock() {
            sink.push(acc);
        }
    }
}

struct StampVisitorBuilder<'a> {
    ctx: &'a StampWalkCtx<'a>,
    sink: &'a std::sync::Mutex<Vec<StampThreadAcc>>,
}

impl<'s> ignore::ParallelVisitorBuilder<'s> for StampVisitorBuilder<'s> {
    fn build(&mut self) -> Box<dyn ignore::ParallelVisitor + 's> {
        Box::new(StampVisitor {
            ctx: self.ctx,
            acc: StampThreadAcc::default(),
            sink: self.sink,
        })
    }
}

/// Walks `repo_path` comparing `(mtime_secs, mtime_nanos, size_bytes)` against `meta.file_stamps` WITHOUT
/// reading unchanged files from disk. Only files whose `(mtime_secs, mtime_nanos, size_bytes)` differ from
/// their recorded stamp ("suspects") are read and BLAKE3-hashed; touch-only suspects whose
/// BLAKE3 hash matches `stamp.blake3_hash` are treated as unchanged and recorded in `touched_mtimes`.
///
/// The walk is parallel (`ignore::WalkParallel`): `.gitignore`/`.ignore`/`.claudeignore` rules are
/// evaluated once per directory by the ignore crate and reused from its per-directory matcher stack,
/// while every entry's stat + stamp comparison runs on the walker's worker threads. `FxHashMap`
/// lookups keep the per-file work allocation-light, and unchanged files are never opened.
pub fn stamp_check(
    repo_path: &Path,
    meta: &RepoMetadata,
    max_file_bytes: u64,
) -> Option<StampCheck> {
    if meta.file_stamps.is_empty() || !repo_path.is_dir() {
        return None;
    }

    let blueprint_opt = load_repo_blueprint(repo_path);
    let bp_ref = blueprint_opt.as_ref().map(|(bp, _)| bp);

    // Verify whether `.chipsrc.json` changed by computing the Merkle fingerprint over existing stamps
    let expected_fp = {
        let mut h = blake3::Hasher::new();
        if let Some((_, ref bp_hash)) = blueprint_opt {
            h.update(b"blueprint:");
            h.update(bp_hash.as_bytes());
            h.update(b"\n");
        }
        for stamp in &meta.file_stamps {
            h.update(stamp.rel_path.as_bytes());
            h.update(b":");
            h.update(&stamp.size_bytes.to_le_bytes());
            h.update(b":");
            h.update(stamp.blake3_hash.as_bytes());
            h.update(b"\n");
        }
        h.finalize().to_hex()[..16].to_string()
    };
    let blueprint_changed = !meta.fingerprint.is_empty() && expected_fp != meta.fingerprint;

    let custom_ignore_dirs: Vec<String> = blueprint_opt
        .as_ref()
        .map(|(bp, _)| {
            bp.ignore_dirs
                .iter()
                .map(|ig| {
                    ig.replace('\\', "/")
                        .trim_start_matches("./")
                        .trim_end_matches("/**")
                        .trim_end_matches("/*")
                        .trim_matches('/')
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default();

    let mut walker = WalkBuilder::new(repo_path);
    walker
        .parents(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .require_git(false)
        .ignore(true)
        .hidden(true)
        .add_custom_ignore_filename(".claudeignore")
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                if let Some(name) = entry.file_name().to_str() {
                    if IGNORED_DIRS.iter().any(|&ig| ig.eq_ignore_ascii_case(name)) {
                        return false;
                    }
                    if custom_ignore_dirs
                        .iter()
                        .any(|clean| clean.eq_ignore_ascii_case(name))
                    {
                        return false;
                    }
                }
            }
            true
        });

    let stamp_index: FxHashMap<&str, u32> = meta
        .file_stamps
        .iter()
        .enumerate()
        .map(|(idx, s)| (s.rel_path.as_str(), idx as u32))
        .collect();

    let ctx = StampWalkCtx {
        repo_root: repo_path,
        stamps: &meta.file_stamps,
        stamp_index,
        blueprint: bp_ref,
        vendor_mode: meta.vendor_mode,
        max_file_bytes,
        blueprint_changed,
    };
    let sink: std::sync::Mutex<Vec<StampThreadAcc>> = std::sync::Mutex::new(Vec::new());
    {
        let mut builder = StampVisitorBuilder {
            ctx: &ctx,
            sink: &sink,
        };
        walker.build_parallel().visit(&mut builder);
    }
    // A poisoned sink means a walker worker already panicked (which propagates out of `visit`);
    // recover the accumulated results anyway rather than reporting every file as deleted.
    let thread_accs = sink
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut suspects: Vec<PathBuf> = Vec::new();
    let mut suspect_rel_paths: Vec<String> = Vec::new();
    let mut touched_mtimes: BTreeMap<String, (u64, u32)> = BTreeMap::new();
    let mut built_files: Vec<ScannedFile> = Vec::with_capacity(meta.file_stamps.len());
    let mut seen_stamps: FxHashSet<u32> =
        FxHashSet::with_capacity_and_hasher(meta.file_stamps.len(), Default::default());
    let mut can_build_files = !blueprint_changed;
    let mut added = 0usize;
    let mut modified = 0usize;
    for mut acc in thread_accs {
        built_files.append(&mut acc.built_files);
        suspects.append(&mut acc.suspects);
        suspect_rel_paths.append(&mut acc.suspect_rel_paths);
        for (rel, mtime) in acc.touched_mtimes {
            touched_mtimes.insert(rel, mtime);
        }
        seen_stamps.extend(acc.seen_stamp_idx);
        added += acc.added;
        modified += acc.modified;
        can_build_files &= acc.can_build_files;
    }

    let deleted = meta.file_stamps.len().saturating_sub(seen_stamps.len());

    let mut changed_count = added + deleted + modified;
    if changed_count == 0 && blueprint_changed {
        changed_count = 1;
    }

    let (scanned_files, fingerprint) = if can_build_files && !built_files.is_empty() {
        built_files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        let mut repo_hasher = blake3::Hasher::new();
        if let Some((_, ref bp_hash)) = blueprint_opt {
            repo_hasher.update(b"blueprint:");
            repo_hasher.update(bp_hash.as_bytes());
            repo_hasher.update(b"\n");
        }
        for file in &built_files {
            repo_hasher.update(file.rel_path.as_bytes());
            repo_hasher.update(b":");
            repo_hasher.update(&file.size_bytes.to_le_bytes());
            repo_hasher.update(b":");
            repo_hasher.update(file.blake3_hash.as_bytes());
            repo_hasher.update(b"\n");
        }
        let fp = repo_hasher.finalize().to_hex()[..16].to_string();
        (Some(built_files), fp)
    } else {
        (None, String::new())
    };

    Some(StampCheck {
        unchanged: changed_count == 0,
        suspects,
        suspect_rel_paths,
        changed_count,
        added,
        deleted,
        touched_mtimes,
        scanned_files,
        fingerprint,
    })
}

/// Checks how many files were added, deleted, or modified compared to `meta.file_stamps`
/// using the stat-only `stamp_check` fast path (reading only suspect files whose `mtime`/`size` changed).
pub fn check_meta_files_changed(
    repo_path: &Path,
    meta: &RepoMetadata,
    max_file_bytes: u64,
) -> Option<usize> {
    stamp_check(repo_path, meta, max_file_bytes).map(|sc| sc.changed_count)
}

/// Checks how many files were added, deleted, or modified compared to `cached.files`.
pub fn check_files_changed(
    repo_path: &Path,
    cached: &IncrementalAstCache,
    max_file_bytes: u64,
) -> Result<usize> {
    let (scanned_files, live_fp) =
        match scan_repository(repo_path, cached.vendor_mode, max_file_bytes) {
            Ok(res) => res,
            Err(ChipsrcError::NoSourceFilesFound(_)) => return Ok(cached.files.len()),
            Err(e) => return Err(e),
        };

    let mut changed = 0usize;
    let mut seen_paths = HashSet::with_capacity(scanned_files.len());

    for file in &scanned_files {
        seen_paths.insert(file.rel_path.as_str());
        match cached.files.get(&file.rel_path) {
            Some(cached_unit) => {
                if cached_unit.scanned.size_bytes != file.size_bytes
                    || cached_unit.scanned.blake3_hash != file.blake3_hash
                    || cached_unit.scanned.scope != file.scope
                    || cached_unit.scanned.arch_layer != file.arch_layer
                {
                    changed += 1;
                }
            }
            None => {
                changed += 1;
            }
        }
    }

    for cached_rel_path in cached.files.keys() {
        if !seen_paths.contains(cached_rel_path.as_str()) {
            changed += 1;
        }
    }

    if changed == 0 && !cached.fingerprint.is_empty() && cached.fingerprint != live_fp {
        changed = 1;
    }

    Ok(changed)
}

/// Deterministically groups files into logical module shards while honoring `.chipsrc.json`
/// `shards` overrides when present.
pub fn assign_section_id_with_blueprint(
    rel_path: &str,
    scope: FileScope,
    arch_layer: ArchLayer,
    blueprint: Option<&RepoBlueprint>,
) -> (String, String, String) {
    if let Some(bp) = blueprint {
        if let Some((matched_prefix, custom_shard)) = match_longest_prefix(rel_path, &bp.shards) {
            let slug = sanitize_slug(custom_shard);
            let layer_str = arch_layer.as_str();
            let title = format!("{matched_prefix} ({layer_str})");
            return (slug, title, matched_prefix);
        }
    }
    assign_section_id(rel_path, scope, arch_layer)
}

/// Deterministically groups files into logical module shards and returns
/// `(section_slug, section_title, module_path)`.
pub fn assign_section_id(
    rel_path: &str,
    scope: FileScope,
    arch_layer: ArchLayer,
) -> (String, String, String) {
    let normalized = rel_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    let layer_str = arch_layer.as_str();

    // Case 1: Workspace / multi-package layouts (`crates/<name>/...`, `packages/<name>/...`,
    // `apps/<name>/...`, `services/<name>/...`, `modules/<name>/...`, `components/<name>/...`)
    if parts.len() >= 3
        && matches!(
            parts[0],
            "crates" | "packages" | "apps" | "services" | "modules" | "components"
        )
    {
        let container = parts[0];
        let pkg_name = parts[1];
        if scope == FileScope::Test
            || matches!(
                parts.get(2).copied(),
                Some("tests" | "test" | "benches" | "evals")
            )
        {
            let module_path = format!("{container}/{pkg_name}/tests");
            let slug = sanitize_slug(&format!("{container}-{pkg_name}-tests"));
            let title = format!("{module_path} ({layer_str})");
            return (slug, title, module_path);
        }
        let module_path = format!("{container}/{pkg_name}");
        let slug = sanitize_slug(&format!("{container}-{pkg_name}"));
        let title = format!("{module_path} ({layer_str})");
        return (slug, title, module_path);
    }

    // Number of directory segments is `parts.len().saturating_sub(1)`
    let dir_count = parts.len().saturating_sub(1);
    if dir_count >= 3
        && matches!(
            parts[0].to_ascii_lowercase().as_str(),
            "src" | "fw" | "firmware" | "app" | "apps" | "source"
        )
        && matches!(
            parts[1].to_ascii_lowercase().as_str(),
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
    {
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
        let module_path = "root".to_string();
        let slug = "root".to_string();
        let title = format!("Root Module ({layer_str})");
        (slug, title, module_path)
    }
}

/// Analyzes onboarding signals for `chipsrc inspect` so an agent on Turn 1 can see
/// unclassified directories, workspace subprojects, and unknown C qualifier macros.
pub fn analyze_onboarding_signals(
    repo_path: &Path,
    scanned_files: &[ScannedFile],
    blueprint: Option<&RepoBlueprint>,
) -> (bool, Vec<String>, Vec<String>, Vec<String>) {
    let has_blueprint = blueprint.is_some();

    // 1. Unclassified directories (first-party files that fell back to ArchLayer::Other)
    let mut unclassified_set: BTreeSet<String> = BTreeSet::new();
    for file in scanned_files {
        if file.scope == FileScope::FirstParty && file.arch_layer == ArchLayer::Other {
            let parts: Vec<&str> = file.rel_path.split('/').filter(|s| !s.is_empty()).collect();
            let dir_count = parts.len().saturating_sub(1);
            if dir_count >= 2 {
                unclassified_set.insert(format!("{}/{}", parts[0], parts[1]));
            } else if dir_count == 1 {
                unclassified_set.insert(parts[0].to_string());
            }
        }
    }

    // 2. Detected workspaces / subproject manifests
    let mut workspaces_set: BTreeSet<String> = BTreeSet::new();
    const MANIFEST_NAMES: &[&str] = &[
        "Cargo.toml",
        "package.json",
        "CMakeLists.txt",
        "platformio.ini",
        "Kconfig",
        "pyproject.toml",
    ];
    for container in [
        "crates",
        "packages",
        "apps",
        "services",
        "modules",
        "components",
    ] {
        let container_dir = repo_path.join(container);
        if let Ok(entries) = fs::read_dir(&container_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    if let Some(sub) = p.file_name().and_then(|s| s.to_str()) {
                        if !sub.starts_with('.') {
                            workspaces_set.insert(format!("{container}/{sub}"));
                        }
                    }
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir(repo_path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let Some(dir_name) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if dir_name.starts_with('.') || IGNORED_DIRS.contains(&dir_name) {
                continue;
            }
            if MANIFEST_NAMES.iter().any(|m| p.join(m).is_file()) {
                workspaces_set.insert(dir_name.to_string());
            }
        }
    }

    // 3. Candidate C/C++ qualifier macros before function declarators
    let mut candidate_macros: BTreeSet<String> = BTreeSet::new();
    let custom_quals: HashSet<&str> = blueprint
        .map(|bp| bp.c_qualifiers.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

    for file in scanned_files
        .iter()
        .filter(|f| matches!(f.language, LanguageKind::C | LanguageKind::Cpp))
        .take(40)
    {
        let Ok(content) = fs::read_to_string(&file.abs_path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with('/')
                || trimmed.starts_with('*')
                || !trimmed.contains('(')
            {
                continue;
            }
            let mut tokens = trimmed.split_whitespace();
            let Some(first) = tokens.next() else {
                continue;
            };
            let Some(second) = tokens.next() else {
                continue;
            };
            if is_candidate_unknown_c_qualifier(first, second, &custom_quals) {
                candidate_macros.insert(first.to_string());
            }
        }
    }

    (
        has_blueprint,
        unclassified_set.into_iter().collect(),
        workspaces_set.into_iter().collect(),
        candidate_macros.into_iter().collect(),
    )
}

fn is_candidate_unknown_c_qualifier(
    first: &str,
    second: &str,
    custom_quals: &HashSet<&str>,
) -> bool {
    if first.len() < 3
        || custom_quals.contains(first)
        || !first
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || !first.bytes().any(|b| b.is_ascii_uppercase())
    {
        return false;
    }
    // Skip macros already normalized by parser.rs
    if matches!(
        first,
        "__I"
            | "__O"
            | "__IO"
            | "__IM"
            | "__OM"
            | "__IOM"
            | "__IAR_FT"
            | "__ALIGNED"
            | "STATIC"
            | "CONST"
            | "INLINE"
            | "__INLINE"
            | "__INLINE__"
            | "FORCEINLINE"
            | "__FORCEINLINE"
            | "__STATIC_INLINE"
            | "__STATIC_FORCEINLINE"
            | "STATIC_INLINE"
            | "STATIC_FORCEINLINE"
            | "WEAK"
            | "__WEAK"
            | "__IRQ"
            | "__INTERRUPT"
            | "__RAMFUNC"
            | "RAMFUNC"
            | "__PACKED"
            | "PACKED"
            | "ISR"
            | "SIGNAL"
            | "EXTERN"
    ) || first.ends_with("_STATIC_INLINE")
        || first.ends_with("_STATIC_FORCEINLINE")
        || first.ends_with("_INLINE")
        || first.ends_with("_FORCEINLINE")
        || first.ends_with("_WEAK")
        || first.ends_with("_IRQ")
        || first.ends_with("_INTERRUPT")
        || first.ends_with("_RAMFUNC")
        || first.ends_with("_PACKED")
        || first.ends_with("_ALIGNED")
        || first.ends_with("_ATTR")
        || first.ends_with("_ATTRIBUTE")
    {
        return false;
    }
    let clean_second = second.trim_matches('*');
    matches!(
        clean_second,
        "void"
            | "int"
            | "char"
            | "short"
            | "long"
            | "float"
            | "double"
            | "bool"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "size_t"
            | "static"
            | "inline"
    )
}

fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os) => os.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Deterministically reports whether a repository-relative path (file path or module directory)
/// belongs to a vendor SDK / third-party component rather than first-party project code.
///
/// `size_bytes = 0` disables the large-generated-header heuristic, so no file content is needed.
pub(crate) fn path_is_vendor_owned(rel_path: &str) -> bool {
    let parts: Vec<&str> = rel_path
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return false;
    }
    if classify_file_scope(rel_path, 0, b"") == FileScope::VendorSdk {
        return true;
    }
    // Module paths carry no trailing filename, so inspect all segments as directory segments.
    dir_segments_are_vendor(&parts)
}

fn is_vendor_composite_segment(lower_seg: &str) -> bool {
    if lower_seg.ends_with("driverlib")
        || lower_seg.ends_with("cube")
        || lower_seg.ends_with("_sdk")
        || lower_seg.ends_with("-sdk")
        || lower_seg.ends_with("_hal")
        || lower_seg.ends_with("-hal")
    {
        return true;
    }

    let subtokens: Vec<&str> = lower_seg
        .split(['_', '-', '.'])
        .filter(|s| !s.is_empty())
        .collect();

    if subtokens
        .iter()
        .any(|tok| VENDOR_COMPOSITE_SUBTOKENS.contains(tok))
    {
        return true;
    }

    if subtokens.windows(2).any(|w| {
        (w[0] == "third" && w[1] == "party")
            || (w[0] == "hal" && matches!(w[1], "driver" | "drivers" | "sdk" | "lib"))
    }) {
        return true;
    }

    false
}

fn dir_segments_are_vendor(dir_segments: &[&str]) -> bool {
    for &seg in dir_segments.iter().take(2) {
        let lower_seg = seg.to_ascii_lowercase();
        if ROOT_VENDOR_DIRS.contains(&lower_seg.as_str()) {
            return true;
        }
    }
    for seg in dir_segments {
        let lower = seg.to_ascii_lowercase();
        if VENDOR_COMPONENTS.contains(&lower.as_str()) || is_vendor_composite_segment(&lower) {
            return true;
        }
    }
    false
}

fn classify_file_scope_with_blueprint(
    rel_path: &str,
    size_bytes: u64,
    bytes: &[u8],
    blueprint: Option<&RepoBlueprint>,
) -> FileScope {
    if let Some(bp) = blueprint {
        if let Some((_, &scope)) = match_longest_prefix(rel_path, &bp.scopes) {
            return scope;
        }
    }
    classify_file_scope(rel_path, size_bytes, bytes)
}

fn classify_file_scope(rel_path: &str, size_bytes: u64, bytes: &[u8]) -> FileScope {
    let parts: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
    let filename = parts.last().copied().unwrap_or(rel_path);
    let lower_filename = filename.to_ascii_lowercase();
    let dir_segments = &parts[..parts.len().saturating_sub(1)];

    // 1. Vendor SDK ownership: checked strictly against directory segments (`dir_segments`)
    // so a first-party file whose filename happens to match a token is never misclassified.
    if dir_segments_are_vendor(dir_segments) {
        return FileScope::VendorSdk;
    }

    // Check if > 200 KiB .h/.hpp file containing device register definitions
    if size_bytes > 200 * 1024
        && (lower_filename.ends_with(".h") || lower_filename.ends_with(".hpp"))
        && (memchr::memmem::find(bytes, b"_TypeDef").is_some()
            || memchr::memmem::find(bytes, b"typedef struct").is_some()
            || memchr::memmem::find(bytes, b"__IO").is_some()
            || memchr::memmem::find(bytes, b"__IOM").is_some()
            || memchr::memmem::find(bytes, b"__IM").is_some()
            || memchr::memmem::find(bytes, b"__OM").is_some()
            || memchr::memmem::find(bytes, b"__IAR_FT").is_some())
    {
        return FileScope::VendorSdk;
    }

    // 2. Test / benchmark / evaluation code, including composite directory names such as
    // `test_utils/` or `motor_tests/`.
    for seg in dir_segments {
        let lower = seg.to_ascii_lowercase();
        if TEST_COMPONENTS.contains(&lower.as_str())
            || lower.starts_with("test_")
            || lower.ends_with("_test")
            || lower.ends_with("_tests")
        {
            return FileScope::Test;
        }
    }

    if lower_filename.starts_with("test_")
        || lower_filename.ends_with("_test.rs")
        || lower_filename.ends_with("_test.py")
        || lower_filename.ends_with("_test.c")
        || lower_filename.ends_with("_test.cpp")
        || lower_filename.ends_with(".test.ts")
        || lower_filename.ends_with(".spec.ts")
        || lower_filename.ends_with(".test.js")
        || lower_filename.ends_with(".spec.js")
        || lower_filename.ends_with(".test.tsx")
        || lower_filename.ends_with(".spec.tsx")
    {
        return FileScope::Test;
    }

    FileScope::FirstParty
}

/// Returns `true` when a vendor-owned path sits inside an SDK `examples/`, `samples/`, `demos/`,
/// or `templates/` directory tree (which holds reference demo applications rather than the SDK library).
fn is_vendor_example_or_demo_path(rel_path: &str) -> bool {
    let parts: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
    let dir_segments = &parts[..parts.len().saturating_sub(1)];
    dir_segments.iter().any(|seg| {
        matches!(
            seg.to_ascii_lowercase().as_str(),
            "examples"
                | "example"
                | "samples"
                | "sample"
                | "demos"
                | "demo"
                | "templates"
                | "template"
        )
    })
}

fn classify_arch_layer_with_blueprint(
    rel_path: &str,
    scope: FileScope,
    blueprint: Option<&RepoBlueprint>,
) -> ArchLayer {
    if let Some(bp) = blueprint {
        if let Some((_, &layer)) = match_longest_prefix(rel_path, &bp.layers) {
            return layer;
        }
    }
    classify_arch_layer(rel_path, scope)
}

fn classify_arch_layer(rel_path: &str, scope: FileScope) -> ArchLayer {
    match scope {
        FileScope::VendorSdk => return ArchLayer::VendorHal,
        FileScope::Test => return ArchLayer::Tests,
        FileScope::FirstParty => {}
    }

    let parts: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
    let dir_segments = &parts[..parts.len().saturating_sub(1)];
    let mut resolved_layer: Option<ArchLayer> = None;
    for seg in dir_segments {
        let lower = seg.to_ascii_lowercase();
        if let Some(layer) = match_segment_to_layer(&lower) {
            if resolved_layer.is_none() {
                resolved_layer = Some(layer);
            } else if resolved_layer == Some(ArchLayer::App) && layer == ArchLayer::Api {
                // Route subdirectories such as `src/pages/api/*` refine `App` to `Api`.
                resolved_layer = Some(ArchLayer::Api);
            }
        }
    }

    let stem_opt = parts.last().map(|filename| {
        filename
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(filename)
            .to_ascii_lowercase()
    });

    // When a directory resolves to generic `Core` (e.g. `crates/*-core/src/`) or `None`,
    // allow pure domain/error/schema file stems to refine the layer to `ArchLayer::Domain`
    // so intra-crate layered-DAG edges (`core -> domain`) and upward violations are tracked.
    if matches!(resolved_layer, None | Some(ArchLayer::Core)) {
        if let Some(ref stem) = stem_opt {
            if matches!(
                stem.as_str(),
                "model"
                    | "models"
                    | "error"
                    | "errors"
                    | "schema"
                    | "schemas"
                    | "entity"
                    | "entities"
            ) {
                return ArchLayer::Domain;
            }
        }
    }

    if let Some(layer) = resolved_layer {
        return layer;
    }

    if let Some(stem) = stem_opt {
        if stem == "lib" {
            return ArchLayer::Core;
        }
        if let Some(layer) = match_segment_to_layer(&stem) {
            return layer;
        }
    }

    ArchLayer::Other
}

fn match_segment_to_layer(lower: &str) -> Option<ArchLayer> {
    match lower {
        "app" | "application" | "apps" | "web" | "frontend" | "client" | "ui" | "components"
        | "views" | "pages" | "screens" | "widgets" | "layouts" => Some(ArchLayer::App),
        "bsp" | "board" | "boards" | "platform" => Some(ArchLayer::Bsp),
        "drvs" | "drv" | "drivers" | "driver" | "nfc" | "peripherals" => Some(ArchLayer::Drivers),
        "config" | "configs" | "cfg" => Some(ArchLayer::Config),
        "libs" | "lib" | "utils" | "common" | "security" | "helpers" | "shell" => {
            Some(ArchLayer::Libs)
        }
        "domain" | "models" | "entities" | "schema" | "schemas" => Some(ArchLayer::Domain),
        "services" | "service" | "sync" | "database" | "db" | "auth" | "plugins" | "features"
        | "store" => Some(ArchLayer::Services),
        "api" | "routes" | "endpoints" | "controllers" | "handlers" => Some(ArchLayer::Api),
        "cli" | "bin" | "scripts" | "tools" => Some(ArchLayer::Cli),
        "core" | "engine" | "kernel" => Some(ArchLayer::Core),
        s if s.ends_with("-cli") => Some(ArchLayer::Cli),
        s if s.ends_with("-core") => Some(ArchLayer::Core),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DEFAULT_MAX_FILE_BYTES;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("{prefix}_{}_{id}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create temp test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Writes a fixture source file, creating parent directories as needed.
    fn write_src(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture dir");
        }
        std::fs::write(path, content).expect("write fixture file");
    }

    /// Sets a deterministic mtime on a fixture file (std-only, no `filetime` dependency).
    fn set_mtime(path: &Path, modified: std::time::SystemTime) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open fixture for mtime")
            .set_modified(modified)
            .expect("set fixture mtime");
    }

    #[test]
    fn test_assign_section_id() {
        let (slug, title, module) = assign_section_id(
            "crates/chipsrc-core/src/parser.rs",
            FileScope::FirstParty,
            ArchLayer::Core,
        );
        assert_eq!(slug, "crates-chipsrc-core");
        assert_eq!(module, "crates/chipsrc-core");
        assert_eq!(title, "crates/chipsrc-core (core)");

        let (test_slug, test_title, test_mod) = assign_section_id(
            "crates/chipsrc-core/tests/integration_tests.rs",
            FileScope::Test,
            ArchLayer::Tests,
        );
        assert_eq!(test_slug, "crates-chipsrc-core-tests");
        assert_eq!(test_mod, "crates/chipsrc-core/tests");
        assert_eq!(test_title, "crates/chipsrc-core/tests (tests)");

        let (slug2, title2, module2) =
            assign_section_id("fw/drvs/motor.c", FileScope::FirstParty, ArchLayer::Drivers);
        assert_eq!(slug2, "fw-drvs");
        assert_eq!(module2, "fw/drvs");
        assert_eq!(title2, "fw/drvs (drvs)");

        let (slug3, title3, module3) =
            assign_section_id("src/main.rs", FileScope::FirstParty, ArchLayer::App);
        assert_eq!(slug3, "src");
        assert_eq!(module3, "src");
        assert_eq!(title3, "src (app)");

        let (slug4, title4, module4) =
            assign_section_id("main.c", FileScope::FirstParty, ArchLayer::Other);
        assert_eq!(slug4, "root");
        assert_eq!(module4, "root");
        assert_eq!(title4, "Root Module (other)");
    }

    #[test]
    fn test_classify_scope_and_layer() {
        let scope1 = classify_file_scope("vendor/cmsis/device.h", 1024, b"struct Foo {};");
        assert_eq!(scope1, FileScope::VendorSdk);
        assert_eq!(
            classify_arch_layer("vendor/cmsis/device.h", scope1),
            ArchLayer::VendorHal
        );

        let scope2 = classify_file_scope("tests/integration_test.rs", 500, b"fn test_it() {}");
        assert_eq!(scope2, FileScope::Test);
        assert_eq!(
            classify_arch_layer("tests/integration_test.rs", scope2),
            ArchLayer::Tests
        );

        let scope3 = classify_file_scope("fw/drvs/pwm.c", 500, b"void pwm_init(void) {}");
        assert_eq!(scope3, FileScope::FirstParty);
        assert_eq!(
            classify_arch_layer("fw/drvs/pwm.c", scope3),
            ArchLayer::Drivers
        );

        let scope4 = classify_file_scope("crates/chipsrc-cli/src/main.rs", 500, b"fn main() {}");
        assert_eq!(scope4, FileScope::FirstParty);
        assert_eq!(
            classify_arch_layer("crates/chipsrc-cli/src/main.rs", scope4),
            ArchLayer::Cli
        );

        // Intra-crate domain stem refinement inside `*-core` crates
        assert_eq!(
            classify_arch_layer("crates/chipsrc-core/src/model.rs", FileScope::FirstParty),
            ArchLayer::Domain
        );
        assert_eq!(
            classify_arch_layer("crates/chipsrc-core/src/error.rs", FileScope::FirstParty),
            ArchLayer::Domain
        );
        assert_eq!(
            classify_arch_layer("crates/chipsrc-core/src/parser.rs", FileScope::FirstParty),
            ArchLayer::Core
        );
    }

    #[test]
    fn test_classify_composite_vendor_directories() {
        // Composite directory names embedding a vendor token must still be vendor-owned.
        let driverlib = classify_file_scope("drvs/My_DriverLib/foo.c", 500, b"void f(void) {}");
        assert_eq!(driverlib, FileScope::VendorSdk);
        assert_eq!(
            classify_arch_layer("drvs/My_DriverLib/foo.c", driverlib),
            ArchLayer::VendorHal
        );

        let stm32 =
            classify_file_scope("references/libs/STM32Cube/bar.c", 500, b"void bar(void) {}");
        assert_eq!(stm32, FileScope::VendorSdk);

        let cmsis_core = classify_file_scope(
            "fw/platform/CMSIS_CORE/startup.c",
            500,
            b"void Reset_Handler(void) {}",
        );
        assert_eq!(cmsis_core, FileScope::VendorSdk);

        let hal_driver =
            classify_file_scope("fw/hal_driver/uart.c", 500, b"void uart_init(void) {}");
        assert_eq!(hal_driver, FileScope::VendorSdk);

        // Plain exact components still resolve to vendor ownership.
        assert_eq!(
            classify_file_scope(
                "fw/deps/zlib/inflate.c",
                300,
                b"int inflate(void) { return 0; }"
            ),
            FileScope::VendorSdk
        );

        // First-party composite names that do not embed a vendor token stay first-party.
        assert_eq!(
            classify_file_scope("fw/drvs/motor_driver/pwm.c", 500, b"void pwm(void) {}"),
            FileScope::FirstParty
        );
        assert_eq!(
            classify_file_scope("fw/drvs/pwm.c", 500, b"void pwm(void) {}"),
            FileScope::FirstParty
        );
    }

    #[test]
    fn test_path_is_vendor_owned_module_paths() {
        assert!(path_is_vendor_owned("vendor/cmsis"));
        assert!(path_is_vendor_owned("references/libs"));
        assert!(path_is_vendor_owned("drvs/My_DriverLib"));
        assert!(!path_is_vendor_owned("src/app"));
        assert!(!path_is_vendor_owned("src/drvs"));
        assert!(!path_is_vendor_owned("root"));
        assert!(!path_is_vendor_owned(""));
    }

    #[test]
    fn test_classify_composite_test_directories() {
        assert_eq!(
            classify_file_scope("fw/test_utils/helpers.c", 500, b"void h(void) {}"),
            FileScope::Test
        );
        assert_eq!(
            classify_file_scope("fw/motor_tests/harness.c", 500, b"void h(void) {}"),
            FileScope::Test
        );
        assert_eq!(
            classify_file_scope("fw/bench_test/bench.c", 500, b"void b(void) {}"),
            FileScope::Test
        );
        assert_eq!(
            classify_arch_layer(
                "fw/test_utils/helpers.c",
                classify_file_scope("fw/test_utils/helpers.c", 500, b"void h(void) {}")
            ),
            ArchLayer::Tests
        );
    }

    #[test]
    fn test_bundled_js_asset_detection() {
        assert!(is_bundled_js_asset("jquery.min.js"));
        assert!(is_bundled_js_asset("jquery.js"));
        assert!(is_bundled_js_asset("modernizr-2.8.3.min.js"));
        assert!(is_bundled_js_asset("underscore.js"));
        assert!(is_bundled_js_asset("bootstrap.min.js"));
        assert!(is_bundled_js_asset("mermaid.min.js"));
        assert!(is_bundled_js_asset("prettify.min.js"));
        assert!(is_bundled_js_asset("searchdata.js"));
        assert!(is_bundled_js_asset("navtree.js"));
        assert!(is_bundled_js_asset("dynsections.js"));
        assert!(is_bundled_js_asset("runtime.min.js"));

        assert!(!is_bundled_js_asset("app.js"));
        assert!(!is_bundled_js_asset("bootstrap.js"));
        assert!(!is_bundled_js_asset("mermaid_renderer.js"));
        assert!(!is_bundled_js_asset("motor_control.js"));
        assert!(!is_bundled_js_asset("main.ts"));
        assert!(!is_bundled_js_asset("minified.h"));
    }

    #[test]
    fn test_scan_repository_skips_docs_vendor_examples_and_honors_claudeignore() {
        let tmp = TestTempDir::new("chipsrc_scanner_ignore_test");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs/_static")).unwrap();
        std::fs::create_dir_all(root.join("doxygen/html")).unwrap();
        std::fs::create_dir_all(root.join("generated")).unwrap();
        std::fs::create_dir_all(root.join("vendor/sdk/examples/blinky")).unwrap();

        std::fs::write(root.join("src/app.c"), "int app_main(void) { return 0; }\n").unwrap();
        std::fs::write(
            root.join("docs/_static/jquery.min.js"),
            "!function(){}();\n",
        )
        .unwrap();
        std::fs::write(root.join("doxygen/html/searchdata.js"), "var x = 1;\n").unwrap();
        std::fs::write(
            root.join("generated/skip_me.c"),
            "int skipped(void) { return 1; }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("vendor/sdk/examples/blinky/main.c"),
            "int main(void) { return 0; }\n",
        )
        .unwrap();
        std::fs::write(root.join(".claudeignore"), "generated/\n").unwrap();

        let (files, fingerprint) = scan_repository(root, VendorMode::All, DEFAULT_MAX_FILE_BYTES)
            .expect("scan_repository");
        let rel_paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(rel_paths, vec!["src/app.c"]);
        assert_eq!(fingerprint.len(), 16);
        assert_eq!(files[0].scope, FileScope::FirstParty);
    }

    #[test]
    fn stamp_check_detects_same_second_same_size_edit() {
        use std::time::Duration;

        let tmp = TestTempDir::new("chipsrc_scanner_same_sec");
        let repo_dir = tmp.path().join("repo");
        let out_dir = tmp.path().join("bundle");
        std::fs::create_dir_all(repo_dir.join("src")).unwrap();

        let file_path = repo_dir.join("src/lib.c");
        let content_v1 = "int alpha_fn(void) { return 1; }\n";
        let content_v2 = "int bravo_fn(void) { return 1; }\n";
        assert_eq!(content_v1.len(), content_v2.len());

        std::fs::write(&file_path, content_v1).unwrap();
        let t0 = UNIX_EPOCH + Duration::new(1_700_000_000, 100_000_000);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(t0)
            .unwrap();

        let cfg = crate::model::ConvertConfig::new(repo_dir.clone(), out_dir);
        let bundle = crate::convert_repo(&cfg).expect("initial convert_repo");

        let sc_clean =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert!(sc_clean.unchanged);
        assert_eq!(sc_clean.changed_count, 0);

        // Same-size edit +100ms within the same whole second
        std::fs::write(&file_path, content_v2).unwrap();
        let t1 = UNIX_EPOCH + Duration::new(1_700_000_000, 200_000_000);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(t1)
            .unwrap();

        let sc_dirty =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert!(
            !sc_dirty.unchanged,
            "Expected same-second same-size edit to be detected as changed"
        );
        assert_eq!(sc_dirty.changed_count, 1);
        assert_eq!(sc_dirty.suspects.len(), 1);
    }

    #[test]
    fn stamp_check_never_reads_unchanged_file_content() {
        use std::time::Duration;

        let tmp = TestTempDir::new("chipsrc_scanner_stat_only");
        let repo_dir = tmp.path().join("repo");
        let out_dir = tmp.path().join("bundle");

        let file_path = repo_dir.join("src/lib.c");
        let content_v1 = "int alpha_fn(void) { return 1; }\n";
        let content_v2 = "int bravo_fn(void) { return 1; }\n";
        assert_eq!(content_v1.len(), content_v2.len());

        write_src(&file_path, content_v1);
        let t0 = UNIX_EPOCH + Duration::new(1_700_000_100, 250_000_000);
        set_mtime(&file_path, t0);

        let cfg = crate::model::ConvertConfig::new(repo_dir.clone(), out_dir);
        let bundle = crate::convert_repo(&cfg).expect("initial convert_repo");

        // Replace the body with a different same-size program and restore the exact mtime.
        // A content read would see `bravo_fn`, so an unchanged result proves the stat-only path.
        write_src(&file_path, content_v2);
        set_mtime(&file_path, t0);

        let sc =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert!(
            sc.unchanged,
            "unchanged (size, mtime_secs, mtime_nanos) must be trusted without reading content"
        );
        assert_eq!(sc.changed_count, 0);
        assert!(sc.suspects.is_empty());
        assert!(sc.suspect_rel_paths.is_empty());
    }

    #[test]
    fn stamp_check_parallel_walk_covers_nested_files_adds_and_deletes() {
        let tmp = TestTempDir::new("chipsrc_scanner_parallel");
        let repo_dir = tmp.path().join("repo");
        let out_dir = tmp.path().join("bundle");
        let mut paths = Vec::new();
        for dir in 0..4 {
            for file in 0..10 {
                let path = repo_dir.join(format!("mod{dir}/nested/file{file}.c"));
                write_src(
                    &path,
                    &format!("int fn_{dir}_{file}(void) {{ return {file}; }}\n"),
                );
                paths.push(path);
            }
        }

        let cfg = crate::model::ConvertConfig::new(repo_dir.clone(), out_dir);
        let bundle = crate::convert_repo(&cfg).expect("initial convert_repo");

        let clean =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert!(clean.unchanged);
        assert_eq!(clean.changed_count, 0);
        let scanned = clean
            .scanned_files
            .expect("clean walk yields scanned files");
        assert_eq!(scanned.len(), 40);
        assert!(
            scanned.windows(2).all(|w| w[0].rel_path < w[1].rel_path),
            "parallel walk must still return rel_path-sorted files"
        );

        write_src(&paths[0], "int fn_edited(void) { return 42; }\n");
        write_src(
            &repo_dir.join("mod3/nested/new_file.c"),
            "int brand_new(void) { return 7; }\n",
        );
        std::fs::remove_file(&paths[1]).unwrap();

        let dirty =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert!(!dirty.unchanged);
        assert_eq!(dirty.added, 1, "one nested file was added");
        assert_eq!(dirty.deleted, 1, "one nested file was deleted");
        assert_eq!(dirty.changed_count, 3);
        assert_eq!(dirty.suspect_rel_paths.len(), 2, "edit + add are suspects");
        assert!(dirty
            .suspect_rel_paths
            .iter()
            .any(|p| p == "mod0/nested/file0.c"));
        assert!(dirty
            .suspect_rel_paths
            .iter()
            .any(|p| p == "mod3/nested/new_file.c"));
    }

    /// A vendor-SDK example/demo file that appears after indexing is excluded by the full scan
    /// (it is never indexed), so it must not invalidate `StampCheck::scanned_files`. Before the
    /// fix the `can_build_files = false` flag was set before the vendor-example filters ran, so
    /// extracting a vendor SDK's `examples/` tree forced a full rescan during self-heal.
    #[test]
    fn stamp_check_vendor_example_files_do_not_invalidate_scanned_files() {
        let tmp = TestTempDir::new("chipsrc_scanner_vendor_examples");
        let repo_dir = tmp.path().join("repo");
        let out_dir = tmp.path().join("bundle");
        write_src(&repo_dir.join("src/app.c"), "int app(void) { return 0; }\n");
        write_src(
            &repo_dir.join("vendor/sdk/inc/sdk_core.h"),
            "int sdk_init(void);\n",
        );

        let cfg = crate::model::ConvertConfig::new(repo_dir.clone(), out_dir);
        let bundle = crate::convert_repo(&cfg).expect("initial convert_repo");

        let clean =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        let baseline = clean
            .scanned_files
            .expect("clean walk yields scanned files");
        assert_eq!(baseline.len(), 2, "first-party + vendor SDK source");

        // A vendor example file appears (as when a vendor SDK submodule is extracted).
        write_src(
            &repo_dir.join("vendor/sdk/examples/blinky/main.c"),
            "int main(void) { return 0; }\n",
        );

        let after =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert!(
            after.unchanged,
            "a filtered-out vendor example file is not an indexed change"
        );
        assert_eq!(after.added, 0, "vendor example files are not indexed adds");
        assert!(after.suspects.is_empty());
        let files = after
            .scanned_files
            .expect("filtered-out vendor example must not invalidate scanned_files");
        assert_eq!(files.len(), 2);
        assert!(!files.iter().any(|f| f.rel_path.contains("examples/blinky")));

        // Control: a genuinely new first-party file *does* invalidate the reusable list, because
        // the full scan would have to index it.
        write_src(
            &repo_dir.join("src/extra.c"),
            "int extra(void) { return 1; }\n",
        );
        let real_add =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert_eq!(real_add.added, 1);
        assert!(
            real_add.scanned_files.is_none(),
            "a real new source file cannot be served from the previous file list"
        );
    }

    #[test]
    fn stamp_check_parallel_walk_honors_gitignore_and_claudeignore() {
        let tmp = TestTempDir::new("chipsrc_scanner_parallel_ignore");
        let repo_dir = tmp.path().join("repo");
        let out_dir = tmp.path().join("bundle");
        write_src(&repo_dir.join("src/app.c"), "int app(void) { return 0; }\n");
        write_src(&repo_dir.join(".gitignore"), "ignored/\n");
        write_src(&repo_dir.join(".claudeignore"), "gen/\n");

        let cfg = crate::model::ConvertConfig::new(repo_dir.clone(), out_dir);
        let bundle = crate::convert_repo(&cfg).expect("initial convert_repo");

        write_src(
            &repo_dir.join("ignored/skip_me.c"),
            "int ignored_fn(void) { return 1; }\n",
        );
        write_src(
            &repo_dir.join("gen/skip_me.c"),
            "int generated_fn(void) { return 1; }\n",
        );
        write_src(
            &repo_dir.join("src/fresh.c"),
            "int fresh_fn(void) { return 1; }\n",
        );

        let sc =
            stamp_check(&repo_dir, &bundle.metadata, DEFAULT_MAX_FILE_BYTES).expect("stamp_check");
        assert_eq!(sc.added, 1, "only src/fresh.c is a real addition");
        assert_eq!(sc.changed_count, 1);
        assert!(sc.suspect_rel_paths.iter().any(|p| p == "src/fresh.c"));
        assert!(!sc
            .suspect_rel_paths
            .iter()
            .any(|p| p.starts_with("ignored/") || p.starts_with("gen/")));
    }

    #[test]
    fn bundle_artifacts_complete_with_reuses_parsed_metadata() {
        let tmp = TestTempDir::new("chipsrc_scanner_artifact_sources");
        let repo_dir = tmp.path().join("repo");
        let bundle_dir = tmp.path().join("bundle");
        write_src(
            &repo_dir.join("src/main.c"),
            "int compute_value(int x) { return x + 1; }\n",
        );

        let cfg = crate::model::ConvertConfig::new(repo_dir, bundle_dir.clone());
        crate::convert_repo(&cfg).expect("initial convert_repo");

        let meta = load_meta_file(&bundle_dir).expect("meta");
        let manifest = load_cache_manifest(&bundle_dir).expect("manifest");
        let sources = BundleArtifactSources {
            meta: Some(&meta),
            manifest: Some(&manifest),
        };
        assert!(bundle_artifacts_complete_with(&bundle_dir, sources));

        // Hiding `meta.json` must not matter when the parsed copy is supplied.
        let meta_path = bundle_dir.join("meta.json");
        let meta_backup = bundle_dir.join("meta.json.hidden");
        std::fs::rename(&meta_path, &meta_backup).unwrap();
        assert!(
            bundle_artifacts_complete_with(&bundle_dir, sources),
            "passed-in meta must be reused instead of re-reading meta.json"
        );
        assert_eq!(
            first_missing_bundle_artifact(&bundle_dir).as_deref(),
            Some("meta.json")
        );
        std::fs::rename(&meta_backup, &meta_path).unwrap();

        // A deleted cache shard is still detected through the supplied manifest.
        let shard = manifest
            .files
            .values()
            .next()
            .expect("manifest entry")
            .shard
            .clone();
        std::fs::remove_file(bundle_dir.join(&shard)).unwrap();
        assert_eq!(
            first_missing_bundle_artifact_with(&bundle_dir, sources).as_deref(),
            Some(shard.as_str())
        );
    }

    #[test]
    fn test_bundle_artifacts_complete_detects_missing_artifacts() {
        let tmp = TestTempDir::new("chipsrc_scanner_bundle_complete");
        let repo_dir = tmp.path().join("repo");
        let bundle_dir = tmp.path().join("bundle");
        std::fs::create_dir_all(repo_dir.join("src")).unwrap();
        std::fs::write(
            repo_dir.join("src/main.c"),
            "int compute_value(int x) { return x + 1; }\n",
        )
        .unwrap();

        let cfg = crate::model::ConvertConfig::new(repo_dir, bundle_dir.clone());
        crate::convert_repo(&cfg).expect("initial convert_repo");

        assert!(bundle_artifacts_complete(&bundle_dir));
        assert_eq!(first_missing_bundle_artifact(&bundle_dir), None);

        // 1. Delete, truncate to 0 bytes, or strip header of each required TSV one by one
        for tsv in [
            "index/sections.tsv",
            "index/symbols.tsv",
            "index/types.tsv",
            "index/calls.tsv",
            "index/macros.tsv",
            "index/xref.tsv",
        ] {
            let p = bundle_dir.join(tsv);
            let saved = std::fs::read(&p).unwrap();
            std::fs::remove_file(&p).unwrap();
            assert!(
                !bundle_artifacts_complete(&bundle_dir),
                "Expected incomplete when {tsv} is missing"
            );
            assert_eq!(
                first_missing_bundle_artifact(&bundle_dir).as_deref(),
                Some(tsv)
            );

            // 0-byte TSV must also be treated as missing/incomplete
            std::fs::write(&p, b"").unwrap();
            assert!(
                !bundle_artifacts_complete(&bundle_dir),
                "Expected incomplete when {tsv} is 0 bytes"
            );
            assert_eq!(
                first_missing_bundle_artifact(&bundle_dir).as_deref(),
                Some(tsv)
            );

            // Header-less TSV must also be treated as missing/incomplete
            std::fs::write(&p, b"not_a_valid_header\tcol2\n").unwrap();
            assert!(
                !bundle_artifacts_complete(&bundle_dir),
                "Expected incomplete when {tsv} lacks its header line"
            );
            assert_eq!(
                first_missing_bundle_artifact(&bundle_dir).as_deref(),
                Some(tsv)
            );

            std::fs::write(&p, saved).unwrap();
            assert!(bundle_artifacts_complete(&bundle_dir));
        }

        // 2. Delete a sections/*.md referenced in index/sections.tsv col 11
        let sec_tsv = std::fs::read_to_string(bundle_dir.join("index/sections.tsv")).unwrap();
        let md_rel = sec_tsv
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .nth(10)
            .unwrap()
            .to_string();
        let full_md_rel = if md_rel.starts_with("sections/") {
            md_rel
        } else {
            format!("sections/{md_rel}")
        };
        let md_path = bundle_dir.join(&full_md_rel);
        let saved_md = std::fs::read(&md_path).unwrap();
        std::fs::remove_file(&md_path).unwrap();
        assert!(!bundle_artifacts_complete(&bundle_dir));
        assert_eq!(
            first_missing_bundle_artifact(&bundle_dir).as_deref(),
            Some(full_md_rel.as_str())
        );
        std::fs::write(&md_path, saved_md).unwrap();
        assert!(bundle_artifacts_complete(&bundle_dir));

        // 3. Delete a cache/<hash>.json shard referenced in cache/manifest.json
        let manifest = load_cache_manifest(&bundle_dir).expect("manifest");
        let shard_rel = manifest.files.values().next().unwrap().shard.clone();
        let shard_path = bundle_dir.join(&shard_rel);
        let saved_shard = std::fs::read(&shard_path).unwrap();
        std::fs::remove_file(&shard_path).unwrap();
        assert!(!bundle_artifacts_complete(&bundle_dir));
        assert_eq!(
            first_missing_bundle_artifact(&bundle_dir).as_deref(),
            Some(shard_rel.as_str())
        );
        std::fs::write(&shard_path, saved_shard).unwrap();
        assert!(bundle_artifacts_complete(&bundle_dir));

        // 4. Delete INDEX.md and meta.json
        for top in ["INDEX.md", "meta.json"] {
            let p = bundle_dir.join(top);
            let saved = std::fs::read(&p).unwrap();
            std::fs::remove_file(&p).unwrap();
            assert!(!bundle_artifacts_complete(&bundle_dir));
            assert_eq!(
                first_missing_bundle_artifact(&bundle_dir).as_deref(),
                Some(top)
            );
            std::fs::write(&p, saved).unwrap();
            assert!(bundle_artifacts_complete(&bundle_dir));
        }
    }

    #[test]
    fn test_count_source_lines_empty_trailing_and_no_trailing_newline() {
        assert_eq!(count_source_lines(b""), 0);
        assert_eq!(count_source_lines(b"a = 1\n"), 1);
        assert_eq!(count_source_lines(b"a = 1"), 1);
        assert_eq!(count_source_lines(b"a = 1\na = 2\na = 3\n"), 3);
        assert_eq!(count_source_lines(b"b = 1\nb = 2\nb = 3"), 3);
        assert_eq!(count_source_lines(b"a = 1\r\na = 2\r\na = 3\r\n"), 3);
        assert_eq!(count_source_lines(b"b = 1\r\nb = 2\r\nb = 3"), 3);
    }

    #[test]
    fn test_cache_shard_key_disambiguates_identical_content_across_paths() {
        use crate::model::CacheShardEntry;

        let content_hash = "b1fb471e4a2045ee";
        let key_alpha = CacheShardEntry::shard_key("alpha/mod.py", content_hash);
        let key_beta = CacheShardEntry::shard_key("beta/mod.py", content_hash);
        assert_eq!(key_alpha.len(), 16);
        assert_eq!(key_beta.len(), 16);
        assert_ne!(key_alpha, key_beta);
        assert_eq!(
            CacheShardEntry::shard_rel_path("alpha/mod.py", content_hash),
            format!("cache/{key_alpha}.json")
        );
        assert_eq!(
            CacheShardEntry::shard_key("alpha/mod.py", content_hash),
            key_alpha
        );
    }

    #[test]
    fn test_packed_cache_shard_loader_reads_each_pack_once_and_restores_fields() {
        use crate::model::{
            ArchLayer, ExtractedSymbol, FileScope, LanguageKind, ParsedFileUnit, ScannedFile,
            SymbolKind, Visibility,
        };

        let tmp = std::env::temp_dir().join(format!(
            "chipsrc_scanner_pack_{}_{}",
            std::process::id(),
            "load"
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache_dir = tmp.join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        fn make_unit(rel_path: &str, symbol: &str) -> ParsedFileUnit {
            ParsedFileUnit {
                scanned: ScannedFile {
                    rel_path: rel_path.to_string(),
                    abs_path: std::path::PathBuf::from(rel_path),
                    language: LanguageKind::Python,
                    scope: FileScope::FirstParty,
                    arch_layer: ArchLayer::Domain,
                    size_bytes: 32,
                    mtime_secs: 1,
                    mtime_nanos: 0,
                    blake3_hash: format!("{rel_path}-hash"),
                    line_count: 2,
                },
                symbols: vec![ExtractedSymbol {
                    symbol_id: format!("{rel_path}::{symbol}"),
                    name: symbol.to_string(),
                    qualified_name: symbol.to_string(),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: rel_path.to_string(),
                    start_line: 1,
                    end_line: 2,
                    signature: format!("def {symbol}():"),
                    doc_summary: String::new(),
                    enclosing_type: None,
                    scope: FileScope::FirstParty,
                    arch_layer: ArchLayer::Domain,
                    section_id: "mod".to_string(),
                }],
                types: Vec::new(),
                macros: Vec::new(),
                imports: Vec::new(),
                raw_calls: Vec::new(),
                raw_xrefs: Vec::new(),
                parse_errors: 0,
            }
        }

        let units = vec![
            make_unit("alpha/mod.py", "alpha_probe"),
            make_unit("beta/mod.py", "beta_probe"),
            make_unit("gamma/mod.py", "gamma_probe"),
        ];
        let pack_name = "pack-0123456789abcdef.json";
        let pack_rel = format!("cache/{pack_name}");
        let json = serde_json::to_string(&units).unwrap();
        std::fs::write(cache_dir.join(pack_name), json).unwrap();

        // A multi-unit pack is not a single shard; the unit-aware loaders must be used.
        assert!(load_cache_shard(&tmp, &pack_rel).is_none());
        let loaded = load_cache_shard_unit(&tmp, &pack_rel, "beta/mod.py").expect("packed unit");
        assert_eq!(loaded.symbols[0].file, "beta/mod.py");
        assert_eq!(loaded.symbols[0].symbol_id, "beta/mod.py::beta_probe");

        let requests = vec![
            ("alpha/mod.py".to_string(), pack_rel.clone()),
            ("gamma/mod.py".to_string(), pack_rel.clone()),
        ];
        let mut by_path = load_cache_units(&tmp, &requests);
        assert_eq!(by_path.len(), 2);
        let gamma = by_path.remove("gamma/mod.py").expect("gamma unit");
        assert_eq!(gamma.symbols[0].name, "gamma_probe");
        assert_eq!(gamma.symbols[0].file, "gamma/mod.py");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
