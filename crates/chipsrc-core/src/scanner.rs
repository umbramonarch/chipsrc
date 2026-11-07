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
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

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

const ROOT_VENDOR_DIRS: &[&str] = &["references", "reference"];

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

const TEST_COMPONENTS: &[&str] = &["tests", "test", "evals", "benches"];

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

/// Loads repository blueprint configuration if present.
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

/// Loads and parses repository blueprint and its content hash.
pub fn load_repo_blueprint(repo_path: &Path) -> Option<(RepoBlueprint, String)> {
    load_repo_blueprint_result(repo_path).ok().flatten()
}

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

/// Counts logical source lines in a byte slice.
pub fn count_source_lines(bytes: &[u8]) -> usize {
    memchr::memchr_iter(b'\n', bytes).count()
        + usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n"))
}

fn is_c_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn c_keyword_at(bytes: &[u8], i: usize, kw: &[u8]) -> bool {
    let end = i + kw.len();
    if end > bytes.len() || &bytes[i..end] != kw {
        return false;
    }
    (i == 0 || !is_c_ident_byte(bytes[i - 1]))
        && (end == bytes.len() || !is_c_ident_byte(bytes[end]))
}

fn skip_ascii_space(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

fn delimiter_after_space(bytes: &[u8], i: usize, delim: u8) -> bool {
    bytes.get(skip_ascii_space(bytes, i)) == Some(&delim)
}

fn skip_quoted_literal(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'\n' => return i + 1,
            b if b == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn header_has_cpp_constructs(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let mut j = i + 2;
                loop {
                    let Some(offset) = memchr::memchr(b'\n', bytes.get(j..).unwrap_or_default())
                    else {
                        j = bytes.len();
                        break;
                    };
                    let newline = j + offset;
                    let mut last = newline;
                    if last > j && bytes[last - 1] == b'\r' {
                        last -= 1;
                    }
                    let continued = last > j && bytes[last - 1] == b'\\';
                    j = newline + 1;
                    if !continued {
                        break;
                    }
                }
                i = j;
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = memchr::memmem::find(bytes.get(i + 2..).unwrap_or_default(), b"*/")
                    .map_or(bytes.len(), |off| i + 2 + off + 2);
                continue;
            }
            b'"' | b'\'' => {
                i = skip_quoted_literal(bytes, i);
                continue;
            }
            b'R' if bytes.get(i + 1) == Some(&b'"')
                && (i == 0 || !is_c_ident_byte(bytes[i - 1])) =>
            {
                let delim_start = i + 2;
                let mut delim_end = delim_start;
                while delim_end < bytes.len()
                    && delim_end - delim_start < 16
                    && !matches!(bytes[delim_end], b'(' | b')' | b'\\')
                    && !bytes[delim_end].is_ascii_whitespace()
                {
                    delim_end += 1;
                }
                if bytes.get(delim_end) != Some(&b'(') {
                    i = skip_quoted_literal(bytes, i + 1);
                    continue;
                }
                let mut terminator = Vec::with_capacity(delim_end - delim_start + 2);
                terminator.push(b')');
                terminator.extend_from_slice(&bytes[delim_start..delim_end]);
                terminator.push(b'"');
                i = memchr::memmem::find(
                    bytes.get(delim_end + 1..).unwrap_or_default(),
                    &terminator,
                )
                .map_or(bytes.len(), |off| delim_end + 1 + off + terminator.len());
                continue;
            }
            b':' if bytes.get(i + 1) == Some(&b':') => return true,
            _ => {}
        }

        match bytes[i] {
            b'c' => {
                if (c_keyword_at(bytes, i, b"class")
                    && bytes.get(i + 5).is_some_and(u8::is_ascii_whitespace))
                    || c_keyword_at(bytes, i, b"constexpr")
                {
                    return true;
                }
            }
            b't' => {
                if (c_keyword_at(bytes, i, b"template")
                    && delimiter_after_space(bytes, i + 8, b'<'))
                    || c_keyword_at(bytes, i, b"typename")
                {
                    return true;
                }
            }
            b'n' => {
                if (c_keyword_at(bytes, i, b"namespace")
                    && bytes.get(i + 9).is_some_and(u8::is_ascii_whitespace))
                    || c_keyword_at(bytes, i, b"nullptr")
                {
                    return true;
                }
            }
            b'p' => {
                if (c_keyword_at(bytes, i, b"public") && delimiter_after_space(bytes, i + 6, b':'))
                    || (c_keyword_at(bytes, i, b"private")
                        && delimiter_after_space(bytes, i + 7, b':'))
                {
                    return true;
                }
            }
            b'v' if c_keyword_at(bytes, i, b"virtual") => return true,
            b'o' if c_keyword_at(bytes, i, b"operator") => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Detects language kind for a source path by extension and content.
pub fn detect_file_language(rel_path: &str, bytes: &[u8]) -> Option<LanguageKind> {
    let file_name = rel_path.rsplit(['/', '\\']).next().unwrap_or(rel_path);
    let (stem, ext) = file_name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    let language = LanguageKind::from_extension(ext)?;
    if ext.eq_ignore_ascii_case("h") && header_has_cpp_constructs(bytes) {
        return Some(LanguageKind::Cpp);
    }
    Some(language)
}

/// Returns worker thread count for parallel directory walks.
pub fn walk_parallel_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 16)
}

type ScanCandidate = (PathBuf, String, LanguageKind, u64, u64, u32);

struct ScanWalkCtx<'a> {
    repo_root: &'a Path,
    blueprint: Option<&'a RepoBlueprint>,
    max_file_bytes: u64,
}

impl ScanWalkCtx<'_> {
    fn candidate(&self, entry: &ignore::DirEntry) -> Option<ScanCandidate> {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            return None;
        }
        let abs_path = entry.path().to_path_buf();
        let ext = abs_path.extension().and_then(|e| e.to_str())?;
        let language = LanguageKind::from_extension(ext)?;

        let lower_filename = abs_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.to_ascii_lowercase())
            .unwrap_or_default();
        if is_bundled_js_asset(&lower_filename) {
            return None;
        }

        let meta = entry.metadata().ok()?;
        let size_bytes = meta.len();
        if size_bytes == 0 || size_bytes > self.max_file_bytes {
            return None;
        }

        let (mtime_secs, mtime_nanos) = file_mtime_secs_nanos(&meta);

        let rel_path = match abs_path.strip_prefix(self.repo_root) {
            Ok(rel) => normalize_rel_path(rel),
            Err(_) => normalize_rel_path(&abs_path),
        };
        if rel_path.is_empty() || is_generated_doc_asset(&rel_path, &lower_filename) {
            return None;
        }
        if let Some(bp) = self.blueprint {
            if path_matches_ignore_dirs(&rel_path, &bp.ignore_dirs) {
                return None;
            }
        }

        Some((
            abs_path,
            rel_path,
            language,
            size_bytes,
            mtime_secs,
            mtime_nanos,
        ))
    }
}

struct ScanVisitor<'a> {
    ctx: &'a ScanWalkCtx<'a>,
    acc: Vec<ScanCandidate>,
    sink: &'a Mutex<Vec<Vec<ScanCandidate>>>,
}

impl ignore::ParallelVisitor for ScanVisitor<'_> {
    fn visit(
        &mut self,
        result: std::result::Result<ignore::DirEntry, ignore::Error>,
    ) -> ignore::WalkState {
        if let Ok(entry) = result {
            if let Some(candidate) = self.ctx.candidate(&entry) {
                self.acc.push(candidate);
            }
        }
        ignore::WalkState::Continue
    }
}

impl Drop for ScanVisitor<'_> {
    fn drop(&mut self) {
        let acc = std::mem::take(&mut self.acc);
        if let Ok(mut sink) = self.sink.lock() {
            sink.push(acc);
        }
    }
}

struct ScanVisitorBuilder<'a> {
    ctx: &'a ScanWalkCtx<'a>,
    sink: &'a Mutex<Vec<Vec<ScanCandidate>>>,
}

impl<'s> ignore::ParallelVisitorBuilder<'s> for ScanVisitorBuilder<'s> {
    fn build(&mut self) -> Box<dyn ignore::ParallelVisitor + 's> {
        Box::new(ScanVisitor {
            ctx: self.ctx,
            acc: Vec::new(),
            sink: self.sink,
        })
    }
}

/// Walks the repository and produces scanned file records.
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

    let bp_ref = blueprint_opt.as_ref().map(|(bp, _)| bp);
    let ctx = ScanWalkCtx {
        repo_root: repo_path,
        blueprint: bp_ref,
        max_file_bytes,
    };
    let sink: Mutex<Vec<Vec<ScanCandidate>>> = Mutex::new(Vec::new());
    {
        let mut builder = ScanVisitorBuilder {
            ctx: &ctx,
            sink: &sink,
        };
        walker
            .threads(walk_parallel_threads())
            .build_parallel()
            .visit(&mut builder);
    }
    let mut candidate_paths: Vec<ScanCandidate> = sink
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .into_iter()
        .flatten()
        .collect();
    candidate_paths.sort_by(|a, b| a.1.cmp(&b.1));

    let mut scanned_files: Vec<ScannedFile> = candidate_paths
        .into_par_iter()
        .filter_map(
            |(abs_path, rel_path, language, size_bytes, mtime_secs, mtime_nanos)| {
                let bytes = fs::read(&abs_path).ok()?;
                if bytes.is_empty() {
                    return None;
                }
                let language = detect_file_language(&rel_path, &bytes).unwrap_or(language);

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

/// Canonicalizes repository path into normalized root and repository name.
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

/// Loads bundle metadata file if present and valid.
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

/// Loads schema-validated cache manifest from bundle directory.
pub fn load_cache_manifest(bundle_dir: &Path) -> Option<CacheManifest> {
    let manifest = load_cache_manifest_any_version(bundle_dir)?;
    if manifest.schema_version != CACHE_SCHEMA_VERSION {
        return None;
    }
    Some(manifest)
}

/// Loads cache manifest from bundle directory regardless of schema version.
pub fn load_cache_manifest_any_version(bundle_dir: &Path) -> Option<CacheManifest> {
    let manifest_path = bundle_dir.join("cache").join("manifest.json");
    let bytes = fs::read(manifest_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

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

/// Loads parsed units stored in a cache shard.
pub fn load_cache_shard_units(bundle_dir: &Path, shard_rel: &str) -> Option<Vec<ParsedFileUnit>> {
    let bytes = fs::read(bundle_dir.join(shard_rel)).ok()?;
    let mut units = parse_cache_shard_units(&bytes)?;
    for unit in &mut units {
        unit.restore_per_file_fields();
    }
    Some(units)
}

/// Loads a single parsed unit cache shard.
pub fn load_cache_shard(bundle_dir: &Path, shard_rel: &str) -> Option<ParsedFileUnit> {
    let mut units = load_cache_shard_units(bundle_dir, shard_rel)?;
    if units.len() == 1 {
        units.pop()
    } else {
        None
    }
}

/// Loads a specific unit from a cache shard by relative path.
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

/// Loads requested cache units from shard files.
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

/// Returns whether bundle directory has a valid cache manifest.
pub fn has_bundle_cache(bundle_dir: &Path) -> bool {
    load_cache_manifest(bundle_dir).is_some()
}

/// Checks whether content begins with canonical TSV header for relative path.
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

/// Pre-parsed bundle metadata sources for artifact integrity checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundleArtifactSources<'a> {
    pub meta: Option<&'a BundleMetaFile>,
    pub manifest: Option<&'a CacheManifest>,
    pub meta_attempted: bool,
    pub manifest_attempted: bool,
}

/// Returns relative path of the first missing or invalid bundle artifact.
pub fn first_missing_bundle_artifact(bundle_dir: &Path) -> Option<String> {
    first_missing_bundle_artifact_with(bundle_dir, BundleArtifactSources::default())
}

/// Checks for missing bundle artifacts using optional pre-parsed metadata.
pub fn first_missing_bundle_artifact_with(
    bundle_dir: &Path,
    sources: BundleArtifactSources<'_>,
) -> Option<String> {
    if !bundle_dir.is_dir() {
        return Some("bundle directory".to_string());
    }
    let local_meta = if sources.meta.is_none() && !sources.meta_attempted {
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

    let local_manifest = if sources.manifest.is_none() && !sources.manifest_attempted {
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

/// Returns whether all required bundle artifacts are present and valid.
pub fn bundle_artifacts_complete(bundle_dir: &Path) -> bool {
    first_missing_bundle_artifact(bundle_dir).is_none()
}

/// Returns whether bundle artifacts are complete using optional pre-parsed metadata.
pub fn bundle_artifacts_complete_with(
    bundle_dir: &Path,
    sources: BundleArtifactSources<'_>,
) -> bool {
    first_missing_bundle_artifact_with(bundle_dir, sources).is_none()
}

/// Loads incremental AST cache from manifest and shards.
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

/// Loads incremental AST cache from bundle directory.
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

/// Result of a stat-only freshness check against file stamps.
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

struct StampWalkCtx<'a> {
    repo_root: &'a Path,
    stamps: &'a [FileStamp],
    stamp_index: FxHashMap<&'a str, u32>,
    blueprint: Option<&'a RepoBlueprint>,
    vendor_mode: VendorMode,
    max_file_bytes: u64,
    blueprint_changed: bool,
}

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
            if stamp.line_count > 0 {
                acc.built_files.push(ScannedFile {
                    rel_path,
                    abs_path: abs_path.to_path_buf(),
                    language: stamp.language.unwrap_or(language),
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
        let language = detect_file_language(&rel_path, &bytes).unwrap_or(language);
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

/// Compares file stamps against repository files without reading unchanged content.
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
    let sink: Mutex<Vec<StampThreadAcc>> = Mutex::new(Vec::new());
    {
        let mut builder = StampVisitorBuilder {
            ctx: &ctx,
            sink: &sink,
        };
        walker
            .threads(walk_parallel_threads())
            .build_parallel()
            .visit(&mut builder);
    }
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

/// Checks file change counts against metadata file stamps.
pub fn check_meta_files_changed(
    repo_path: &Path,
    meta: &RepoMetadata,
    max_file_bytes: u64,
) -> Option<usize> {
    stamp_check(repo_path, meta, max_file_bytes).map(|sc| sc.changed_count)
}

/// Checks file change counts against cached files.
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

/// Assigns logical section shard ID honoring blueprint configuration.
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

/// Assigns logical section shard ID based on file path and layer.
pub fn assign_section_id(
    rel_path: &str,
    scope: FileScope,
    arch_layer: ArchLayer,
) -> (String, String, String) {
    let normalized = rel_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    let layer_str = arch_layer.as_str();

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

/// Analyzes unclassified directories, workspaces, and qualifier macros.
pub fn analyze_onboarding_signals(
    repo_path: &Path,
    scanned_files: &[ScannedFile],
    blueprint: Option<&RepoBlueprint>,
) -> (bool, Vec<String>, Vec<String>, Vec<String>) {
    let has_blueprint = blueprint.is_some();

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

    if dir_segments_are_vendor(dir_segments) {
        return FileScope::VendorSdk;
    }

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
