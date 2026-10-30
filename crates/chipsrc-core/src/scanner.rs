//! Layer 1 — Parallel `.gitignore`-aware repository scanner, scope/layer classifier,
//! deterministic BLAKE3 fingerprinting, and logical module shard assignment.

use crate::error::{ChipsrcError, Result};
use crate::model::{
    ArchLayer, FileScope, IncrementalAstCache, LanguageKind, RepoBlueprint, ScannedFile, VendorMode,
};
use ignore::WalkBuilder;
use rayon::prelude::*;
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

/// Loads `<repo_path>/.chipsrc.json` if present, returning the parsed [`RepoBlueprint`]
/// together with its 16-character BLAKE3 content hash.
pub fn load_repo_blueprint(repo_path: &Path) -> Option<(RepoBlueprint, String)> {
    let bp_path = repo_path.join(".chipsrc.json");
    let bytes = fs::read(&bp_path).ok()?;
    let bp: RepoBlueprint = serde_json::from_slice(&bytes).ok()?;
    let full_hash = blake3::hash(&bytes).to_hex();
    let hash = full_hash[..16].to_string();
    Some((bp, hash))
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
        .map(|(bp, _)| bp.ignore_dirs.clone())
        .unwrap_or_default();

    let mut walker = WalkBuilder::new(repo_path);
    walker
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .hidden(true)
        .add_custom_ignore_filename(".claudeignore")
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_ascii_lowercase();
                    if IGNORED_DIRS.contains(&lower.as_str()) {
                        return false;
                    }
                    if custom_ignore_dirs.iter().any(|ig| {
                        let clean = ig.trim_matches('/');
                        clean.eq_ignore_ascii_case(name)
                    }) {
                        return false;
                    }
                }
            }
            true
        });

    let mut candidate_paths: Vec<(PathBuf, String, LanguageKind, u64, u64)> = Vec::new();
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

        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let rel_path = match abs_path.strip_prefix(repo_path) {
            Ok(rel) => normalize_rel_path(rel),
            Err(_) => normalize_rel_path(&abs_path),
        };
        if rel_path.is_empty() {
            continue;
        }
        if let Some(bp) = bp_ref {
            if path_matches_ignore_dirs(&rel_path, &bp.ignore_dirs) {
                continue;
            }
        }

        candidate_paths.push((abs_path, rel_path, language, size_bytes, mtime_secs));
    }

    let mut scanned_files: Vec<ScannedFile> = candidate_paths
        .into_par_iter()
        .filter_map(|(abs_path, rel_path, language, size_bytes, mtime_secs)| {
            let bytes = fs::read(&abs_path).ok()?;
            if bytes.is_empty() {
                return None;
            }

            let scope = classify_file_scope_with_blueprint(&rel_path, size_bytes, &bytes, bp_ref);
            if vendor_mode == VendorMode::None && scope == FileScope::VendorSdk {
                return None;
            }

            let arch_layer = classify_arch_layer_with_blueprint(&rel_path, scope, bp_ref);
            let line_count = memchr::memchr_iter(b'\n', &bytes).count() + 1;
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
                blake3_hash,
                line_count,
            })
        })
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
    _scope: FileScope,
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
        let module_path = format!("{container}/{pkg_name}");
        let slug = sanitize_slug(&format!("{container}-{pkg_name}"));
        let title = format!("{module_path} ({layer_str})");
        return (slug, title, module_path);
    }

    // Number of directory segments is `parts.len().saturating_sub(1)`
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
        "STATIC"
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
    if let Some(first) = dir_segments.first() {
        let lower_first = first.to_ascii_lowercase();
        if ROOT_VENDOR_DIRS.contains(&lower_first.as_str()) {
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
            || memchr::memmem::find(bytes, b"__IO").is_some())
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
    if let Some(layer) = resolved_layer {
        return layer;
    }

    if let Some(filename) = parts.last() {
        let stem = filename
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(filename)
            .to_ascii_lowercase();
        if let Some(layer) = match_segment_to_layer(&stem) {
            return layer;
        }
    }

    ArchLayer::Other
}

fn match_segment_to_layer(lower: &str) -> Option<ArchLayer> {
    match lower {
        "app" | "application" | "apps" | "pages" | "views" | "screens" => Some(ArchLayer::App),
        "bsp" | "board" | "boards" | "platform" => Some(ArchLayer::Bsp),
        "drvs" | "drv" | "drivers" | "driver" | "nfc" | "peripherals" => Some(ArchLayer::Drivers),
        "config" | "configs" | "cfg" => Some(ArchLayer::Config),
        "libs" | "lib" | "utils" | "common" | "security" | "helpers" | "ui" | "components"
        | "widgets" | "shell" | "layouts" => Some(ArchLayer::Libs),
        "domain" | "models" | "entities" | "schema" | "schemas" => Some(ArchLayer::Domain),
        "services" | "service" | "sync" | "database" | "db" | "auth" | "plugins" | "features"
        | "store" => Some(ArchLayer::Services),
        "api" | "frontend" | "routes" | "endpoints" | "controllers" | "handlers" | "web" => {
            Some(ArchLayer::Api)
        }
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
    fn test_ignored_dirs_include_docs_and_static_assets() {
        for dir in [
            "_static",
            "_build",
            "doxygen",
            "coverage",
            "htmlcov",
            ".tox",
            ".nox",
            "wheelhouse",
            "node_modules",
            "target",
        ] {
            assert!(
                IGNORED_DIRS.contains(&dir),
                "Expected IGNORED_DIRS to contain '{dir}'"
            );
        }
        // Generic first-party package names must never be globally ignored.
        assert!(!IGNORED_DIRS.contains(&"site"));
        assert!(!IGNORED_DIRS.contains(&"html"));
    }

    #[test]
    fn test_scan_repository_skips_docs_and_honors_claudeignore() {
        let root = std::env::temp_dir().join(format!(
            "chipsrc_scanner_ignore_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs/_static")).unwrap();
        std::fs::create_dir_all(root.join("doxygen/html")).unwrap();
        std::fs::create_dir_all(root.join("generated")).unwrap();

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
        std::fs::write(root.join(".claudeignore"), "generated/\n").unwrap();

        let (files, fingerprint) =
            scan_repository(&root, VendorMode::All, 4 * 1024 * 1024).expect("scan_repository");
        let rel_paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(rel_paths, vec!["src/app.c"]);
        assert_eq!(fingerprint.len(), 16);
        assert_eq!(files[0].scope, FileScope::FirstParty);

        let _ = std::fs::remove_dir_all(&root);
    }
}
