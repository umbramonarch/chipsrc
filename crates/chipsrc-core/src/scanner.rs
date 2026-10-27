//! Layer 1 — Parallel `.gitignore`-aware repository scanner, scope/layer classifier,
//! deterministic BLAKE3 fingerprinting, and logical module shard assignment.

use crate::error::{ChipsrcError, Result};
use crate::model::{
    ArchLayer, FileScope, IncrementalAstCache, LanguageKind, ScannedFile, VendorMode,
};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Excluded build/artifact/cache directories skipped unconditionally during walking.
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
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
];

/// Path components indicating third-party / vendor SDK ownership.
const VENDOR_COMPONENTS: &[&str] = &[
    "vendor",
    "third_party",
    "3rdparty",
    "external",
    "sdk",
    "cmsis",
    "hal",
    "driverlib",
    "stm32",
    "freertos",
    "middlewares",
    "submodules",
];

/// Path components indicating test / benchmark / evaluation code.
const TEST_COMPONENTS: &[&str] = &["tests", "test", "evals", "benches"];

/// Walks `repo_path` respecting `.gitignore` and `.claudeignore`, classifies each supported
/// source file by language, ownership scope, and architectural layer, and returns the sorted
/// file list along with a 16-character BLAKE3 repository fingerprint.
pub fn scan_repository(
    repo_path: &Path,
    vendor_mode: VendorMode,
    max_file_bytes: u64,
) -> Result<(Vec<ScannedFile>, String)> {
    if !repo_path.is_dir() {
        return Err(ChipsrcError::InvalidRepoPath(repo_path.to_path_buf()));
    }

    let mut walker = WalkBuilder::new(repo_path);
    walker
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .hidden(true)
        .add_custom_ignore_filename(".claudeignore")
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_ascii_lowercase();
                    if IGNORED_DIRS.contains(&lower.as_str()) {
                        return false;
                    }
                }
            }
            true
        });

    let mut candidate_paths: Vec<(PathBuf, String, LanguageKind, u64, u64)> = Vec::new();

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

        candidate_paths.push((abs_path, rel_path, language, size_bytes, mtime_secs));
    }

    let mut scanned_files: Vec<ScannedFile> = candidate_paths
        .into_par_iter()
        .filter_map(|(abs_path, rel_path, language, size_bytes, mtime_secs)| {
            let bytes = fs::read(&abs_path).ok()?;
            if bytes.is_empty() {
                return None;
            }

            let scope = classify_file_scope(&rel_path, size_bytes, &bytes);
            if vendor_mode == VendorMode::None && scope == FileScope::VendorSdk {
                return None;
            }

            let arch_layer = classify_arch_layer(&rel_path, scope);
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

    if scanned_files.is_empty() {
        return Err(ChipsrcError::NoSourceFilesFound(repo_path.to_path_buf()));
    }

    let mut repo_hasher = blake3::Hasher::new();
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
    let scanned_files = match scan_repository(repo_path, cached.vendor_mode, max_file_bytes) {
        Ok((files, _)) => files,
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

    Ok(changed)
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

    // Case 1: Rust workspace crate layout `crates/<crate_name>/...`
    if parts.len() >= 3 && parts[0] == "crates" {
        let crate_name = parts[1];
        let module_path = format!("crates/{crate_name}");
        let slug = sanitize_slug(&format!("crates-{crate_name}"));
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

fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os) => os.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn classify_file_scope(rel_path: &str, size_bytes: u64, bytes: &[u8]) -> FileScope {
    let parts: Vec<&str> = rel_path.split('/').collect();
    let filename = parts.last().copied().unwrap_or(rel_path);
    let lower_filename = filename.to_ascii_lowercase();

    for part in &parts {
        let lower = part.to_ascii_lowercase();
        if VENDOR_COMPONENTS.contains(&lower.as_str()) {
            return FileScope::VendorSdk;
        }
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

    for part in &parts {
        let lower = part.to_ascii_lowercase();
        if TEST_COMPONENTS.contains(&lower.as_str()) {
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

fn classify_arch_layer(rel_path: &str, scope: FileScope) -> ArchLayer {
    match scope {
        FileScope::VendorSdk => return ArchLayer::VendorHal,
        FileScope::Test => return ArchLayer::Tests,
        FileScope::FirstParty => {}
    }

    let parts: Vec<&str> = rel_path.split('/').collect();
    // Inspect directory segments first, then fall back to file stem if needed
    let dir_segments = &parts[..parts.len().saturating_sub(1)];
    for seg in dir_segments {
        let lower = seg.to_ascii_lowercase();
        if let Some(layer) = match_segment_to_layer(&lower) {
            return layer;
        }
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
        "app" | "application" | "apps" => Some(ArchLayer::App),
        "bsp" | "board" | "boards" => Some(ArchLayer::Bsp),
        "drvs" | "drv" | "drivers" | "driver" | "nfc" | "peripherals" => Some(ArchLayer::Drivers),
        "config" | "configs" | "cfg" => Some(ArchLayer::Config),
        "libs" | "lib" | "utils" | "common" | "security" => Some(ArchLayer::Libs),
        "domain" | "models" | "entities" => Some(ArchLayer::Domain),
        "services" | "service" | "sync" | "database" | "db" | "auth" => Some(ArchLayer::Services),
        "api" | "frontend" | "routes" | "ui" | "web" => Some(ArchLayer::Api),
        "cli" | "bin" => Some(ArchLayer::Cli),
        "core" => Some(ArchLayer::Core),
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
}
