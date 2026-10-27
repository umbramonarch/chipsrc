//! `chipsrc-core` — Multi-language AST extraction, static call-graph,
//! code + hardware cross-reference graph, and Agent Codebase Bundle engine.

pub mod emitter;
pub mod error;
pub mod graph;
pub mod mmio;
pub mod model;
pub mod parser;
pub mod query;
pub mod resolver;
pub mod sanity;
pub mod scanner;
pub mod sharder;

pub use crate::error::{ChipsrcError, Result};
pub use crate::model::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Inspects a repository's language breakdown, first-party vs. vendor SDK file counts,
/// line counts, and detected architectural layers without writing a bundle to disk.
pub fn inspect_repo(repo_path: &Path, vendor_mode: VendorMode) -> Result<InspectReport> {
    let (scanned_files, fingerprint) =
        scanner::scan_repository(repo_path, vendor_mode, 4 * 1024 * 1024)?;
    let (source_root, repo_name) = canonical_repo_root_and_name(repo_path);

    let total_files = scanned_files.len();
    let first_party_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::FirstParty)
        .count();
    let vendor_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::VendorSdk)
        .count();
    let test_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::Test)
        .count();
    let total_lines: usize = scanned_files.iter().map(|f| f.line_count).sum();
    let languages = compute_language_stats(&scanned_files);

    let mut layer_set: BTreeSet<ArchLayer> = BTreeSet::new();
    for f in &scanned_files {
        layer_set.insert(f.arch_layer);
    }
    let mut layers_vec: Vec<ArchLayer> = layer_set.into_iter().collect();
    layers_vec.sort_by(|a, b| {
        b.rank()
            .cmp(&a.rank())
            .then_with(|| a.as_str().cmp(b.as_str()))
    });
    let detected_layers = layers_vec
        .into_iter()
        .map(|l| l.as_str().to_string())
        .collect();

    Ok(InspectReport {
        repo_name,
        source_root,
        fingerprint,
        total_files,
        first_party_files,
        vendor_files,
        test_files,
        total_lines,
        languages,
        detected_layers,
    })
}

/// Converts and indexes a source repository into a Hierarchical Agent Codebase Bundle.
///
/// Supports fast-path `<5ms` cache hits when the repository BLAKE3 Merkle fingerprint
/// matches `meta.json`, and incremental per-file AST caching via `cache.json` so only
/// modified or added files are re-parsed on subsequent runs.
pub fn convert_repo(config: &ConvertConfig) -> Result<ConversionBundle> {
    let start = Instant::now();
    let (scanned_files, fingerprint) =
        scanner::scan_repository(&config.repo_path, config.vendor_mode, config.max_file_bytes)?;
    let (source_root, repo_name) = canonical_repo_root_and_name(&config.repo_path);

    let meta_path = config.output_dir.join("meta.json");
    let index_md_path = config.output_dir.join("INDEX.md");
    let cache_path = config.output_dir.join("cache.json");
    let single_md_path = config.output_dir.join(format!("{repo_name}.md"));

    // Fast-path cache hit when repository fingerprint and vendor_mode match existing bundle
    if !config.force
        && meta_path.is_file()
        && index_md_path.is_file()
        && cache_path.is_file()
        && (!config.single_file || single_md_path.is_file())
    {
        if let Some(mut existing_meta) = load_meta_file(&config.output_dir) {
            if existing_meta.metadata.fingerprint == fingerprint
                && existing_meta.metadata.vendor_mode == config.vendor_mode
            {
                let claudeignore_updated =
                    emitter::ensure_claudeignore_entry(&config.output_dir).unwrap_or(false);
                existing_meta.metadata.elapsed_ms = start.elapsed().as_millis() as u64;
                existing_meta.metadata.incremental_reparsed_files = 0;
                existing_meta.metadata.incremental_reused_files =
                    existing_meta.metadata.total_files;

                return Ok(ConversionBundle {
                    output_dir: config.output_dir.clone(),
                    metadata: existing_meta.metadata,
                    sanity: existing_meta.sanity,
                    sections: Vec::new(),
                    indexes: BundleIndexes::default(),
                    cache_hit: true,
                    claudeignore_updated,
                });
            }
        }
    }

    // Load incremental per-file AST cache if available and not forcing full rebuild
    let existing_cache = if !config.force && cache_path.is_file() {
        load_cache_file(&config.output_dir)
    } else {
        None
    };

    let (units, incremental_reused_files, incremental_reparsed_files) =
        parser::parse_files_incremental(&scanned_files, existing_cache.as_ref())?;

    let (symbols, mut types, mut macros, mut calls, mut xrefs, vendor_surface) =
        resolver::resolve_and_link(&units);

    let (mut ranked_symbols, mut god_nodes, mut entrypoints, layer_edges, cycles) =
        graph::analyze_graph(symbols, &calls, &units);

    let (section_summaries, sections) = sharder::build_section_shards(
        &units,
        &mut ranked_symbols,
        &mut types,
        &mut macros,
        &mut calls,
        &mut xrefs,
        &vendor_surface,
        config.vendor_mode,
    );

    // Synchronize numbered section_ids onto god_nodes and entrypoints
    {
        let sym_sec_map: BTreeMap<&str, &str> = ranked_symbols
            .iter()
            .map(|rs| (rs.symbol.symbol_id.as_str(), rs.symbol.section_id.as_str()))
            .collect();
        for gn in &mut god_nodes {
            if let Some(&sec_id) = sym_sec_map.get(gn.symbol.symbol_id.as_str()) {
                gn.symbol.section_id = sec_id.to_string();
            }
        }
        for ep in &mut entrypoints {
            if let Some(&sec_id) = sym_sec_map.get(ep.symbol.symbol_id.as_str()) {
                ep.symbol.section_id = sec_id.to_string();
            }
        }
    }

    let indexes = BundleIndexes {
        sections: section_summaries,
        symbols: ranked_symbols,
        types,
        calls,
        macros,
        xrefs,
        god_nodes,
        entrypoints,
        layer_edges,
        cycles,
        vendor_surface,
    };

    let sanity = sanity::compute_sanity_report(&units, &indexes, &sections);

    let total_files = scanned_files.len();
    let first_party_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::FirstParty)
        .count();
    let vendor_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::VendorSdk)
        .count();
    let test_files = scanned_files
        .iter()
        .filter(|f| f.scope == FileScope::Test)
        .count();
    let total_lines: usize = scanned_files.iter().map(|f| f.line_count).sum();
    let languages = compute_language_stats(&scanned_files);

    let mut cache_files = BTreeMap::new();
    for unit in units {
        cache_files.insert(unit.scanned.rel_path.clone(), unit);
    }
    let cache = IncrementalAstCache {
        schema_version: "1.0.0".to_string(),
        repo_root: source_root.clone(),
        vendor_mode: config.vendor_mode,
        files: cache_files,
    };

    let elapsed_ms = start.elapsed().as_millis() as u64;

    let metadata = RepoMetadata {
        repo_name,
        source_root,
        fingerprint,
        vendor_mode: config.vendor_mode,
        total_files,
        first_party_files,
        vendor_files,
        test_files,
        total_lines,
        languages,
        section_count: sections.len(),
        symbol_count: indexes.symbols.len(),
        type_count: indexes.types.len(),
        call_edge_count: indexes.calls.len(),
        macro_count: indexes.macros.len(),
        xref_count: indexes.xrefs.len(),
        god_node_count: indexes.god_nodes.len(),
        entrypoint_count: indexes.entrypoints.len(),
        elapsed_ms,
        incremental_reused_files,
        incremental_reparsed_files,
    };

    let claudeignore_updated =
        emitter::emit_bundle(config, &metadata, &sanity, &sections, &indexes, &cache)?;

    Ok(ConversionBundle {
        output_dir: config.output_dir.clone(),
        metadata,
        sanity,
        sections,
        indexes,
        cache_hit: false,
        claudeignore_updated,
    })
}

/// Ensures a repository is indexed under `<output_root>/<repo_stem>` and incrementally
/// synchronized via `cache.json`.
pub fn ensure_repo(
    repo_path: &Path,
    output_root: &Path,
    force: bool,
    vendor_mode: VendorMode,
) -> Result<ConversionBundle> {
    let (_, repo_stem) = canonical_repo_root_and_name(repo_path);
    let output_dir = output_root.join(repo_stem);
    let mut cfg = ConvertConfig::new(repo_path.to_path_buf(), output_dir);
    cfg.force = force;
    cfg.vendor_mode = vendor_mode;
    convert_repo(&cfg)
}

/// Checks all provided `bundles` against their live `source_root` on disk and incrementally
/// refreshes any stale bundles in place. Returns the number of refreshed bundles.
pub fn auto_refresh_bundles(bundles: &[PathBuf]) -> Result<usize> {
    let mut refreshed = 0usize;

    for bundle_dir in bundles {
        let Some(meta_file) = load_meta_file(bundle_dir) else {
            continue;
        };
        let meta = meta_file.metadata;
        let source_path = Path::new(&meta.source_root);
        if !source_path.is_dir() {
            continue;
        }

        let needs_refresh = if let Some(cache) = load_cache_file(bundle_dir) {
            scanner::check_files_changed(source_path, &cache, 4 * 1024 * 1024).unwrap_or(0) > 0
                || scanner::scan_repository(source_path, meta.vendor_mode, 4 * 1024 * 1024)
                    .map(|(_, fp)| fp != meta.fingerprint)
                    .unwrap_or(false)
        } else if let Ok((_, fp)) =
            scanner::scan_repository(source_path, meta.vendor_mode, 4 * 1024 * 1024)
        {
            fp != meta.fingerprint
        } else {
            false
        };

        if needs_refresh {
            let mut cfg = ConvertConfig::new(source_path.to_path_buf(), bundle_dir.clone());
            cfg.vendor_mode = meta.vendor_mode;
            cfg.force = false;
            cfg.single_file = bundle_dir.join(format!("{}.md", meta.repo_name)).is_file();
            convert_repo(&cfg)?;
            refreshed += 1;
        }
    }

    Ok(refreshed)
}

fn canonical_repo_root_and_name(repo_path: &Path) -> (String, String) {
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

fn compute_language_stats(scanned_files: &[ScannedFile]) -> Vec<LanguageStat> {
    let mut map: BTreeMap<&'static str, LanguageStat> = BTreeMap::new();
    for file in scanned_files {
        let key = file.language.as_str();
        let entry = map.entry(key).or_insert_with(|| LanguageStat {
            language: key.to_string(),
            files: 0,
            lines: 0,
            first_party_files: 0,
            vendor_files: 0,
        });
        entry.files += 1;
        entry.lines += file.line_count;
        match file.scope {
            FileScope::FirstParty => entry.first_party_files += 1,
            FileScope::VendorSdk => entry.vendor_files += 1,
            FileScope::Test => {}
        }
    }

    let mut stats: Vec<LanguageStat> = map.into_values().collect();
    stats.sort_by(|a, b| {
        b.files
            .cmp(&a.files)
            .then_with(|| b.lines.cmp(&a.lines))
            .then_with(|| a.language.cmp(&b.language))
    });
    stats
}

fn load_meta_file(bundle_dir: &Path) -> Option<BundleMetaFile> {
    let bytes = fs::read(bundle_dir.join("meta.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn load_cache_file(bundle_dir: &Path) -> Option<IncrementalAstCache> {
    let bytes = fs::read(bundle_dir.join("cache.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}
