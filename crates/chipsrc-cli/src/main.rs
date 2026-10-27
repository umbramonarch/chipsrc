use anyhow::{Context, Result};
use chipsrc_core::query::{
    parallel_bundle_search, query_callees, query_callers, query_macros, query_sections,
    query_symbols, query_types, query_xref, resolve_bundles, resolve_target_and_query,
    workspace_status,
};
use chipsrc_core::{
    auto_refresh_bundles, convert_repo, ensure_repo, inspect_repo, ConversionBundle, ConvertConfig,
    VendorMode,
};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "chipsrc",
    version,
    about = "Agent Code Intelligence CLI: index, auto-sync, and query firmware & software repositories in 1 turn"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Convert/index a repository into a Hierarchical Agent Codebase Bundle
    #[command(visible_alias = "index")]
    Convert {
        /// Repository path to index
        #[arg(default_value = ".")]
        repo: PathBuf,

        /// Output bundle directory (defaults to `output/<repo_stem>`)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Also emit a single merged `<repo_stem>.md` file alongside `sections/*.md`
        #[arg(long)]
        single_file: bool,

        /// Force a full re-index even when `cache.json` and `meta.json` are up to date
        #[arg(short, long)]
        force: bool,

        /// Vendor SDK handling mode (`active`, `all`, `none`)
        #[arg(long, default_value = "active")]
        vendor_mode: String,
    },

    /// Ensure one or more repositories are indexed and incrementally synchronized (`<2ms` on cache hit)
    Ensure {
        /// Repository paths to ensure (defaults to `.`)
        repos: Vec<PathBuf>,

        /// Output root directory (each repo creates `<output_root>/<repo_stem>/`)
        #[arg(
            short = 'o',
            long = "output-root",
            visible_alias = "out",
            default_value = "output"
        )]
        output_root: PathBuf,

        /// Force full re-index even if cached
        #[arg(short, long)]
        force: bool,

        /// Vendor SDK handling mode (`active`, `all`, `none`)
        #[arg(long, default_value = "active")]
        vendor_mode: String,
    },

    /// Show indexed codebase bundles and their live freshness status (`FRESH` vs `STALE`)
    Status {
        /// Workspace or output directory to scan
        #[arg(default_value = ".")]
        workspace: PathBuf,

        /// Immediately synchronize any stale bundles via incremental AST cache refresh
        #[arg(long)]
        sync: bool,
    },

    /// Inspect a repository's language breakdown, first-party vs vendor SDK scope, and architectural layers
    Inspect {
        /// Repository path to inspect
        #[arg(default_value = ".")]
        repo: PathBuf,

        /// Vendor SDK handling mode (`active`, `all`, `none`)
        #[arg(long, default_value = "active")]
        vendor_mode: String,

        /// Emit inspection report as pretty-printed JSON
        #[arg(long)]
        json: bool,
    },

    /// Look up function, method, constructor, entrypoint, or ISR definitions in 1 turn
    Sym {
        /// Either `<query>` (searches `./output`) or `<bundle_or_repo>` followed by `<query>`
        target_or_query: String,

        /// Optional `<query>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Filter by symbol kind (`fn`, `method`, `isr`, `ctor`, `entrypoint`)
        #[arg(short, long)]
        kind: Option<String>,

        /// Extract and display the exact source implementation body inline
        #[arg(short, long)]
        show: bool,

        /// Maximum matching symbols to return
        #[arg(short, long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// List all static callers of a function, method, or ISR across the codebase
    Callers {
        /// Either `<symbol>` or `<bundle_or_repo>` followed by `<symbol>`
        target_or_query: String,

        /// Optional `<symbol>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Show caller source lines around each call site
        #[arg(short, long)]
        show: bool,

        /// Maximum caller edges to return
        #[arg(short, long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// List all static callees invoked by a function, method, or ISR
    Callees {
        /// Either `<symbol>` or `<bundle_or_repo>` followed by `<symbol>`
        target_or_query: String,

        /// Optional `<symbol>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Show callee definitions or call-site source context
        #[arg(short, long)]
        show: bool,

        /// Maximum callee edges to return
        #[arg(short, long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// Look up struct, enum, union, trait, interface, class, or typedef layouts and fields
    Type {
        /// Either `<query>` or `<bundle_or_repo>` followed by `<query>`
        target_or_query: String,

        /// Optional `<query>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Extract and display the full source definition inline
        #[arg(short, long)]
        show: bool,

        /// Maximum matching types to return
        #[arg(short, long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// Look up `#define` macros, constants, bitmasks, and MMIO register hex addresses (`0x41C00004`, `400h`)
    #[command(visible_alias = "reg", visible_alias = "mmio")]
    Macro {
        /// Either `<query>` or `<bundle_or_repo>` followed by `<query>`
        target_or_query: String,

        /// Optional `<query>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Show surrounding source lines at the macro/register definition or access site
        #[arg(short, long)]
        show: bool,

        /// Maximum matching macros/MMIO entries to return
        #[arg(short, long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// List or inspect architectural module shards (`sections/*.md`)
    Section {
        /// Optional `<query>` or `<bundle_or_repo>` followed by `<query>`
        #[arg(default_value = "")]
        target_or_query: String,

        /// Optional `<query>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Print the full Markdown signature skeleton body for matching section shards
        #[arg(short, long)]
        show: bool,

        /// Maximum matching sections to return
        #[arg(short, long, default_value_t = 20)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// Traverse the Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`)
    #[command(visible_alias = "explain")]
    Xref {
        /// Either `<query>` or `<bundle_or_repo>` followed by `<query>`
        target_or_query: String,

        /// Optional `<query>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Maximum cross-reference edges to return
        #[arg(short, long, default_value_t = 40)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },

    /// Parallel SIMD + Regex search across all indexed Agent Codebase Bundles
    Search {
        /// Either `<pattern>` or `<bundle_or_repo>` followed by `<pattern>`
        target_or_query: String,

        /// Optional `<pattern>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Filter search target (`all`, `symbols`, `types`, `calls`, `macros`, `xref`, `sections`)
        #[arg(short, long, default_value = "all")]
        kind: String,

        /// Case-insensitive matching
        #[arg(short, long)]
        ignore_case: bool,

        /// Maximum matches to return
        #[arg(short, long, default_value_t = 50)]
        limit: usize,

        /// Truncate long snippets for minimal token usage
        #[arg(long)]
        compact: bool,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Convert {
            repo,
            output,
            single_file,
            force,
            vendor_mode,
        } => {
            let vmode = parse_vendor_mode(&vendor_mode)?;
            let output_dir = match output {
                Some(dir) => dir,
                None => {
                    let stem = derive_repo_stem(&repo);
                    PathBuf::from("output").join(stem)
                }
            };
            println!(
                "==> Indexing '{}' -> '{}' (vendor-mode={}) ...",
                repo.display(),
                output_dir.display(),
                vmode.as_str()
            );

            let mut cfg = ConvertConfig::new(repo.clone(), output_dir);
            cfg.single_file = single_file;
            cfg.force = force;
            cfg.vendor_mode = vmode;

            let bundle = convert_repo(&cfg)
                .with_context(|| format!("Failed to index repository '{}'", repo.display()))?;
            print_conversion_summary(&bundle);
        }

        Commands::Ensure {
            repos,
            output_root,
            force,
            vendor_mode,
        } => {
            let vmode = parse_vendor_mode(&vendor_mode)?;
            let targets = if repos.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                repos
            };

            for repo in targets {
                let bundle = ensure_repo(&repo, &output_root, force, vmode)
                    .with_context(|| format!("Failed to ensure repository '{}'", repo.display()))?;
                let tag = if bundle.cache_hit {
                    "CACHE HIT"
                } else if bundle.metadata.incremental_reused_files > 0 {
                    "INCREMENTAL SYNC"
                } else {
                    "INDEXED"
                };
                println!(
                    "[{tag}] {} -> {} ({} files [{}/{} reparsed/reused], {} syms, {} types, {} calls, {} macros, {} xrefs, sanity {}/100 in {}ms)",
                    repo.display(),
                    bundle.output_dir.display(),
                    bundle.metadata.total_files,
                    bundle.metadata.incremental_reparsed_files,
                    bundle.metadata.incremental_reused_files,
                    bundle.metadata.symbol_count,
                    bundle.metadata.type_count,
                    bundle.metadata.call_edge_count,
                    bundle.metadata.macro_count,
                    bundle.metadata.xref_count,
                    bundle.sanity.score,
                    bundle.metadata.elapsed_ms,
                );
            }
        }

        Commands::Status { workspace, sync } => {
            let mut entries = workspace_status(&workspace).with_context(|| {
                format!(
                    "Failed to scan workspace status at '{}'",
                    workspace.display()
                )
            })?;

            if sync && !entries.is_empty() {
                let bundle_dirs: Vec<PathBuf> =
                    entries.iter().map(|e| e.bundle_dir.clone()).collect();
                let refreshed = auto_refresh_bundles(&bundle_dirs)?;
                if refreshed > 0 {
                    println!("Synchronized {refreshed} stale bundle(s).");
                    entries = workspace_status(&workspace)?;
                }
            }

            println!("=== chipsrc Workspace Status ({}) ===", workspace.display());
            if entries.is_empty() {
                println!("Indexed Bundles : (none)");
            } else {
                println!("Indexed Bundles ({}):", entries.len());
                for entry in &entries {
                    let freshness = if entry.is_fresh {
                        "FRESH".to_string()
                    } else {
                        format!("STALE ({} files changed)", entry.changed_files_count)
                    };
                    println!(
                        "  [{freshness}] {:<24} | {:>5} symbols | {:>3} sections | {} (source: {})",
                        entry.bundle_name,
                        entry.symbol_count,
                        entry.section_count,
                        entry.bundle_dir.display(),
                        entry.source_root,
                    );
                }
            }
        }

        Commands::Inspect {
            repo,
            vendor_mode,
            json,
        } => {
            let vmode = parse_vendor_mode(&vendor_mode)?;
            let report = inspect_repo(&repo, vmode)
                .with_context(|| format!("Failed to inspect repository '{}'", repo.display()))?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }

            println!("=== Repository Inspection: {} ===", report.repo_name);
            println!("Source Root    : {}", report.source_root);
            println!("Fingerprint    : {}", report.fingerprint);
            println!(
                "Files          : {} total ({} first-party, {} vendor SDK, {} test)",
                report.total_files,
                report.first_party_files,
                report.vendor_files,
                report.test_files
            );
            println!("Total Lines    : {}", report.total_lines);
            println!(
                "Arch Layers    : {}",
                if report.detected_layers.is_empty() {
                    "-".to_string()
                } else {
                    report.detected_layers.join(", ")
                }
            );
            println!("Languages ({})  :", report.languages.len());
            for lang in &report.languages {
                println!(
                    "  - {:<12}: {:>5} files ({:>5} first-party, {:>5} vendor) | {:>8} lines",
                    lang.language,
                    lang.files,
                    lang.first_party_files,
                    lang.vendor_files,
                    lang.lines
                );
            }
        }

        Commands::Sym {
            target_or_query,
            query,
            bundle,
            kind,
            show,
            limit,
            no_sync,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_symbols(&bundles, &q, kind.as_deref(), show, limit)?;
            print!("{out}");
        }

        Commands::Callers {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
        } => {
            let (bundles, sym) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_callers(&bundles, &sym, show, limit)?;
            print!("{out}");
        }

        Commands::Callees {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
        } => {
            let (bundles, sym) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_callees(&bundles, &sym, show, limit)?;
            print!("{out}");
        }

        Commands::Type {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_types(&bundles, &q, show, limit)?;
            print!("{out}");
        }

        Commands::Macro {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_macros(&bundles, &q, show, limit)?;
            print!("{out}");
        }

        Commands::Section {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_sections(&bundles, &q, show, limit)?;
            print!("{out}");
        }

        Commands::Xref {
            target_or_query,
            query,
            bundle,
            limit,
            no_sync,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let out = query_xref(&bundles, &q, limit)?;
            print!("{out}");
        }

        Commands::Search {
            target_or_query,
            query,
            bundle,
            kind,
            ignore_case,
            limit,
            compact,
            no_sync,
        } => {
            let (bundles, pattern) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let hits = parallel_bundle_search(&bundles, &pattern, &kind, ignore_case, limit)?;
            if hits.is_empty() {
                println!("No search hits for pattern '{pattern}' (kind={kind}).");
            } else {
                println!(
                    "=== Search Hits for '{}' (kind={}, {} matches) ===",
                    pattern,
                    kind,
                    hits.len()
                );
                for hit in &hits {
                    let snippet = if compact && hit.snippet.chars().count() > 120 {
                        let truncated: String = hit.snippet.chars().take(120).collect();
                        format!("{truncated}...")
                    } else {
                        hit.snippet.clone()
                    };
                    if hit.line > 0 {
                        println!(
                            "  [{} | {}] {}:{} -> {}",
                            hit.bundle_name, hit.kind, hit.file, hit.line, snippet
                        );
                    } else {
                        println!(
                            "  [{} | {}] {} -> {}",
                            hit.bundle_name, hit.kind, hit.file, snippet
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn parse_vendor_mode(raw: &str) -> Result<VendorMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => Ok(VendorMode::Active),
        "all" => Ok(VendorMode::All),
        "none" => Ok(VendorMode::None),
        other => {
            anyhow::bail!("Invalid --vendor-mode '{other}'. Expected one of: active, all, none")
        }
    }
}

fn derive_repo_stem(repo: &Path) -> String {
    let canonical = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    canonical
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != ".")
        .unwrap_or("repo")
        .to_string()
}

fn resolve_cli_target_and_query(
    target_or_query: &str,
    query: Option<&str>,
    explicit_bundle: Option<&Path>,
    no_sync: bool,
) -> Result<(Vec<PathBuf>, String)> {
    let (bundles, resolved_query) = if let Some(b) = explicit_bundle {
        let bundles = resolve_bundles(b)?;
        let q = query.unwrap_or(target_or_query).to_string();
        (bundles, q)
    } else if target_or_query.is_empty() && query.is_none() {
        let bundles = resolve_bundles(Path::new("."))?;
        (bundles, String::new())
    } else {
        resolve_target_and_query(target_or_query, query)?
    };

    if !no_sync && !bundles.is_empty() {
        let _ = auto_refresh_bundles(&bundles)?;
    }

    Ok((bundles, resolved_query))
}

fn print_conversion_summary(bundle: &ConversionBundle) {
    let m = &bundle.metadata;
    let s = &bundle.sanity;
    let mode_tag = if bundle.cache_hit {
        "CACHE HIT".to_string()
    } else if m.incremental_reused_files > 0 {
        format!(
            "INCREMENTAL SYNC: {} reparsed, {} reused",
            m.incremental_reparsed_files, m.incremental_reused_files
        )
    } else {
        format!("INDEXED: {} parsed", m.incremental_reparsed_files)
    };

    println!(
        "    [ok] Bundle      : {} ({})",
        bundle.output_dir.display(),
        mode_tag
    );
    println!(
        "    [ok] Master Index: {}",
        bundle.output_dir.join("INDEX.md").display()
    );
    println!(
        "    [ok] Source Files: {} total ({} first-party, {} vendor SDK, {} test) | {} lines | {} sections | vendor-mode={}",
        m.total_files,
        m.first_party_files,
        m.vendor_files,
        m.test_files,
        m.total_lines,
        m.section_count,
        m.vendor_mode.as_str()
    );
    println!(
        "    [ok] Symbols     : {} symbols ({} god nodes, {} entrypoints/ISRs) | {} types",
        m.symbol_count, m.god_node_count, m.entrypoint_count, m.type_count
    );
    println!(
        "    [ok] Call Graph  : {} call edges ({:.1}% resolved) | {} macros/MMIO | {} xrefs",
        m.call_edge_count,
        s.call_resolution_ratio * 100.0,
        m.macro_count,
        m.xref_count
    );
    println!(
        "    [ok] Sanity      : {}/100 ({:.1}% clean parse) | ~{} -> ~{} tokens ({:.1}x compression) in {}ms",
        s.score,
        s.parse_clean_ratio * 100.0,
        s.raw_source_tokens_est,
        s.bundle_index_tokens_est,
        s.token_compression_ratio,
        m.elapsed_ms
    );
    println!(
        "    [ok] ClaudeIgnore: {}",
        if bundle.claudeignore_updated {
            "updated (.claudeignore)"
        } else {
            "already configured"
        }
    );
    for warn in &s.warnings {
        println!("    [warn] {warn}");
    }
}
