use anyhow::{Context, Result};
use chipsrc_core::query::{
    parallel_bundle_search, query_call_path, query_callees, query_callers, query_impact,
    query_macros, query_sections, query_subcommand_json, query_symbols, query_types, query_xref,
    resolve_bundles, resolve_target_and_query, workspace_status,
};
use chipsrc_core::{
    auto_refresh_bundles, convert_repo, ensure_repo, inspect_repo, ConversionBundle, ConvertConfig,
    LanguageKind, VendorMode,
};
use clap::{Parser, Subcommand};
use std::io::Read;
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

        /// Print per-stage pipeline timing breakdown (`scan`, `parse`, `link`, `graph`, `shard`, `emit`)
        #[arg(long)]
        timings: bool,
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

        /// Print per-stage pipeline timing breakdown (`scan`, `parse`, `link`, `graph`, `shard`, `emit`)
        #[arg(long)]
        timings: bool,
    },

    /// Show indexed codebase bundles and their live freshness status (`FRESH` vs `STALE`)
    Status {
        /// Workspace or output directory to scan
        #[arg(default_value = ".")]
        workspace: PathBuf,

        /// Immediately synchronize any stale bundles via incremental AST cache refresh
        #[arg(long)]
        sync: bool,

        /// Exit with status code 2 when any indexed bundle is STALE (for CI checks)
        #[arg(long)]
        check: bool,

        /// Emit status entries as pretty-printed JSON
        #[arg(long)]
        json: bool,
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
        #[arg(default_value = "")]
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
        #[arg(short, short_alias = 'n', long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit matching symbols as pretty-printed JSON
        #[arg(long)]
        json: bool,
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
        #[arg(short, short_alias = 'n', long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit caller edges as pretty-printed JSON
        #[arg(long)]
        json: bool,
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
        #[arg(short, short_alias = 'n', long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit callee edges as pretty-printed JSON
        #[arg(long)]
        json: bool,
    },

    /// Look up struct, enum, union, trait, interface, class, or typedef layouts and fields
    Type {
        /// Either `<query>` or `<bundle_or_repo>` followed by `<query>`
        #[arg(default_value = "")]
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
        #[arg(short, short_alias = 'n', long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit matching types as pretty-printed JSON
        #[arg(long)]
        json: bool,
    },

    /// Look up `#define` macros, constants, bitmasks, and MMIO register hex addresses (`0x41C00004`, `400h`)
    #[command(visible_alias = "reg", visible_alias = "mmio")]
    Macro {
        /// Either `<query>` or `<bundle_or_repo>` followed by `<query>`
        #[arg(default_value = "")]
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
        #[arg(short, short_alias = 'n', long, default_value_t = 30)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit matching macros/MMIO registers as pretty-printed JSON
        #[arg(long)]
        json: bool,
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
        #[arg(short, short_alias = 'n', long, default_value_t = 20)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit matching section summaries as pretty-printed JSON
        #[arg(long)]
        json: bool,
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
        #[arg(short, short_alias = 'n', long, default_value_t = 40)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit cross-reference edges as pretty-printed JSON
        #[arg(long)]
        json: bool,
    },

    /// Find the shortest static call path (`from -> ... -> to`) across the call graph
    Path {
        /// Either `<from>` (searches `./output`) or `<bundle_or_repo>` followed by `<from>` and `<to>`
        from_or_target: String,

        /// Either `<to>` or `<from>` when the first argument is a bundle/repo path
        to_or_from: String,

        /// Optional `<to>` when the first argument is a bundle/repo path
        to: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Maximum BFS hop depth to search
        #[arg(short = 'd', long, visible_alias = "depth", default_value_t = 8)]
        max_depth: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit call path result as pretty-printed JSON
        #[arg(long)]
        json: bool,
    },

    /// Compute the reverse-BFS blast radius (`callee <- caller <- ...`) of modifying a symbol
    Impact {
        /// Either `<symbol>` or `<bundle_or_repo>` followed by `<symbol>`
        target_or_query: String,

        /// Optional `<symbol>` when the first positional argument is a bundle/repo path
        query: Option<String>,

        /// Explicit bundle or root directory to search
        #[arg(short, long)]
        bundle: Option<PathBuf>,

        /// Maximum reverse-BFS hop depth
        #[arg(short = 'd', long, visible_alias = "depth", default_value_t = 5)]
        max_depth: usize,

        /// Maximum impacted callers to display
        #[arg(short, short_alias = 'n', long, default_value_t = 40)]
        limit: usize,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit impact analysis as pretty-printed JSON
        #[arg(long)]
        json: bool,
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

        /// Filter search target (`all`, `source`, `symbols`, `types`, `calls`, `macros`, `xref`, `sections`)
        #[arg(short, long, default_value = "all")]
        kind: String,

        /// Search raw source files directly (`--kind source`)
        #[arg(short = 'S', long = "source")]
        source: bool,

        /// Case-insensitive matching
        #[arg(short, long)]
        ignore_case: bool,

        /// Maximum matches to return
        #[arg(short, short_alias = 'n', long, default_value_t = 50)]
        limit: usize,

        /// Truncate long snippets for minimal token usage
        #[arg(long)]
        compact: bool,

        /// Skip automatic incremental bundle refresh before querying
        #[arg(long)]
        no_sync: bool,

        /// Emit search hits as pretty-printed JSON
        #[arg(long)]
        json: bool,
    },

    /// Native Claude Code plugin hooks (`session-start`, `post-edit`)
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(Debug, Subcommand)]
enum HookAction {
    /// Run the SessionStart bundle discovery and refresh hook natively in Rust
    SessionStart,
    /// Run the PostToolUse (Edit|Write|MultiEdit) incremental auto-sync hook natively in Rust
    PostEdit,
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
            timings,
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

            let had_existing_bundle = !cfg.force
                && chipsrc_core::scanner::has_bundle_cache(&cfg.output_dir)
                && chipsrc_core::scanner::load_meta_file(&cfg.output_dir).is_some_and(|m| {
                    m.metadata.vendor_mode == cfg.vendor_mode && !m.metadata.file_stamps.is_empty()
                });

            let bundle = convert_repo(&cfg)
                .with_context(|| format!("Failed to index repository '{}'", repo.display()))?;
            print_conversion_summary(&bundle, timings, had_existing_bundle);
        }

        Commands::Ensure {
            repos,
            output_root,
            force,
            vendor_mode,
            timings,
        } => {
            let vmode = parse_vendor_mode(&vendor_mode)?;
            let targets = if repos.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                repos
            };

            for repo in targets {
                let out_dir = output_root.join(derive_repo_stem(&repo));
                let had_existing_bundle = !force
                    && chipsrc_core::scanner::has_bundle_cache(&out_dir)
                    && chipsrc_core::scanner::load_meta_file(&out_dir).is_some_and(|m| {
                        m.metadata.vendor_mode == vmode && !m.metadata.file_stamps.is_empty()
                    });
                let bundle = ensure_repo(&repo, &output_root, force, vmode)
                    .with_context(|| format!("Failed to ensure repository '{}'", repo.display()))?;
                let tag = if bundle.cache_hit {
                    "CACHE HIT"
                } else if bundle.metadata.incremental_reused_files > 0 || had_existing_bundle {
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
                if timings {
                    let m = &bundle.metadata;
                    println!(
                        "    [ok] Timings     : scan={}ms parse={}ms link={}ms graph={}ms shard={}ms emit={}ms (total={}ms)",
                        m.scan_ms, m.parse_ms, m.link_ms, m.graph_ms, m.shard_ms, m.emit_ms, m.elapsed_ms
                    );
                }
            }
        }

        Commands::Status {
            workspace,
            sync,
            check,
            json,
        } => {
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
                    if !json {
                        println!("Synchronized {refreshed} stale bundle(s).");
                    }
                    entries = workspace_status(&workspace)?;
                }
            }

            let any_stale = entries.iter().any(|e| !e.is_fresh);

            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                if check && any_stale {
                    std::process::exit(2);
                }
                return Ok(());
            }

            println!("=== chipsrc Workspace Status ({}) ===", workspace.display());
            if entries.is_empty() {
                println!("Indexed Bundles : (none)");
            } else {
                println!("Indexed Bundles ({}):", entries.len());
                for entry in &entries {
                    let freshness = if entry.is_fresh {
                        "FRESH".to_string()
                    } else if let Some(ref reason) = entry.reason {
                        format!("STALE ({reason})")
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

            if check && any_stale {
                std::process::exit(2);
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
                "Blueprint      : {}",
                if let Some(ref err) = report.blueprint_error {
                    format!("INVALID (.chipsrc.json: {err})")
                } else if report.has_blueprint {
                    "present (.chipsrc.json)".to_string()
                } else {
                    "none".to_string()
                }
            );
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

            if !report.has_blueprint
                && (!report.unclassified_dirs.is_empty()
                    || !report.detected_workspaces.is_empty()
                    || !report.candidate_c_macros.is_empty())
            {
                println!("\n=== Onboarding Digest (.chipsrc.json missing) ===");
                if !report.unclassified_dirs.is_empty() {
                    println!(
                        "  Unclassified Dirs  : {}",
                        report.unclassified_dirs.join(", ")
                    );
                }
                if !report.detected_workspaces.is_empty() {
                    println!(
                        "  Workspace Roots    : {}",
                        report.detected_workspaces.join(", ")
                    );
                }
                if !report.candidate_c_macros.is_empty() {
                    println!(
                        "  Candidate C Macros : {}",
                        report.candidate_c_macros.join(", ")
                    );
                }
                println!(
                    "  Tip                : Write a root `.chipsrc.json` (`scopes`, `layers`, `shards`, `c_qualifiers`, `mmio_ranges`) to lock in repo architecture before running `chipsrc ensure`."
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
            json,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("sym", &bundles, &q, None, kind.as_deref(), 0, limit)?
                );
            } else {
                let out = query_symbols(&bundles, &q, kind.as_deref(), show, limit)?;
                print!("{out}");
            }
        }

        Commands::Callers {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, sym) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("callers", &bundles, &sym, None, None, 0, limit)?
                );
            } else {
                let out = query_callers(&bundles, &sym, show, limit)?;
                print!("{out}");
            }
        }

        Commands::Callees {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, sym) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("callees", &bundles, &sym, None, None, 0, limit)?
                );
            } else {
                let out = query_callees(&bundles, &sym, show, limit)?;
                print!("{out}");
            }
        }

        Commands::Type {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("type", &bundles, &q, None, None, 0, limit)?
                );
            } else {
                let out = query_types(&bundles, &q, show, limit)?;
                print!("{out}");
            }
        }

        Commands::Macro {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("macro", &bundles, &q, None, None, 0, limit)?
                );
            } else {
                let out = query_macros(&bundles, &q, show, limit)?;
                print!("{out}");
            }
        }

        Commands::Section {
            target_or_query,
            query,
            bundle,
            show,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("section", &bundles, &q, None, None, 0, limit)?
                );
            } else {
                let out = query_sections(&bundles, &q, show, limit)?;
                print!("{out}");
            }
        }

        Commands::Xref {
            target_or_query,
            query,
            bundle,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, q) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("xref", &bundles, &q, None, None, 0, limit)?
                );
            } else {
                let out = query_xref(&bundles, &q, limit)?;
                print!("{out}");
            }
        }

        Commands::Path {
            from_or_target,
            to_or_from,
            to,
            bundle,
            max_depth,
            no_sync,
            json,
        } => {
            let (bundles, from_sym, to_sym) = if let Some(explicit_to) = to {
                let (bundles, from_sym) = resolve_cli_target_and_query(
                    &from_or_target,
                    Some(&to_or_from),
                    bundle.as_deref(),
                    no_sync,
                )?;
                (bundles, from_sym, explicit_to)
            } else {
                let (bundles, from_sym) = resolve_cli_target_and_query(
                    &from_or_target,
                    None,
                    bundle.as_deref(),
                    no_sync,
                )?;
                (bundles, from_sym, to_or_from)
            };
            if json {
                println!(
                    "{}",
                    query_subcommand_json(
                        "path",
                        &bundles,
                        &from_sym,
                        Some(&to_sym),
                        None,
                        max_depth,
                        0
                    )?
                );
            } else {
                let out = query_call_path(&bundles, &from_sym, &to_sym, max_depth)?;
                print!("{out}");
            }
        }

        Commands::Impact {
            target_or_query,
            query,
            bundle,
            max_depth,
            limit,
            no_sync,
            json,
        } => {
            let (bundles, sym) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            if json {
                println!(
                    "{}",
                    query_subcommand_json("impact", &bundles, &sym, None, None, max_depth, limit)?
                );
            } else {
                let out = query_impact(&bundles, &sym, max_depth, limit)?;
                print!("{out}");
            }
        }

        Commands::Search {
            target_or_query,
            query,
            bundle,
            kind,
            source,
            ignore_case,
            limit,
            compact,
            no_sync,
            json,
        } => {
            let effective_kind = if source { "source" } else { kind.as_str() };
            let (bundles, pattern) = resolve_cli_target_and_query(
                &target_or_query,
                query.as_deref(),
                bundle.as_deref(),
                no_sync,
            )?;
            let hits =
                parallel_bundle_search(&bundles, &pattern, effective_kind, ignore_case, limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&hits)?);
                return Ok(());
            }
            if hits.is_empty() {
                println!("No search hits for pattern '{pattern}' (kind={effective_kind}).");
            } else {
                println!(
                    "=== Search Hits for '{}' (kind={}, {} matches) ===",
                    pattern,
                    effective_kind,
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

        Commands::Hook { action } => match action {
            HookAction::SessionStart => run_session_start_hook()?,
            HookAction::PostEdit => run_post_edit_hook()?,
        },
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
    chipsrc_core::scanner::canonical_repo_root_and_name(repo).1
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

fn print_conversion_summary(bundle: &ConversionBundle, timings: bool, incremental_sync: bool) {
    let m = &bundle.metadata;
    let s = &bundle.sanity;
    let mode_tag = if bundle.cache_hit {
        "CACHE HIT".to_string()
    } else if m.incremental_reused_files > 0 || incremental_sync {
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
    if timings {
        println!(
            "    [ok] Timings     : scan={}ms parse={}ms link={}ms graph={}ms shard={}ms emit={}ms (total={}ms)",
            m.scan_ms, m.parse_ms, m.link_ms, m.graph_ms, m.shard_ms, m.emit_ms, m.elapsed_ms
        );
    }
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

fn run_session_start_hook() -> Result<()> {
    let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let project_dir = std::fs::canonicalize(&project_dir).unwrap_or(project_dir);

    let bundles = chipsrc_core::query::discover_workspace_bundles(&project_dir).unwrap_or_default();
    if !bundles.is_empty() {
        let _ = auto_refresh_bundles(&bundles);
    }

    let mut bundle_summaries = Vec::new();
    for bdir in &bundles {
        if let Some(meta_file) = chipsrc_core::scanner::load_meta_file(bdir) {
            let m = &meta_file.metadata;
            let rel = bdir
                .strip_prefix(&project_dir)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| bdir.to_string_lossy().replace('\\', "/"));
            let rel_str = if rel.is_empty() { ".".to_string() } else { rel };
            bundle_summaries.push(format!(
                "`{rel_str}` ({} files, {} syms, {} types, {} calls, {} macros/MMIO, sanity {}/100)",
                m.total_files,
                m.symbol_count,
                m.type_count,
                m.call_edge_count,
                m.macro_count,
                meta_file.sanity.score
            ));
        }
    }

    if bundle_summaries.is_empty() && !dir_has_source_files(&project_dir, 0, 3) {
        return Ok(());
    }

    let mut lines =
        vec!["[chipsrc] Source Code & Hardware Cross-Reference Intelligence active:".to_string()];
    let has_blueprint = project_dir.join(".chipsrc.json").is_file();
    if !bundle_summaries.is_empty() {
        lines.push(format!(
            "- Indexed codebase bundles ready (auto-synced via `cache/`): {}",
            bundle_summaries.join(", ")
        ));
    } else if has_blueprint {
        lines.push(
            "- Unindexed source repository with `.chipsrc.json` blueprint detected (run `chipsrc ensure . -o output` to build the Agent Codebase Bundle)."
                .to_string(),
        );
    } else {
        lines.push(
            "- Unindexed source repository detected: run `chipsrc inspect .` first; if an Onboarding Digest appears, write a root `.chipsrc.json` blueprint once, then run `chipsrc ensure . -o output`."
                .to_string(),
        );
    }
    lines.push(
        "- Prefer 1-turn CLI queries over blind Grep/Read loops (all queries auto-refresh changed files): `chipsrc sym <name> [-s]`, `chipsrc callers <fn>`, `chipsrc callees <fn>`, `chipsrc path <from> <to>`, `chipsrc impact <fn>`, `chipsrc type <name> [-s]`, `chipsrc macro|reg|mmio <name|0xHEX>`, `chipsrc xref <symbol>`, `chipsrc section [query] [-s]`, `chipsrc search <pattern>`."
            .to_string(),
    );

    let payload = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": lines.join("\n"),
        }
    });
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

fn dir_has_source_files(dir: &Path, depth: usize, max_depth: usize) -> bool {
    if depth > max_depth {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if path.is_dir() {
            if name_str.starts_with('.')
                || matches!(
                    name_str.to_ascii_lowercase().as_str(),
                    "target" | "node_modules" | "bin" | "output" | "dist" | "build" | "venv"
                )
            {
                continue;
            }
            if dir_has_source_files(&path, depth + 1, max_depth) {
                return true;
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if LanguageKind::from_extension(ext).is_some() {
                return true;
            }
        }
    }
    false
}

fn run_post_edit_hook() -> Result<()> {
    if std::env::var("CHIPSRC_DISABLE_AUTO_SYNC").as_deref() == Ok("1") {
        return Ok(());
    }
    let mut raw_stdin = String::new();
    if std::io::stdin().read_to_string(&mut raw_stdin).is_err() || raw_stdin.trim().is_empty() {
        return Ok(());
    }
    let Ok(event) = serde_json::from_str::<serde_json::Value>(&raw_stdin) else {
        return Ok(());
    };
    let tool_name = event
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !matches!(tool_name, "Edit" | "Write" | "MultiEdit") {
        return Ok(());
    }
    let file_path_str = event
        .get("tool_input")
        .and_then(|ti| ti.get("file_path").or_else(|| ti.get("path")))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if file_path_str.is_empty() {
        return Ok(());
    }

    let edited_path = PathBuf::from(file_path_str);
    let Some(ext) = edited_path.extension().and_then(|e| e.to_str()) else {
        return Ok(());
    };
    if LanguageKind::from_extension(ext).is_none() {
        return Ok(());
    }
    if edited_path.components().any(|c| {
        c.as_os_str().to_str().is_some_and(|s| {
            matches!(
                s.to_ascii_lowercase().as_str(),
                ".git"
                    | "target"
                    | "node_modules"
                    | "bin"
                    | "output"
                    | "dist"
                    | "build"
                    | ".claude"
                    | ".factory"
                    | ".venv"
                    | "venv"
            )
        })
    }) {
        return Ok(());
    }

    let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let project_dir = std::fs::canonicalize(&project_dir).unwrap_or(project_dir);
    let abs_edited = if edited_path.is_absolute() {
        edited_path
    } else {
        project_dir.join(edited_path)
    };
    let (edited_canon, _) = chipsrc_core::scanner::canonical_repo_root_and_name(&abs_edited);

    let output_root = project_dir.join("output");
    let Ok(entries) = std::fs::read_dir(&output_root) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if !child.is_dir() {
            continue;
        }
        let (source_root, vendor_mode, repo_name) =
            if let Some(meta_file) = chipsrc_core::scanner::load_meta_file(&child) {
                (
                    meta_file.metadata.source_root,
                    meta_file.metadata.vendor_mode,
                    meta_file.metadata.repo_name,
                )
            } else if let Some(manifest) =
                chipsrc_core::scanner::load_cache_manifest_any_version(&child)
            {
                let name = child
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("repo")
                    .to_string();
                (manifest.repo_root, manifest.vendor_mode, name)
            } else {
                continue;
            };
        let src_path = Path::new(&source_root);
        let (src_canon, _) = chipsrc_core::scanner::canonical_repo_root_and_name(src_path);
        let prefix = format!("{}/", src_canon.trim_end_matches('/'));
        if edited_canon.eq_ignore_ascii_case(&src_canon)
            || edited_canon
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
        {
            let mut cfg = ConvertConfig::new(src_path.to_path_buf(), child.clone());
            cfg.vendor_mode = vendor_mode;
            cfg.force = false;
            cfg.single_file = child.join(format!("{repo_name}.md")).is_file();
            let _ = convert_repo(&cfg);
        }
    }
    Ok(())
}
