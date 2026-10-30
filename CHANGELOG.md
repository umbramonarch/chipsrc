# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/), and the version lives in
`.claude-plugin/plugin.json` and `Cargo.toml`.

## [Unreleased]

### Added

- **Agent-Once Onboarding Blueprint (`.chipsrc.json`) & Turn-1 Discovery (`model.rs`, `scanner.rs`, `mmio.rs`, `parser.rs`, `lib.rs`, `main.rs`)**:
  - Added root `.chipsrc.json` `RepoBlueprint` support (`scopes`, `layers`, `shards`, `ignore_dirs`, `c_qualifiers`, `entrypoints`, `isr_patterns`, `mmio_ranges`) with BLAKE3 hash folding into the repository Merkle `fingerprint` and `cache.json` (`blueprint_hash`) for automatic cache invalidation.
  - Extended `chipsrc inspect` (`InspectReport`) with an **Onboarding Digest** (`has_blueprint`, `unclassified_dirs`, `detected_workspaces`, `candidate_c_macros`) and multi-package workspace sharding (`crates/`, `packages/`, `apps/`, `services/`, `modules/`, `components/`).
- **Local Variable & Parameter Type Binding for Receiver Resolution (`parser.rs`, `resolver.rs`)**:
  - Added function-scoped local variable and parameter type binding across C/C++, Rust, Python, and TypeScript/JavaScript so `var.method()` and `ptr->method()` calls resolve accurately to their static enclosing type.
- **Function-Pointer Dispatch Tables, ISR Vectors & Callback Tracking (`parser.rs`, `resolver.rs`)**:
  - Extracted function-pointer references from struct/array/object initializers and callback arguments (`fn_ptr_candidate`), precision-filtered against known repository symbols in compatible language families (`fn_ptr_ref` / `dispatches_fn`), and synthesized static call-graph edges.
- **MMIO Register & Struct/Class Field Mutability Dataflow (`mmio.rs`, `parser.rs`, `resolver.rs`)**:
  - Classified MMIO peripheral accesses and struct/class member accesses into write vs read dataflow relations (`writes_reg`, `reads_reg`, `writes_field`, `reads_field`) in `index/xref.tsv`.
- **Multi-Hop Shortest Call-Path (`chipsrc path`) & Blast-Radius (`chipsrc impact`) Queries (`query.rs`, `main.rs`)**:
  - Added `chipsrc path <from> <to> [--max-depth N]` (BFS shortest static call chain) and `chipsrc impact <symbol> [--max-depth N]` (reverse-BFS blast radius highlighting affected shards, entrypoints, ISR handlers, and test roots).
- **Thread-Local Parser Pool, Zero-Clone Incremental Cache & Single-Pass Auto-Refresh (`parser.rs`, `emitter.rs`, `lib.rs`, `post_edit_hook.py`)**:
  - Added thread-local Tree-sitter `Parser` pooling (`THREAD_PARSERS`), in-place `IncrementalAstCache` entry removal (`existing_cache.files.remove`), compact single-line `cache.json` serialization, single-pass `auto_refresh_bundles` fingerprint checking, and silent `post_edit_hook.py` execution on clean incremental syncs.
- **Single-File Component (`.astro`, `.vue`, `.svelte`) & JSX/TSX Extraction (`model.rs`, `parser.rs`)**:
  - Added byte-aligned SFC preprocessing (`preprocess_sfc_to_tsx`) that preserves exact 1:1 byte and line coordinates across frontmatter (`---`), `<script>` blocks, and component templates.
  - Added component symbol synthesis, JSX/template PascalCase component usage call/xref edges (`<Component />`), nested helper arrow-function extraction, HTTP route handler entrypoint classification (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `ALL`), and exported constant indexing.
- **Core Domain Types Table, Oversized Module Sub-Sharding & Fast `meta.json` Freshness Stamps (`model.rs`, `scanner.rs`, `sharder.rs`, `emitter.rs`, `query.rs`, `lib.rs`)**:
  - Added a **Core Domain Types & Data Structures** table in `INDEX.md` ranking top first-party types by cross-codebase reference count.
  - Added automatic sub-sharding in `sharder.rs` for oversized first-party modules (`> 8` files or `> 3,000` lines), partitioning by architectural layer (`domain` vs `core`) and dedicated large-file / balanced chunks.
  - Added per-file `file_stamps` in `meta.json` (`RepoMetadata`) so `auto_refresh_bundles` and `workspace_status` verify bundle freshness in `<2ms` without deserializing multi-megabyte `cache.json` files.
  - Added `-n` short alias for `--limit` across all query subcommands and `-S` / `--source` full-text source search in `chipsrc search`.

### Fixed

- **AST & MMIO Extraction Precision (`mmio.rs`, `scanner.rs`, `parser.rs`, `emitter.rs`)**:
  - Restricted C-style `PERIPH->REG` and `*(volatile ...)` extraction to C/C++, masked standard and multi-line Rust raw string literals (`r#"..."#`), and stopped MMIO regex scanning at `#[cfg(test)]`.
  - Extended `PERIPH_REG_RE` and `is_register_write_in_line` to capture chained nested struct members and array subscripts (`IOMUX->SECCFG.PINCM[idx] |= ...`, `TIMG2->CPU_INT.ICLR = ...`).
  - Excluded 32-bit ASCII FourCC magic constants (`0x50574D00UL` / `"PWM\0"`) and `*MAGIC*`/`*VERSION*` identifiers from `MmioAddress` classification, stripped trailing comments from `#define` values, and supported datasheet hex queries starting with `A..F` (`FFh` -> `0xFF`).
  - Tagged Rust `#[cfg(test)] mod` items and `#[test]` functions as `FileScope::Test` (`ArchLayer::Tests`), skipped test-local constants and multi-line raw string literals (`<multiline string>`) in `macros.tsv`, and hardened `sanitize_tsv` against control characters.
  - Passed only function declaration headers (before `{`) to `classify_symbol_kind` and ignored comment lines in `has_preceding_interrupt_attr` so string literals/comments never trigger false `SymbolKind::Isr` tags.
  - Excluded C++ member function prototypes from `fields_summary`, raised `MAX_TYPE_SUMMARY_ITEMS` from 6 to 16 (`... (+N more)`), handled outer `#[...]` attributes on Rust `pub` items, matched Python `async def`, defaulted TS/JS class methods to `pub`, and extracted calls nested inside Rust macros (`format!`).
  - Scoped `.claudeignore` updates strictly to when `output_dir` resides inside `repo_path`.
- **Vendor-Neutral SDK & Asset Classification (`scanner.rs`, `sharder.rs`)**:
  - Replaced hardcoded chip/vendor tokens with structural composite directory sub-token classification (`driverlib`, `cmsis`, `thirdparty`, `3rdparty`, `vendor`, `svd`, `sdk`, `bundled`, `submodules`, `middlewares`) and root-scoped reference directories (`references/`, `reference/`), and skipped vendor `examples/`/`samples/`/`demos/`/`templates/` subdirectories.
  - Removed overly broad directory exclusions (`html`, `site`) and refined bundled JavaScript asset detection (`*.min.js`, `*.bundle.js`, versioned doc-generator scripts) so first-party modules (`bootstrap.js`, `site/`, `html/`) are never dropped.
  - Changed shard group scope resolution to dominant/majority ownership, synchronized fallback `ArchLayer::Other` symbol/type/macro layers with their module shard, and pruned unreferenced vendor entries from both `sections/*.md` and `index/*.tsv` under `VendorMode::Active`.
- **Context-Aware C/C++ Qualifier Normalization & Signature Extraction (`parser.rs`, `sanity.rs`)**:
  - Replaced hardcoded vendor macro tables with structural top-level (`brace_depth == 0 && paren_depth == 0`) declaration-context normalization for `STATIC`, `CONST`, `INLINE`, `*_STATIC_INLINE`, `*_FORCEINLINE`, `*_WEAK`, `*_IRQ`, `*_INTERRUPT`, `*_RAMFUNC`, and `*_PACKED`, preserving `enum { STATIC = 0, CONST = 1 };` and exact byte lengths.
  - Fixed `extract_clean_signature` to use AST block body boundaries and parenthesis-aware brace splitting so destructured parameters (`({ request }) =>`) and object literals are never truncated.
  - Filtered C control-flow keywords from misparsed conditional blocks, skipped decorative ASCII divider banners (`---- label ----`, `====`) when extracting doc summaries, and listed offending file paths in `sanity.rs` parse-error warnings.
- **Call-Graph Resolution, Iterative Tarjan SCC & Query Precision (`resolver.rs`, `graph.rs`, `query.rs`)**:
  - Prevented explicit type-qualified calls (`String::new()`, `Vec::new()`, `Parser::new()`) and ubiquitous stdlib methods (`.as_str()`, `.clone()`, `.unwrap()`) from binding to unrelated project methods (`ConvertConfig::new`, `ArchLayer::as_str`), isolated `FirstParty` vs `Test` and `VendorSdk` scopes across all resolution tiers, and filtered noisy Rust stdlib `ExternalOrMacro` calls.
  - Restricted PageRank, `in_degree`/`out_degree`, Tarjan SCC cycle detection, and `sanity.rs` `call_resolution_ratio` to high-confidence resolution tiers (`SameFile`, `ImportResolved`, `UniqueGlobal`), converted `compute_tarjan_sccs` to an iterative algorithm, and prioritized bidirectional transit hubs in `god_nodes`.
  - Improved `resolve_bundles` to scope default `.` queries to the current workspace's `source_root` when multiple bundles exist in `output/`, return `BundleNotFound` on invalid multi-segment paths, require exact hex equality on hex queries (`0xFF` / `FFh`), fall back to literal regex escaping on unclosed metacharacters in `search`, and cache source files in `SourceSnippetCache`.

## [1.0.0] - 2026-10-27

### Added

- **Core Source-to-Agent Extraction Engine (`crates/chipsrc-core`)**:
  - Parallel `.gitignore`-aware repository scanner (`scanner.rs`) with BLAKE3 file and tree fingerprinting (`meta.json`) for sub-2ms incremental cache hits.
  - Multi-language Tree-sitter AST parser (`parser.rs`) supporting C, C++, Rust, Python, TypeScript, and JavaScript without LLM calls or build-system compilation.
  - Structural extraction modules (`symbols.rs`, `types.rs`, `calls.rs`, `macros.rs`) for function/method signatures, struct/enum/trait/type definitions with byte/field layout, static caller->callee edges, `#define` / `const` constants, and peripheral MMIO register / ISR vector usage.
  - Unified Code + Hardware Cross-Reference Graph (`xref.rs`) linking functions, types, macros, call edges, and hardware registers/peripherals across the codebase (`index/xref.tsv`).
  - Hierarchical Agent Codebase Bundle emitter (`sharding.rs`, `emitter.rs`, `sanity.rs`) producing `INDEX.md`, module-sharded `sections/*.md` signature skeletons, flat `index/*.tsv` tables, `meta.json`, and `.claudeignore` prompt-cache protection.
- **1-Turn Agent Code Intelligence CLI (`crates/chipsrc-cli` & `query.rs`)**:
  - `chipsrc status [--compact]`: Scans the workspace for ready bundles and unindexed source trees.
  - `chipsrc ensure <repo_dir...> [-o output/]`: Indexes source repositories with `<2ms` BLAKE3 incremental cache hits.
  - `chipsrc sym <query> [--compact]`: 1-turn function/method signature, docstring, location, and call-summary lookup.
  - `chipsrc type <query> [--compact]`: 1-turn struct/enum/union/trait/class definition and field layout lookup.
  - `chipsrc callers <symbol>` and `chipsrc callees <symbol>`: Static call-graph traversal (direct and multi-hop).
  - `chipsrc macro <query>`: `#define` / `const` / register address constant lookup with C/vendor hex normalization (`0x400` <-> `400h`).
  - `chipsrc xref <symbol>`: Unified Code + Hardware Cross-Reference Graph traversal across symbols, types, macros, and hardware peripherals.
  - `chipsrc section [bundle] [query]` and `chipsrc body <file:line|symbol>`: Module skeleton slice and exact on-demand function body extraction from source.
  - `chipsrc search <pattern> [--compact]`: Parallel SIMD (`memchr`) + Regex search across all bundles in `./output`.
  - `chipsrc index` and `chipsrc inspect`.
- **Hybrid Claude Code Plugin (`.claude-plugin/`, `skills/chipsrc/`)**:
  - `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` manifests.
  - `/chipsrc` skill (`skills/chipsrc/SKILL.md`) teaching 1-turn CLI codebase retrieval workflows alongside `chipdoc`.

[Unreleased]: https://github.com/umbramonarch/chipsrc/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/umbramonarch/chipsrc/releases/tag/v1.0.0
