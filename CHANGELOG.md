# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/), and the version lives in
`.claude-plugin/plugin.json` and `Cargo.toml`.

## [Unreleased]

### Added

- **Parameterized In-Repo Black-Box QA Harness (`qa/qa_blackbox.py`, `qa/lib/`, `qa/suites/`, `qa/oracles/`, `qa/README.md`)**:
  - Ported the 123-assertion black-box regression suites (`real`, `sync`, `boundary`, `focused`, `hooks`) into the repository as a Python 3.13 standard-library-only harness (`python -I` compatible) with `--bin`, `--repos-root`, `--corpus-root`, `--out`, repeatable `--suite` (`core` alias), `--only`, `--skip`, `--timeout`, and `--fixtures-mode build|require`.
  - Externalized repository-specific golden values to `qa/oracles/{chipsrc,smart_locker,volt_website,beautiful-embedded-c}.json`, added skip-if-missing preflight checks, fixed same-second sub-second `st_mtime_ns` carry rollover in `qa/lib/mutate.py`, surfaced negative `expected=None` CLI probes in `<suite>-results.json` and `summary.json`, and isolated all mutations into `<out>/sandboxes/<suite>-<timestamp>/`.
- **Per-File Content-Addressed AST Cache Shards (`2.0.0`), Stat-Only `stamp_check`, Structural Digest Short-Circuit & Stage Timings (`model.rs`, `scanner.rs`, `emitter.rs`, `lib.rs`, `main.rs`)**:
  - Replaced the monolithic `cache.json` with `cache/manifest.json` (`CACHE_SCHEMA_VERSION = "2.0.0"`) and per-file `cache/<blake3>.json` shards (with automatic migration and cleanup of legacy `cache.json`).
  - Added `scanner::stamp_check` to verify `(size_bytes, mtime_secs)` against `meta.file_stamps` without reading unchanged files from disk (`<2ms` warm cache hits) and refresh `mtime_secs` on touch-only edits.
  - Added `ParsedFileUnit::structural_digest()` (16-char BLAKE3 over symbols, types, macros, imports, raw_calls, and raw_xrefs, excluding line numbers and docstrings) to short-circuit comment-only edits in `<25ms` without re-running global link, graph, sharding, or sanity passes.
  - Added `scan_ms`, `parse_ms`, `link_ms`, `graph_ms`, `shard_ms`, and `emit_ms` to `RepoMetadata` and `--timings` to `chipsrc convert` and `chipsrc ensure`.
- **Deterministic 25-Iteration HITS Hub/Authority Ranking (`model.rs`, `graph.rs`, `emitter.rs`)**:
  - Added `compute_hits` alongside PageRank over the high-confidence call graph (`FileScope::Test` callers weighted `0`), emitting `hub_score` and `authority_score` to `RankedSymbol` and `index/symbols.tsv` (columns 16–17) and ranking God Nodes by `sqrt(hub * auth)` bridging centrality with per-file diversity.
- **Native Rust Claude Code Hooks, Universal `--json` Output & CI `status --check` (`main.rs`, `query.rs`, `hooks/hooks.json`)**:
  - Added `chipsrc hook session-start` and `chipsrc hook post-edit` subcommands for `<25ms` zero-Python hook execution (with Python fallback in `hooks/hooks.json`).
  - Added `--json` output across all query subcommands (`status`, `inspect`, `sym`, `callers`, `callees`, `type`, `macro`, `section`, `xref`, `path`, `impact`, `search`) and `chipsrc status --check` (exits with status code `2` when any bundle is `STALE`).
  - Added `crates/chipsrc-core/tests/invariants.rs` (`INV-1`..`INV-7` and Bugs #1–#20 regression harness) and `scripts/bench.ps1`.
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

- **Duplicate-Content Per-File Cache Shard Disambiguation (`model.rs`, `scanner.rs`, `emitter.rs`, `lib.rs`)**:
  - Added `CacheShardEntry::shard_key(rel_path, blake3_hash)` and `CacheShardEntry::shard_rel_path(rel_path, blake3_hash)` keying per-file AST cache shards by `blake3(rel_path + "\0" + blake3_hash)` (`cache/<shard_key>.json`) and verifying `scanned.rel_path` on load so byte-identical files at different paths never alias or drop sibling sections/symbols across incremental refreshes.
- **Unified Source Line Counting Across Full Scan & Incremental Sync (`scanner.rs`)**:
  - Added `scanner::count_source_lines(bytes)` (`\n` count plus `1` when non-empty and not ending with `\n`; `0` for empty buffers) and wired it into both `scan_repository` and `stamp_check` so incremental syncs, `--force` rebuilds, and `chipsrc inspect` report identical per-file `line_count` and `total_lines` values and emit byte-identical `index/*` and `sections/*` artifacts.
- **Bundle Artifact Integrity Gate, Missing-Table Self-Heal & Explicit `--no-sync` Errors (`error.rs`, `model.rs`, `scanner.rs`, `query.rs`, `lib.rs`, `main.rs`)**:
  - Added `scanner::bundle_artifacts_complete` and `scanner::first_missing_bundle_artifact` verifying `meta.json`, `INDEX.md`, all six `index/*.tsv` tables, every `sections/*.md` referenced in column 11 of `index/sections.tsv`, `cache/manifest.json`, and every listed per-file cache shard.
  - Wired artifact completeness into `convert_repo`, `auto_refresh_bundles`, `workspace_status` (`is_fresh = false` with a `reason` naming the missing artifact in both JSON and human output), and both hooks so incomplete bundles self-heal automatically.
  - Replaced silent TSV reads in `query.rs` with `load_index_table` returning `ChipsrcError::IncompleteBundle { bundle, missing }` so `--no-sync` queries on incomplete bundles exit non-zero naming the missing table on stderr instead of returning `[]`.
- **Sub-Second `mtime_nanos` Freshness Stamps & Cache Schema `2.1.0` (`model.rs`, `scanner.rs`, `emitter.rs`, `query.rs`, `lib.rs`, `main.rs`)**:
  - Added `#[serde(default)] mtime_nanos: u32` (`d.subsec_nanos()`) to `ScannedFile` and `FileStamp` and updated `scanner::stamp_check` to require `(size_bytes, mtime_secs, mtime_nanos)` equality so same-size edits within the same second are detected by `status --check`, `convert`, `ensure`, `hook post-edit`, and query auto-refresh.
  - Bumped `CACHE_SCHEMA_VERSION` from `"2.0.0"` to `"2.1.0"` and invalidated legacy `2.0.0` manifests and `meta.json` stamps lacking `mtime_nanos` so existing bundles rebuild once and hit cache on subsequent runs.
- **Round 2 Sharder, C/CMSIS Qualifier, Query Identity, Vendor Surface & Receiver Binding Fixes (`scanner.rs`, `parser.rs`, `mmio.rs`, `resolver.rs`, `graph.rs`, `sharder.rs`, `sanity.rs`, `emitter.rs`, `query.rs`)**:
  - Fixed `resolve_numbered` in `sharder.rs` to resolve by file path (`file_to_numbered`) before raw slug so split sub-shards never lose symbols or inherit wrong scopes, keyed `group_map` by `(scope, slug)`, disambiguated generic file stems (`main`, `mod`, `index`, `lib`), preserved canonical `module_path` on multi-file split chunks, and enforced global shard/TSV invariants in `sanity.rs`.
  - Replaced `brace_depth` with a `Vec<BraceFrame>` stack (`Transparent` for `extern "C" { ... }`, `Aggregate` for `struct`/`union`/`class` bodies) in `normalize_c_qualifier_macros` and added `__I`, `__O`, `__IO`, `__IM`, `__OM`, `__IOM`, `__IAR_FT`, `__ALIGNED` so CMSIS register structs (`GPIO_TypeDef`) extract clean field types.
  - Added `SymbolIdView` (`parse_symbol_id`) and `query_targets_file` in `query.rs` so symbol, caller, callee, type, and impact queries never match file-path prefixes (`smart_locker/`, `parser.rs`) unless the query targets a file path, restricted `search` to semantic TSV columns with `(bundle, file, line)` deduplication, and optimized `xref` with zero-allocation `QueryHw` stack canonicalization.
  - Fixed `CallerSite` in `resolver.rs` to use the caller symbol's scope (`symbols[i].scope`) so inline `#[cfg(test)]` helpers resolve as `SameFile`, expanded Rust/Python/JS/Tree-sitter builtin allowlists (`<15%` `external_or_macro` ratio), and excluded `external::*` pseudo-nodes from `path` and `impact` BFS graphs.
  - Hardened `compute_vendor_surface` with path-boundary header matching (`GENERIC_HEADER_STEMS`), excluded `LinkerSection` and generic bit utility macros (`SET_BIT`, `CLEAR_BIT`, `READ_BIT`) from active MMIO surfaces, synchronized post-compaction `god_nodes`/`entrypoints`/`vendor_surface`, and reserved up to 8 entrypoint slots + 17 ISR slots in `INDEX.md`.
  - Extended local receiver type inference to `for` loops, `if let` / `while let` (`let_condition`), tuple bindings, and closure parameters via `elem_type_of`, accepted 2..=8 hex-digit `<HEX>h` literals (`deadbeefh` -> `0xDEADBEEF`) with English stoplist filtering, reported invalid `.chipsrc.json` files via `InspectReport.blueprint_error`, stripped glob suffixes (`/**`, `/*`) in `match_longest_prefix`, and mapped web/SFC directories (`web`, `frontend`, `client`, `ui`, `components`, `views`, `pages`, `screens`, `widgets`, `layouts`) to `ArchLayer::App`.
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
