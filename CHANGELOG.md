# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/), and the version lives in
`.claude-plugin/plugin.json` and `Cargo.toml`.

## [Unreleased]

### Performance

- **Coordinate-Shift Incremental Tier (Tier 3) & Persisted Linked-Graph State (`model.rs`, `lib.rs`, `emitter.rs`, `resolver.rs`, `sharder.rs`)**:
  - Added `cache/graph_state.json` (schema `2.1.0`, written atomically next to `cache/manifest.json` and excluded from shard pruning) storing the linked-graph results that cannot be re-derived from the AST: per-symbol PageRank/HITS/degree/SCC annotations plus god nodes, entrypoints, layer edges, cycles, and the active vendor surface. It is refreshed on every full conversion and on every Tier 3 sync, so it always describes the on-disk bundle.
  - `convert_repo` now detects coordinate-only dirty batches (every dirty file keeps its `structural_digest`, scope, and architecture layer while line coordinates or docstrings moved, no files added/deleted, no file reaches the `1,400`-line single-file threshold, and no module group exceeds `3,000` lines / `8` files). For those it rebuilds the symbol/type/macro tables with the shared `resolver::collect_symbol_tables`, re-attaches the persisted graph metrics 1:1, re-coordinates `index/calls.tsv`/`index/xref.tsv` from zipped old/new AST lists, and re-runs `build_section_shards` + `emit_bundle` **without** executing `resolve_and_link` or `analyze_graph` (`link=0ms graph=0ms` in `--timings`).
  - Any reconstruction failure (missing/truncated/schema-mismatched `graph_state.json`, unparsable or incomplete index tables, conflicting line translations, shard-shape drift) falls back to the full structural path, which now deletes `graph_state.json` before relinking so a failed emit can never leave stale annotations next to fresh tables. Tier 3 output (`index/*`, `sections/*`, `INDEX.md`) is byte-identical to `convert --force`. C/C++ dirty files fall back because header-prototype doc transfer can rewrite another file's docstring.
  - Added `RepoMetadata.incremental_tier` (`cache_hit`, `digest_noop`, `coordinate_shift`, `structural`) for observability, plus `resolver::collect_symbol_tables`, `sharder::shard_group_key`, `sharder::coordinate_shift_grouping_stable`, and a shared `synchronize_indexed_sections` helper used by the structural and coordinate-shift paths.
  - Raised the `INDEX.md` **Core Domain Types & Data Structures** table cap from 12 to 15 rows so the core pipeline types (`ConvertConfig`, `ChipsrcError`, `ConversionBundle`, `ParsedFileUnit`, `ExtractedSymbol`, …) stay listed as the codebase grows.
  - Added tier-selection/line-map unit tests and `invariants.rs` end-to-end coverage for the coordinate shift (`link_ms == 0`, `graph_ms == 0`, shifted `start_line`/`end_line`, `sections/*.md` coordinates, byte-identical to `--force`), docstring-only shifts, the 1,398 → 1,498-line threshold fallback, truncated `graph_state.json`/`meta.json` self-healing, and invalid-UTF-8/Unicode sources with repeated Unicode concept searches.

- **Zero-Alloc `sanitize_tsv`, Pre-Sized Parallel TSV Emission, Uncapped Content-Compare Write Skip & Incremental Sync Hot-Path Optimization (`emitter.rs`, `scanner.rs`, `resolver.rs`, `sharder.rs`, `graph.rs`, `lib.rs`, `main.rs`)**:
  - Changed `emitter::sanitize_tsv(&str) -> Cow<'_, str>` (and `escape_table`) to use a byte-scan fast path (`is_clean_tsv_str`) that returns `Cow::Borrowed` when no control characters, tabs/newlines, leading/trailing spaces, or consecutive spaces are present, and a single-pass `String::with_capacity` builder otherwise.
  - Pre-sized all six `index/*.tsv` buffers in `emit_bundle`, formatted `calls.tsv` and `xref.tsv` with direct string/integer pushes (`push_usize`) and `sections.tsv`/`symbols.tsv`/`types.tsv`/`macros.tsv` with `std::fmt::Write`, and parallelized in-memory Markdown/TSV formatting and output writes via `rayon::join`.
  - Updated `emit_cache_shards` to read `cache/` once via `fs::read_dir`, reuse `structural_digest` from the previous `cache/manifest.json` when `blake3_hash` and `shard` match, write only missing or changed shards, and prune orphaned `.json` shards from the directory set.
  - Removed the 256 KB size cap in `write_file` so unchanged large tables (`calls.tsv`, `xref.tsv`) compare existing bytes whenever `fs::metadata` length matches and skip redundant disk writes (preserving file mtime), and eliminated the duplicate `meta.json` write inside `emit_bundle` so `meta.json` is written once per conversion with final timings.
  - Replaced full-file TSV reads in `scanner::first_missing_bundle_artifact` with 512-byte header-line reads (`read_tsv_header_line`), deferred full bundle-completeness checks to cache-hit/short-circuit gates, disabled parent/global git-config walking in `WalkBuilder`, and precomputed symbol/import path metadata with parallel per-unit resolution in `resolver::resolve_and_link` and `sharder::build_section_shards`, reducing 123-file `smart_locker` incremental structural sync from `477 ms` (`emit = 265 ms`) to `85–95 ms` median (`emit = 21–25 ms`).

### Added

- **Atomic Bundle Writes (`write_bytes_atomic`) & Advisory Bundle Lock (`BundleLock`, `error.rs`, `model.rs`, `emitter.rs`, `lib.rs`, `main.rs`)**:
  - Added `emitter::write_bytes_atomic(path, bytes)` with identical-content skip, sibling `.<name>.<pid>.<seq>.tmp` staging, 5-attempt `fs::rename` with Windows `5/10/20/40 ms` backoff on `PermissionDenied`/sharing violations, and guaranteed `.tmp` cleanup on failure.
  - Routed all bundle writers (`emitter::write_file`, `emit_cache_shards`, and all five `meta.json` / `manifest.json` / cache-shard writes in `lib.rs`) through `write_bytes_atomic`, and updated bundle pruners (`prune_stale_tmp_files_in_dir`, `emit_bundle`, `emit_cache_shards`) to ignore fresh `*.tmp` files and remove stale `*.tmp` files (`> 60 s`).
  - Added `emitter::BundleLock` (`<out>/cache/.lock`, `File::options().write(true).create_new(true)`, `<pid>:<unix_ms>\n`, automatic reclamation of locks `> 10 s` old or with garbage contents via mtime, and `Drop` cleanup) and `ChipsrcError::BundleLocked`.
  - Configured `ConvertConfig.auto_sync` so `auto_refresh_bundles` and `chipsrc hook post-edit` wait up to `150 ms` (`LOCK_WAIT_AUTO_SYNC`) and skip refresh on contention (queries answer from the consistent on-disk bundle; hooks exit `0`), while explicit `chipsrc convert` / `chipsrc ensure` wait up to `5 s` (`LOCK_WAIT_EXPLICIT`) before failing with `ChipsrcError::BundleLocked`.
- **Parameterized In-Repo Black-Box QA Harness (`qa/qa_blackbox.py`, `qa/lib/`, `qa/suites/`, `qa/oracles/`, `qa/fixtures/`, `qa/README.md`)**:
  - Ported the 123-assertion black-box regression suites (`real`, `sync`, `boundary`, `focused`, `hooks`) into the repository as a Python 3.13 standard-library-only harness (`python -I` compatible) with `--bin`, `--repos-root`, `--corpus-root`, `--out`, repeatable `--suite` (`core` alias), `--only`, `--skip`, `--timeout`, and `--fixtures-mode build|require`.
  - Added the 7-assertion `dup-content` suite (`qa/suites/dup_content.py`), checked-in duplicate-content fixtures (`qa/fixtures/dup-content/{alpha,beta}/mod.py`), and oracle (`qa/oracles/dup-content.json`) verifying per-file cache shard disambiguation across cold builds, single-copy edits, `--force` count/hash equivalence, and incremental additions/deletions without external repositories, finalizing the 6-suite `core` alias (130 assertions).
  - Externalized repository-specific golden values to `qa/oracles/{chipsrc,smart_locker,volt_website,beautiful-embedded-c,dup-content}.json`, added skip-if-missing preflight checks, fixed same-second sub-second `st_mtime_ns` carry rollover in `qa/lib/mutate.py`, surfaced negative `expected=None` CLI probes in `<suite>-results.json` and `summary.json`, and isolated all mutations into `<out>/sandboxes/<suite>-<timestamp>/`.
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

- **Accurate `ClaudeIgnore` Status Message for Out-of-Tree Bundles (`emitter.rs`, `main.rs`)**:
  - Added `emitter::is_output_inside_repo` and updated `print_conversion_summary` in `chipsrc-cli` to print `[ok] ClaudeIgnore: not needed (bundle outside repo)` when the output directory is outside the target repository instead of misleadingly printing `already configured`.
- **QA Harness Rerun Idempotency, Fixture-Bundle Separation, Build-Failure Recording & Sandbox Cleanup (`qa/qa_blackbox.py`, `qa/lib/runner.py`, `qa/suites/real.py`, `qa/suites/dup_content.py`, `qa/README.md`)**:
  - Separated checked-in fixture bundles (`<out>/fixture-bundles/<fixture>` via `ensure_fixture_bundle`) from real-repository baseline bundles (`<out>/bundles/<repo>` via `ensure_repo_bundle`), automatically migrating any stray `<out>/bundles/<fixture>` directories and filtering `real` multi-bundle freshness checks to named repository bundles so repeated `--suite core` runs into the same `--out` directory are idempotent.
  - Recorded `<name>: fixture bundle ready` as a failed check with the command's `args`, `exit`, and `wall_ms` when a fixture or baseline bundle build fails under `--fixtures-mode build`.
  - Updated `HarnessContext.check` (along with `skip_record` and `record_observational`) to emit `null` for `args`, `exit`, and `wall_ms` on non-command assertions instead of inheriting values from the previous subprocess invocation.
  - Removed per-suite `<out>/sandboxes/<suite>-<timestamp>/` directories at the end of a successful suite unless `--keep-sandboxes` is passed.
- **Honest Incremental Stage Timings, Header-Validated TSV Integrity & Exact-Symbol Loader (`scanner.rs`, `query.rs`, `lib.rs`)**:
  - Removed the artificial `link_ms = graph_ms = 0` override in `convert_repo` when `resolve_and_link` and `analyze_graph` run after line-count-changing comment edits; `link_ms = graph_ms = shard_ms = 0` is reported only when the real `can_short_circuit` fast path skips those stages.
  - Added `scanner::has_valid_tsv_header` and wired it into `scanner::first_missing_bundle_artifact` and `query::load_index_table` so zero-byte or header-less `index/*.tsv` files are treated as missing/incomplete, self-healed by `ensure`/`convert`/`auto_refresh_bundles`, and flagged as stale by `status --check`.
  - Updated `query::bundles_have_exact_symbol` to read `index/symbols.tsv` through `load_index_table` so `callers` and `callees` with `--no-sync` fail with `ChipsrcError::IncompleteBundle` naming `index/symbols.tsv` instead of silently broadening matches.
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
