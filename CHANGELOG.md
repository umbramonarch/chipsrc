# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/), and the version lives in
`.claude-plugin/plugin.json` and `Cargo.toml`.

## [1.1.0] - 2026-11-04

### Added

- **C++ Template, Namespace & Out-of-Line Method Extraction (`parser.rs`, `resolver.rs`)**:
  - C++ parse buffers are normalized structurally while preserving byte offsets and newlines: trailing annotation macros, statement macros, macro-expanded definitions, extra declaration specifiers, `::new`/`::delete`, pointer-to-member operators, and `using typename` are rewritten; conditional directives are flattened so a declaration split across `#if`/`#else` branches parses as one declaration.
  - Class/struct template names drop their argument lists and types/symbols are namespace-qualified: `namespace demo { template <typename T> class Box ... }` emits `type_id = demo.h::demo::Box`, member methods `demo::Box::method`, and nested classes `demo::Box::Inner`. Out-of-line definitions (`ReturnT Class::method`, `ns::Class::method`, `Class<T>::method`) carry `enclosing_type`/`qualified_name` and exact coordinates, and operator overloads (including conversion operators), constructors (`kind=ctor`), destructors, and `using` aliases (typedef-kind types) are extracted.
  - Signatures of functions inside a `template<...>` carry the template prefix (`template <typename T> ...`), and parameter lists longer than 80 characters collapse to `template<...>`, keeping every signature at 160 characters or fewer.
  - Receiver/qualified call resolution compares enclosing types through their namespace leaf, so `callees`/`callers` resolve across namespace-qualified template classes.
- **Content-Based `.h` C/C++ Header Detection (`scanner.rs`, `model.rs`, `lib.rs`)**:
  - `.h` headers are content-classified: `scanner::detect_file_language` runs a one-pass byte heuristic (`class `, `template<`, `namespace `, `::`, `public:`/`private:`, `typename`, `nullptr`, `constexpr`, `virtual`, `operator`) that skips `//` line comments, `/* ... */` block comments, `"..."`/`'...'` literals, and C++ raw strings (`R"delim(...)delim"`), selecting `LanguageKind::Cpp` only when a marker appears in code.
  - The detected language is recorded on `ScannedFile.language` and `FileStamp.language` so warm stat-only checks reuse the recorded language without re-reading unchanged headers.
- **Deterministic BM25 Concept Search (`query.rs`, `main.rs`, `README.md`)**:
  - `search --kind concept "<words>"` ranks the rows of `index/symbols.tsv`, `index/types.tsv`, and `index/macros.tsv` with BM25 (`k1=1.2`, `b=0.75`) over camelCase / snake_case / acronym sub-tokens (`VendorMode` -> `vendor` + `mode`). `query::tokenize_concept` lowercases, drops 1-character tokens and stopwords, and applies suffix stemming (`s`, `es`, `ed`, `ing`) on tokens of 5+ characters. Fields are weighted name x3, docstring x2, signature/fields/value and file stem x1; the score is multiplied by `(matched_terms / |Q|)^2` and ties break on pagerank then row id.
  - Multi-token `search` queries that produce zero literal/regex hits retry automatically as a concept query; `--source` / `--kind source` disable the fallback.
- **Self-Contained In-Repo Black-Box QA Harness (`qa/qa_blackbox.py`, `qa/lib/`, `qa/suites/`, `qa/oracles/`, `qa/fixtures/`, `qa/README.md`)**:
  - Added a Python 3.13 standard-library-only black-box CLI regression harness (`real`, `dup-content`, `concept`, `cpp`, `sfc`) with checked-in fixtures (`qa/fixtures/{dup-content,cpp,sfc}/`) and externalized oracles (`qa/oracles/*.json`).
- **Atomic Bundle Writes (`write_bytes_atomic`) & Advisory Bundle Lock (`BundleLock`, `error.rs`, `model.rs`, `emitter.rs`, `lib.rs`, `main.rs`)**:
  - Added `emitter::write_bytes_atomic(path, bytes)` with identical-content skip, sibling `.<name>.<pid>.<seq>.tmp` staging, 5-attempt `fs::rename` with Windows backoff, and guaranteed `.tmp` cleanup.
  - Added `emitter::BundleLock` (`<out>/cache/.lock`, heartbeat thread, 10 s stale reclamation, owner-token `Drop`) and `ChipsrcError::BundleLocked`. Background auto-sync waits up to `150 ms` and serves the on-disk bundle on contention; explicit `convert`/`ensure` wait up to `5 s`.
- **Path-Keyed & Packed AST Cache Shards (`2.1.0`), Stat-Only `stamp_check`, Coordinate-Shift Tier 3 & Stage Timings (`model.rs`, `scanner.rs`, `emitter.rs`, `lib.rs`, `main.rs`)**:
  - Replaced monolithic `cache.json` with `cache/manifest.json` (`CACHE_SCHEMA_VERSION = "2.1.0"`), path-keyed `cache/<shard_key>.json` shards (`blake3(rel_path + "\0" + content_hash)`), and deterministic 256-unit `cache/pack-<16hex>.json` packs for repositories with more than 500 source files.
  - Added `scanner::stamp_check` over `(size_bytes, mtime_secs, mtime_nanos)` using `ignore::WalkParallel`, `ParsedFileUnit::structural_digest()` for digest no-op short-circuiting, and `cache/graph_state.json` for Tier 3 coordinate-shift syncs (`link=0ms graph=0ms`).
- **Deterministic 25-Iteration HITS Hub/Authority Ranking (`model.rs`, `graph.rs`, `emitter.rs`)**:
  - Added `compute_hits` alongside PageRank over the high-confidence call graph (`FileScope::Test` callers weighted `0`), emitting `hub_score` and `authority_score` to `RankedSymbol` and `index/symbols.tsv` and ranking God Nodes by `sqrt(hub * auth)`.
- **Native Rust Claude Code Hooks, Universal `--json` Output & CI `status --check` (`main.rs`, `query.rs`, `hooks/hooks.json`)**:
  - Added `chipsrc hook session-start` and `chipsrc hook post-edit` subcommands, `--json` output across all query subcommands, and `chipsrc status --check` (exits with status code `2` when any bundle is `STALE`).
- **Agent-Once Onboarding Blueprint (`.chipsrc.json`) & Turn-1 Discovery (`model.rs`, `scanner.rs`, `mmio.rs`, `parser.rs`, `lib.rs`, `main.rs`)**:
  - Added root `.chipsrc.json` `RepoBlueprint` support (`scopes`, `layers`, `shards`, `ignore_dirs`, `c_qualifiers`, `entrypoints`, `isr_patterns`, `mmio_ranges`) and an Onboarding Digest in `chipsrc inspect`.
- **Local Variable & Parameter Type Binding, Function-Pointer Dispatch & Mutability Dataflow (`mmio.rs`, `parser.rs`, `resolver.rs`)**:
  - Added function-scoped local variable and parameter type binding for receiver resolution, function-pointer dispatch table tracking (`fn_ptr_ref` / `dispatches_fn`), and read/write mutability dataflow (`writes_reg`, `reads_reg`, `writes_field`, `reads_field`) in `index/xref.tsv`.
- **Multi-Hop Shortest Call-Path (`chipsrc path`) & Blast-Radius (`chipsrc impact`) Queries (`query.rs`, `main.rs`)**:
  - Added `chipsrc path <from> <to> [--max-depth N]` and `chipsrc impact <symbol> [--max-depth N]`.
- **Single-File Component (`.astro`, `.vue`, `.svelte`) & JSX/TSX Extraction (`model.rs`, `parser.rs`)**:
  - Added byte-aligned SFC preprocessing (`preprocess_sfc_to_tsx`), component symbol synthesis, JSX/template PascalCase component usage call/xref edges, HTTP route handler entrypoint classification, and exported constant indexing.
- **Core Domain Types Table & Oversized Module Sub-Sharding (`model.rs`, `scanner.rs`, `sharder.rs`, `emitter.rs`, `query.rs`, `lib.rs`)**:
  - Added a **Core Domain Types & Data Structures** table in `INDEX.md` and automatic sub-sharding in `sharder.rs` for oversized first-party modules (`> 8` files or `> 3,000` lines).

### Changed

- **Structural Call-Noise Pruning (`resolver.rs`)**:
  - `resolver::resolve_and_link` drops unresolved (`external_or_macro`) receiver/qualified calls whose short name is defined by no non-Test symbol and bare Rust `PascalCase(...)` calls that name no callable symbol, while preserving all resolved tiers and bare unqualified calls.

### Fixed

- **Bundle Artifact Integrity Gate, Missing-Table Self-Heal & Explicit `--no-sync` Errors (`error.rs`, `model.rs`, `scanner.rs`, `query.rs`, `lib.rs`, `main.rs`)**:
  - Added `scanner::bundle_artifacts_complete` and `scanner::first_missing_bundle_artifact` verifying `meta.json`, `INDEX.md`, all six `index/*.tsv` tables (with valid headers), every referenced `sections/*.md`, `cache/manifest.json`, and every listed cache shard/pack.
  - Replaced silent TSV reads in `query.rs` with `load_index_table` returning `ChipsrcError::IncompleteBundle { bundle, missing }` when `--no-sync` runs against an incomplete bundle.
- **Unified Source Line Counting (`scanner.rs`)**:
  - Added `scanner::count_source_lines(bytes)` and wired it into both `scan_repository` and `stamp_check` so incremental syncs, `--force` rebuilds, and `chipsrc inspect` report identical line counts.
- **Sharder, C/CMSIS Qualifier, Query Identity, Vendor Surface & Receiver Binding Fixes (`scanner.rs`, `parser.rs`, `mmio.rs`, `resolver.rs`, `graph.rs`, `sharder.rs`, `sanity.rs`, `emitter.rs`, `query.rs`)**:
  - Fixed sub-shard scope/file resolution in `sharder.rs`, CMSIS struct qualifier normalization (`__I`, `__O`, `__IO`, `__IM`, `__OM`, `__IOM`), `SymbolIdView` (`parse_symbol_id`) file-vs-symbol disambiguation in `query.rs`, active vendor surface header/macro filtering, and C/C++ uppercase callable preservation.

## [1.0.0] - 2026-10-27

### Added

- **Core Source-to-Agent Extraction Engine (`crates/chipsrc-core`)**:
  - Parallel `.gitignore`-aware repository scanner (`scanner.rs`) with BLAKE3 file and tree fingerprinting (`meta.json`).
  - Multi-language Tree-sitter AST parser (`parser.rs`) supporting C, C++, Rust, Python, TypeScript, and JavaScript.
  - Structural extraction for function/method signatures, struct/enum/trait/type definitions, static caller->callee edges, `#define` / `const` constants, and peripheral MMIO register / ISR vector usage.
  - Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`).
  - Hierarchical Agent Codebase Bundle emitter (`sharder.rs`, `emitter.rs`, `sanity.rs`) producing `INDEX.md`, module-sharded `sections/*.md` signature skeletons, flat `index/*.tsv` tables, `meta.json`, and `.claudeignore` prompt-cache protection.
- **1-Turn Agent Code Intelligence CLI (`crates/chipsrc-cli` & `query.rs`)**:
  - `chipsrc status`, `ensure`, `convert`, `inspect`, `sym`, `type`, `callers`, `callees`, `macro`/`reg`/`mmio`, `xref`/`explain`, `section`, and `search`.
- **Hybrid Claude Code Plugin (`.claude-plugin/`, `skills/chipsrc/`)**:
  - `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` manifests and `/chipsrc` skill (`skills/chipsrc/SKILL.md`).

[Unreleased]: https://github.com/umbramonarch/chipsrc/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/umbramonarch/chipsrc/releases/tag/v1.1.0
[1.0.0]: https://github.com/umbramonarch/chipsrc/releases/tag/v1.0.0
