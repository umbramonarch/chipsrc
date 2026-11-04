# Repository Guidelines (`chipsrc`)

## Project Structure & Module Organization

`chipsrc` is the sister project to `chipdoc`. While `chipdoc` converts technical PDFs (datasheets, TRMs, errata) into **Hierarchical Agent Documentation Bundles**, `chipsrc` converts firmware and software source repositories (C, C++, Rust, Python, TypeScript, JavaScript) into **Hierarchical Agent Codebase Bundles** (`INDEX.md` + module-sharded `sections/*.md` signature skeletons + flat `index/*.tsv` symbol/type/call/macro/xref tables + `meta.json` + path-keyed incremental AST cache shards in `cache/`) and provides a 1-turn **Agent Code Intelligence CLI** and **Hybrid Claude Code Plugin** with automatic code-change synchronization.

The architecture enforces a strict unidirectional **Layered DAG (`Layer 0` -> `Layer 5`)** with zero circular dependencies:

- `Cargo.toml`: Workspace manifest defining shared dependencies, lints, and release profiles.
- `crates/chipsrc-core/`: Core source scanning, Tree-sitter AST parsing, symbol/type/call/macro extraction, cross-reference graph, incremental AST caching, query engine, and bundle emission library.
  - **Layer 0 — Domain Model (`src/model.rs`, `src/error.rs`)**: Pure canonical domain data structures (`LanguageKind`, `FileScope`, `ArchLayer`, `VendorMode`, `ScannedFile`, `ExtractedSymbol`, `ExtractedType`, `ExtractedMacro`, `ParsedFileUnit`, `IncrementalAstCache`, `RankedSymbol`, `ResolvedCallEdge`, `XrefEntry`, `SectionShard`, `RepoMetadata`, `SanityReport`, `ConvertConfig`, `ConversionBundle`, `InspectReport`, `SearchHit`, `BundleStatusEntry`) and typed error enum (`ChipsrcError`).
  - **Layer 1 — Ingestion, MMIO & AST Parsing (`src/mmio.rs`, `src/scanner.rs`, `src/parser.rs`)**:
    - `src/mmio.rs`: Hardware/MMIO register address classification, datasheet hex normalization (`0x400` <-> `400h`), peripheral `PERIPH->REG` / `*(volatile ...)` extraction, and linker section attribute detection.
    - `src/scanner.rs`: Parallel `.gitignore`-aware directory walker (`ignore` + `rayon`), `FirstParty` / `VendorSdk` / `Test` scope classification, architectural layer detection (`app`, `bsp`, `drvs`, `config`, `libs`, `domain`, `services`, `api`, `core`, `cli`, `vendor_hal`, `tests`), deterministic BLAKE3 per-file & Merkle repository fingerprinting, `(size_bytes, mtime_secs, mtime_nanos)` stamp checks (`stamp_check`), unified `count_source_lines`, bundle artifact-integrity checks, and content-based `.h` C/C++ language detection.
    - `src/parser.rs`: Multi-language Tree-sitter dispatcher (`C`, `C++`, `Rust`, `Python`, `TypeScript`, `TSX`, `JavaScript`, `JSX`, plus `.astro`/`.vue`/`.svelte` SFCs) with C++ class templates, namespaces, nested classes, out-of-line `Class::method`, operator overloads, and per-file AST caching (`cache/manifest.json` + shards/packs) so code edits only re-parse changed files.
  - **Layer 2 — Call Resolution, Graph Analysis, Sharding & Sanity (`src/resolver.rs`, `src/graph.rs`, `src/sharder.rs`, `src/sanity.rs`)**:
    - `src/resolver.rs`: Resolves static `caller -> callee` call-graph edges with 5-tier provenance (`SameFile`, `ImportResolved`, `UniqueGlobal`, `AmbiguousName`, `ExternalOrMacro`), builds the Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`), and computes active vendor SDK / MMIO surfaces (`--vendor-mode active|all|none`).
    - `src/graph.rs`: Runs 25-iteration deterministic PageRank (`god_nodes`), iterative Tarjan SCC cycle detection, entrypoint/ISR identification, and cross-layer dependency edge analysis (`from_layer -> to_layer` with upward violation detection).
    - `src/sharder.rs`: Groups source files by architectural module hierarchy (auto-splitting oversized modules into cohesive sub-shards) into compact Markdown signature skeletons (`sections/*.md`) that omit verbose function bodies while preserving docstrings, signatures, type definitions, and `file:start_line-end_line` coordinates.
    - `src/sanity.rs`: Computes token-compression ratio, clean parse coverage, high-confidence call resolution ratio, and structural sanity score (0–100).
  - **Layer 3 — Bundle Emission & 1-Turn Query Engine (`src/emitter.rs`, `src/query.rs`)**:
    - `src/emitter.rs`: Writes `INDEX.md`, `sections/*.md`, `index/*.tsv`, `meta.json`, `cache/manifest.json`, cache shards/`pack-<16hex>.json` packs, `cache/graph_state.json`, `--single-file`, and `.claudeignore` (only when output is inside the target repository). Owns `write_bytes_atomic` (temp file + rename) and the advisory `BundleLock` on `<out>/cache/.lock`.
    - `src/query.rs`: Multi-bundle discovery, automatic stale-bundle incremental refresh (`auto_refresh_bundles`), C/vendor hex & peripheral prefix normalization (`0x400` <-> `400h`, `GPIO_MODER` <-> `GPIO->MODER`), 1-turn domain queries (`sym`, `callers`, `callees`, `path`, `impact`, `type`, `macro`/`reg`/`mmio`, `section`, `xref`), parallel SIMD (`memchr` + `rayon`) index & raw-source search, deterministic BM25 concept search (`--kind concept` plus automatic multi-token fallback), and `load_index_table` errors for missing `index/*.tsv`.
  - **Layer 4 — Library Facade (`src/lib.rs`)**: Orchestrates `inspect_repo`, tiered `convert_repo` (integrity gate -> stat hit -> digest no-op -> coordinate shift -> structural), `ensure_repo`, `auto_refresh_bundles`, and `workspace_status`.
- **Layer 5 — CLI & Auto-Sync Plugin (`crates/chipsrc-cli/`, `.claude-plugin/`, `hooks/`, `scripts/`, `skills/chipsrc/`)**:
  - `crates/chipsrc-cli/src/main.rs`: Command-line interface binary (`chipsrc`) implementing `convert` (alias `index`), `ensure`, `status`, `inspect`, `sym`, `callers`, `callees`, `path`, `impact`, `type`, `macro` (aliases `reg`, `mmio`), `section`, `xref` (alias `explain`), and `search` (`-S`/`--source`, `--kind concept`).
  - `.claude-plugin/`, `hooks/hooks.json`, `scripts/_hook_common.py`, `scripts/session_start_hook.py`, `scripts/post_edit_hook.py`, `skills/chipsrc/SKILL.md`: Hybrid Claude Code plugin with `SessionStart` bundle discovery/refresh hook and `PostToolUse` (`Edit|Write|MultiEdit`) auto-sync hook (background lock budget 150 ms, then serve the on-disk bundle).

### Incremental Sync, Cache Layout & Concurrency

- **Cache shards are path-keyed, not purely content-addressed**: `cache/<shard_key>.json` where `shard_key = blake3(rel_path + "\0" + content_hash)`. Byte-identical files at different paths never share a shard. Repositories with more than 500 source files use deterministic 256-unit packs (`cache/pack-<16hex>.json`); `cache/manifest.json` (`CACHE_SCHEMA_VERSION` `2.1.0`) maps every path to its hash, structural digest, and shard.
- **Tier ladder**: (0) bundle artifact-integrity gate -> full rebuild when incomplete; (1) stat-only `(size_bytes, mtime_secs, mtime_nanos)` hit -> `CACHE HIT`; (2) digest no-op when `structural_digest` **and** coordinates/line counts are unchanged -> shard + `meta.json` only; (3) coordinate shift with the digest unchanged but lines/docstrings moved -> skip `resolve_and_link` and `analyze_graph` (`link=0ms graph=0ms`); (4) structural -> full link/graph/shard/emit. Any doubt falls back to a lower tier; never emit a partial bundle.
- **Atomic writes and lock**: all bundle writes go through `write_bytes_atomic` (temp file + rename with Windows retry); writers hold the advisory `<out>/cache/.lock` (`create_new`, 10 s stale window, heartbeat, owner-token `Drop`). Query auto-refresh and `hook post-edit` wait at most **150 ms** and then skip the refresh (reading the consistent on-disk bundle); explicit `convert`/`ensure` wait at most **5 s** and then fail with `BundleLocked`.

## Build, Test, and Development Commands

- `cargo build --release`: Build optimized `chipsrc` binary (`target/release/chipsrc.exe`).
- `cargo test --workspace`: Run all unit and integration tests across the workspace.
- `cargo fmt --all -- --check`: Check Rust formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: Run strict static analysis with zero warnings permitted.
- `cargo run --release -p chipsrc-cli -- convert . -o output/chipsrc --vendor-mode active`: Convert a repository into an Agent Codebase Bundle with active vendor SDK surface filtering.
- `cargo run --release -p chipsrc-cli -- ensure . -o output/`: Ensure a repository is indexed and incrementally synchronized (stat-only cache hit; 1-file structural sync under 100 ms on a 123-file repo, warm 12k-file check ~175 ms).
- `cargo run --release -p chipsrc-cli -- status --sync`: Show indexed codebase bundles (`FRESH` vs `STALE`) and synchronize any modified source files.
- `cargo run --release -p chipsrc-cli -- inspect .`: Inspect language breakdown, first-party vs vendor SDK file counts, and architectural layers.
- `cargo run --release -p chipsrc-cli -- sym lock_actuator -s`: Query function/method signature, doc comment, call relationships, and inline source body in 1 turn.
- `cargo run --release -p chipsrc-cli -- type ConvertConfig -s`: Query struct/enum/trait definition and fields in 1 turn.
- `cargo run --release -p chipsrc-cli -- callers parse_register`: List all callers of a function across the codebase.
- `cargo run --release -p chipsrc-cli -- reg 0x41C00004`: Query `#define` macros, constants, or MMIO hex register offsets (`macro`, `reg`, `mmio`).
- `cargo run --release -p chipsrc-cli -- xref GPIOA`: Query the Code + Hardware Cross-Reference Graph across all bundles.
- `python qa/qa_blackbox.py --suite core --bin target/release/chipsrc.exe --repos-root D:/projects --corpus-root D:/projects/chipsrc-mission-corpus --out D:/projects/chipsrc-mission-corpus/qa-results`: Run the in-repo stdlib-only black-box QA harness (`core` = `real`, `sync`, `boundary`, `focused`, `hooks`, `dup-content`). Heavier suites: `perf`, `concurrency`, `scale`, `concept`, `cpp`, `corpus`, `sfc`. Real repositories are read-only; mutations run in sandbox copies. See `qa/README.md`.

## Coding Style & Naming Conventions

- **Rust Edition 2021+**: Follow `rustfmt` defaults (4-space indentation, `snake_case` functions/modules, `PascalCase` types/traits, `SCREAMING_SNAKE_CASE` constants).
- **Language- & Vendor-Neutral Rules**: Keep all AST extraction heuristics 100% deterministic and vendor-neutral. Never hardcode project-specific filenames or chip part numbers; rely on Tree-sitter grammar node kinds and structural identifier patterns.
- **Strict Layering**: Lower layers (`Layer 0`..`Layer 3`) must never import higher layers (`emitter`, `query`, or CLI).
- **Error Handling**: Use typed errors (`thiserror`) in `chipsrc-core` and contextual reporting (`anyhow`) in `chipsrc-cli`. Never `unwrap()` untrusted source files or malformed UTF-8 inputs when graceful skip/fallback is possible.

## Commit & Pull Request Guidelines

- **Branch workflow**: Work on dedicated feature or fix branches (`feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`) and merge to `main`.
- **Verification before commit**: Every commit must pass `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible features or fixes.
