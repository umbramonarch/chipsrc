# Repository Guidelines (`chipsrc`)

## Project Structure & Module Organization

`chipsrc` is the sister project to `chipdoc`. While `chipdoc` converts technical PDFs (datasheets, TRMs, errata) into **Hierarchical Agent Documentation Bundles**, `chipsrc` converts firmware and software source repositories (C, C++, Rust, Python, TypeScript, JavaScript) into **Hierarchical Agent Codebase Bundles** (`INDEX.md` + module-sharded `sections/*.md` signature skeletons + flat `index/*.tsv` symbol/type/call/macro/xref tables + `meta.json` + per-file incremental AST `cache.json`) and provides a 1-turn **Agent Code Intelligence CLI** and **Hybrid Claude Code Plugin** with automatic code-change synchronization.

The architecture enforces a strict unidirectional **Layered DAG (`Layer 0` -> `Layer 5`)** with zero circular dependencies:

- `Cargo.toml`: Workspace manifest defining shared dependencies, lints, and release profiles.
- `crates/chipsrc-core/`: Core source scanning, Tree-sitter AST parsing, symbol/type/call/macro extraction, cross-reference graph, incremental AST caching, query engine, and bundle emission library.
  - **Layer 0 — Domain Model (`src/model.rs`, `src/error.rs`)**: Pure canonical domain data structures (`LanguageKind`, `FileScope`, `ArchLayer`, `VendorMode`, `ScannedFile`, `ExtractedSymbol`, `ExtractedType`, `ExtractedMacro`, `ParsedFileUnit`, `IncrementalAstCache`, `RankedSymbol`, `ResolvedCallEdge`, `XrefEntry`, `SectionShard`, `RepoMetadata`, `SanityReport`, `ConvertConfig`, `ConversionBundle`, `InspectReport`, `SearchHit`, `BundleStatusEntry`) and typed error enum (`ChipsrcError`).
  - **Layer 1 — Ingestion & AST Parsing (`src/scanner.rs`, `src/parser.rs`)**:
    - `src/scanner.rs`: Parallel `.gitignore`-aware directory walker (`ignore` + `rayon`), `FirstParty` / `VendorSdk` / `Test` scope classification, architectural layer detection (`app`, `bsp`, `drvs`, `config`, `libs`, `domain`, `services`, `api`, `core`, `cli`, `vendor_hal`, `tests`), and deterministic BLAKE3 per-file & Merkle repository fingerprinting.
    - `src/parser.rs`: Multi-language Tree-sitter dispatcher (`C`, `C++`, `Rust`, `Python`, `TypeScript`, `TSX`, `JavaScript`, `JSX`) with incremental per-file AST caching (`cache.json`) so code edits only re-parse changed files.
  - **Layer 2 — Structural Extractors (`src/symbols.rs`, `src/types.rs`, `src/calls.rs`, `src/macros.rs`)**:
    - `src/symbols.rs`: Extracts functions, methods, constructors, entrypoints, and ISR handlers (`index/symbols.tsv`).
    - `src/types.rs`: Extracts `struct`, `enum`, `union`, `typedef`, `trait`, `interface`, and `class` definitions with ordered fields and types (`index/types.tsv`).
    - `src/calls.rs`: Extracts static `caller -> callee` call-graph edges with resolution provenance (`SameFile`, `ImportResolved`, `UniqueGlobal`, `AmbiguousName`, `ExternalOrMacro`) (`index/calls.tsv`).
    - `src/macros.rs`: Extracts `#define` constants, function-like macros, `const` / `constexpr` items, bitmasks, and MMIO hex register addresses (`index/macros.tsv`).
  - **Layer 3 — Cross-Reference Graph & Module Sharding (`src/xref.rs`, `src/sharding.rs`)**:
    - `src/xref.rs`: Builds the Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`), computes PageRank (`god_nodes`), Tarjan SCC cycles, upward layer-violation edges, and active vendor SDK / MMIO surfaces (`--vendor-mode active|all|none`).
    - `src/sharding.rs`: Groups source files by architectural module hierarchy into compact Markdown signature skeletons (`sections/*.md`) that omit verbose function bodies while preserving docstrings, signatures, type definitions, and `file:start_line-end_line` coordinates.
  - **Layer 4 — Emission, Sanity & 1-Turn Query Engine (`src/emitter.rs`, `src/sanity.rs`, `src/query.rs`)**:
    - `src/emitter.rs`: Writes `INDEX.md`, `sections/*.md`, `index/*.tsv`, `meta.json`, `cache.json`, `--single-file`, and `.claudeignore`.
    - `src/sanity.rs`: Computes token-compression ratio, clean parse coverage, call resolution ratio, and structural sanity score (0–100).
    - `src/query.rs`: Multi-bundle discovery, automatic stale-bundle incremental refresh (`auto_refresh_bundles`), C/vendor hex & peripheral prefix normalization (`0x400` <-> `400h`, `GPIO_MODER` <-> `GPIO->MODER`), 1-turn domain queries (`sym`, `callers`, `callees`, `type`, `macro`/`reg`/`mmio`, `section`, `xref`), and parallel SIMD (`memchr` + `rayon`) search.
- **Layer 5 — CLI & Auto-Sync Plugin (`crates/chipsrc-cli/`, `.claude-plugin/`, `hooks/`, `scripts/`, `skills/chipsrc/`)**:
  - `crates/chipsrc-cli/src/main.rs`: Command-line interface binary (`chipsrc`) implementing `convert` (alias `index`), `ensure`, `status`, `inspect`, `sym`, `callers`, `callees`, `type`, `macro` (aliases `reg`, `mmio`), `section`, `xref` (alias `explain`), and `search`.
  - `.claude-plugin/`, `hooks/hooks.json`, `scripts/session_start_hook.py`, `scripts/post_edit_hook.py`, `skills/chipsrc/SKILL.md`: Hybrid Claude Code plugin with `SessionStart` bundle discovery/refresh hook and `PostToolUse` (`Edit|Write|MultiEdit`) incremental `<50ms` auto-sync hook.

## Build, Test, and Development Commands

- `cargo build --release`: Build optimized `chipsrc` binary (`target/release/chipsrc.exe`).
- `cargo test --workspace`: Run all unit and integration tests across the workspace.
- `cargo fmt --all -- --check`: Check Rust formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: Run strict static analysis with zero warnings permitted.
- `cargo run --release -p chipsrc-cli -- convert . -o output/chipsrc --vendor-mode active`: Convert a repository into an Agent Codebase Bundle with active vendor SDK surface filtering.
- `cargo run --release -p chipsrc-cli -- ensure . -o output/`: Ensure a repository is indexed and incrementally synchronized (`<2ms` on BLAKE3 cache hit, `<50ms` incremental single-file sync).
- `cargo run --release -p chipsrc-cli -- status --sync`: Show indexed codebase bundles (`FRESH` vs `STALE`) and synchronize any modified source files.
- `cargo run --release -p chipsrc-cli -- inspect .`: Inspect language breakdown, first-party vs vendor SDK file counts, and architectural layers.
- `cargo run --release -p chipsrc-cli -- sym lock_actuator -s`: Query function/method signature, doc comment, call relationships, and inline source body in 1 turn.
- `cargo run --release -p chipsrc-cli -- type ConvertConfig -s`: Query struct/enum/trait definition and fields in 1 turn.
- `cargo run --release -p chipsrc-cli -- callers parse_register`: List all callers of a function across the codebase.
- `cargo run --release -p chipsrc-cli -- reg 0x41C00004`: Query `#define` macros, constants, or MMIO hex register offsets (`macro`, `reg`, `mmio`).
- `cargo run --release -p chipsrc-cli -- xref GPIOA`: Query the Code + Hardware Cross-Reference Graph across all bundles.

## Coding Style & Naming Conventions

- **Rust Edition 2021+**: Follow `rustfmt` defaults (4-space indentation, `snake_case` functions/modules, `PascalCase` types/traits, `SCREAMING_SNAKE_CASE` constants).
- **Language- & Vendor-Neutral Rules**: Keep all AST extraction heuristics 100% deterministic and vendor-neutral. Never hardcode project-specific filenames or chip part numbers; rely on Tree-sitter grammar node kinds and structural identifier patterns.
- **Strict Layering**: Lower layers (`Layer 0`..`Layer 3`) must never import higher layers (`emitter`, `query`, or CLI).
- **Error Handling**: Use typed errors (`thiserror`) in `chipsrc-core` and contextual reporting (`anyhow`) in `chipsrc-cli`. Never `unwrap()` untrusted source files or malformed UTF-8 inputs when graceful skip/fallback is possible.

## Commit & Pull Request Guidelines

- **Branch workflow**: Work on dedicated feature or fix branches (`feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`) and merge to `main`.
- **Verification before commit**: Every commit must pass `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible features or fixes.
