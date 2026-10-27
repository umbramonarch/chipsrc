# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/), and the version lives in
`.claude-plugin/plugin.json` and `Cargo.toml`.

## [Unreleased]

### Added

- **Single-File Component (`.astro`, `.vue`, `.svelte`) & JSX/TSX Extraction (`model.rs`, `parser.rs`)**:
  - Added byte-aligned SFC preprocessing (`preprocess_sfc_to_tsx`) that preserves exact 1:1 byte and line coordinates across frontmatter (`---`), `<script>` blocks, and component templates.
  - Added component symbol synthesis, JSX/template PascalCase component usage call/xref edges (`<Component />`), nested helper arrow-function extraction, HTTP route handler entrypoint classification (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `ALL`), and exported constant indexing.

### Fixed

- **Vendor-Neutral SDK & Asset Classification (`scanner.rs`, `sharder.rs`)**:
  - Replaced hardcoded chip/vendor tokens with structural composite directory sub-token classification (`driverlib`, `cmsis`, `thirdparty`, `3rdparty`, `vendor`, `svd`, `sdk`, `bundled`, `submodules`, `middlewares`) and root-scoped reference directories (`references/`, `reference/`).
  - Removed overly broad directory exclusions (`html`, `site`) and refined bundled JavaScript asset detection (`*.min.js`, `*.bundle.js`, versioned doc-generator scripts) so first-party modules (`bootstrap.js`, `site/`, `html/`) are never dropped.
  - Changed shard group scope resolution to dominant/majority ownership, synchronized fallback `ArchLayer::Other` symbol/type/macro layers with their module shard, and filtered `VendorMode::Active` shards strictly to retained active files.
- **Context-Aware C/C++ Qualifier Normalization & Signature Extraction (`parser.rs`, `sanity.rs`)**:
  - Replaced hardcoded vendor macro tables with structural top-level (`brace_depth == 0 && paren_depth == 0`) declaration-context normalization for `STATIC`, `CONST`, `INLINE`, `*_STATIC_INLINE`, `*_FORCEINLINE`, `*_WEAK`, `*_IRQ`, `*_INTERRUPT`, `*_RAMFUNC`, and `*_PACKED`, preserving `enum { STATIC = 0, CONST = 1 };` and exact byte lengths.
  - Fixed `extract_clean_signature` to use AST block body boundaries and parenthesis-aware brace splitting so destructured parameters (`({ request }) =>`) and object literals are never truncated.
  - Filtered C control-flow keywords from misparsed conditional blocks and skipped decorative ASCII divider banners (`---- label ----`, `====`) when extracting doc summaries.
- **Cross-Language Call Isolation, Relative Import Resolution & Query Precision (`resolver.rs`, `graph.rs`, `query.rs`)**:
  - Merged C/C++ forward header prototype declarations into matching `.c`/`.cpp` implementations with exact case and parameter-arity checking.
  - Added caller `enclosing_type` binding for `self`/`this`/`cls` receivers, import-aware builtin guards, relative import path normalization (`./`, `../`), and receiver filtering in Tier 2 (`ImportResolved`).
  - Improved 1-turn CLI queries (`sym`, `type`, `callers`, `callees`) to suppress low-confidence substring matches when exact symbol/type matches exist.

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
