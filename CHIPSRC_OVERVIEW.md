# `chipsrc` — Architecture, Verification, and Roadmap (1.1.0)

## 1. Executive Summary & Core Design Philosophy

`chipsrc` is a **100% deterministic, zero-LLM code intelligence engine, CLI, and Hybrid Claude Code plugin** written in Rust. It converts firmware and software source repositories (`C`, `C++`, `Rust`, `Python`, `TypeScript`, `TSX`, `JavaScript`, `JSX`, plus `.astro`, `.vue`, and `.svelte` single-file components) into queryable **Hierarchical Agent Codebase Bundles** (`INDEX.md`, `sections/*.md`, `index/*.tsv`, `meta.json`, and incremental `cache/` AST shards).

**Version 1.1.0** is the production-hardening release: it hardens incremental synchronization at 12k-file scale, adds path-keyed and packed AST cache shards (`2.1.0`), adds coordinate-shift Tier 3 incremental sync, adds structural call-noise pruning and deterministic BM25 concept search, adds content-based C++ header detection and template/namespace/out-of-line method extraction, and ships a self-contained black-box E2E test and QA suite. `README.md` documents the user-facing behavior; this document records the architecture, the verification evidence, and what remains.

### Can `chipsrc` Function Independently Without an LLM?
**Yes — and it should remain 100% independent of any local or remote LLM in its core pipeline.**

1. **The caller is already a frontier LLM**: `chipsrc` is built for AI coding agents (Claude Code, Factory Droid, Cursor). Placing a small local model inside `chipsrc` creates a slow, redundant "LLM summarizing for an LLM" bottleneck where the smaller model has lower accuracy than deterministic AST extraction.
2. **Latency and resource constraints**: measured on a 12-core system, a 1,221-file C++ template library converts cold in ~9.4 s and a 12,471-file C vendor HAL SDK tree (4.55M lines) in a median 24.3 s; warm checks take a median 174 ms and indexed queries answer in ~45 ms with `--no-sync`. Adding even a small local model or embedding runtime would add hundreds of milliseconds to seconds per invocation plus a model's RAM footprint.
3. **Deterministic caching and CI verification**: every bundle is keyed by a deterministic BLAKE3 Merkle fingerprint. Identical source trees always produce byte-identical TSV indexes, Markdown skeletons, and graph rankings.

---

## 2. How `chipsrc` Functions (End-to-End Architecture)

`chipsrc` enforces a strict unidirectional **Layered DAG (`Layer 0` $\to$ `Layer 5`)** with zero circular dependencies. `crates/chipsrc-core/tests/architecture_dag.rs` asserts that the core crate contains **exactly twelve modules** and that no module imports a higher layer.

```mermaid
flowchart TD
    L5["Layer 5: CLI & Native Hooks (chipsrc-cli, hooks.json)"] --> L4["Layer 4: Library Facade (lib.rs)"]
    L4 --> L3E["Layer 3: Bundle Emitter (emitter.rs)"]
    L4 --> L3Q["Layer 3: 1-Turn Query Engine (query.rs)"]
    L3E --> L2R["Layer 2: Call & Xref Resolver (resolver.rs)"]
    L3E --> L2G["Layer 2: PageRank/HITS/SCC Graph (graph.rs)"]
    L3E --> L2S["Layer 2: Module Skeleton Sharder (sharder.rs)"]
    L3E --> L2N["Layer 2: Sanity Scorer (sanity.rs)"]
    L3Q --> L1S["Layer 1: Scanner & Stamp Check (scanner.rs)"]
    L2R --> L1P["Layer 1: Tree-sitter Multi-Lang Parser (parser.rs)"]
    L1P --> L1M["Layer 1: Hardware / MMIO Normalizer (mmio.rs)"]
    L1S --> L0["Layer 0: Domain Model & Errors (model.rs, error.rs)"]
    L1P --> L0
    L1M --> L0
```

### Layer-by-Layer Responsibilities

| Layer | Module(s) | How It Works |
| :--- | :--- | :--- |
| **Layer 0: Domain Model** | `model.rs`, `error.rs` | Canonical data structures (`ScannedFile`, `FileStamp`, `ExtractedSymbol`, `ExtractedType`, `ExtractedMacro`, `ParsedFileUnit`, `ResolvedCallEdge`, `XrefEntry`, `SectionShard`, `RepoMetadata`, `SanityReport`, `CacheManifest`), `CACHE_SCHEMA_VERSION` (`2.1.0`), and typed errors (`ChipsrcError`, including `IncompleteBundle` and `BundleLocked`). |
| **Layer 1: Ingestion, MMIO & AST Parsing** | `scanner.rs`, `parser.rs`, `mmio.rs` | **Scanner**: parallel `.gitignore`-aware walker (`ignore` + `rayon`), `FirstParty` / `VendorSdk` / `Test` scope classification, architectural layer detection, BLAKE3 Merkle fingerprinting, stat-only `stamp_check` on `(size, mtime_secs, mtime_nanos)`, unified `count_source_lines`, bundle artifact-integrity checks, and content-based `.h` C/C++ detection.<br>**Parser**: multi-language Tree-sitter dispatcher (`C`, `C++`, `Rust`, `Python`, `TS`, `TSX`, `JS`, `JSX`) with byte-aligned TSX projection for `.astro`/`.vue`/`.svelte`, CMSIS qualifier handling, and C++ class templates, namespaces, nested classes, out-of-line `Class::method`, operator overloads, and long-template signature collapsing.<br>**MMIO**: normalizes hex register literals (`0x400` $\leftrightarrow$ `400h`), extracts peripheral accesses (`GPIOA->MODER`, `*(volatile uint32_t *)`), and detects linker sections (`.intvecs`, `.ccmram`). |
| **Layer 2: Resolution, Graph, Sharding & Sanity** | `resolver.rs`, `graph.rs`, `sharder.rs`, `sanity.rs` | **Resolver**: links `caller -> callee` edges across five confidence tiers (`same_file`, `import_resolved`, `unique_global`, `ambiguous_name`, `external_or_macro`), drops structural call noise (unresolved qualified calls to names defined nowhere, unresolved bare Rust `PascalCase` constructors), builds the Unified Code + Hardware Cross-Reference Graph (`index/xref.tsv`), and computes active vendor SDK surfaces (`--vendor-mode active\|all\|none`).<br>**Graph**: 25-iteration deterministic PageRank + HITS, iterative Tarjan SCC cycle detection, entrypoint/ISR detection, and upward layer-violation detection.<br>**Sharder**: groups files by module into compact Markdown signature skeletons (`sections/*.md`) that keep docstrings, type fields, and signatures with exact `file:start_line-end_line` coordinates, auto-splitting oversized modules.<br>**Sanity**: computes token compression ratio, clean parse ratio, call resolution ratio, and a structural sanity score (`0–100`). |
| **Layer 3: Bundle Emission & 1-Turn Query Engine** | `emitter.rs`, `query.rs` | **Emitter**: writes `INDEX.md`, `sections/*.md`, `index/*.tsv`, `meta.json`, `cache/manifest.json`, per-file shards or 256-unit packs, `cache/graph_state.json`, optional `--single-file`, and `.claudeignore`. All writes go through `write_bytes_atomic`; writers hold the advisory `BundleLock` on `<out>/cache/.lock`.<br>**Query Engine**: discovers bundles, runs the automatic freshness/self-heal gate (`auto_refresh_bundles`), and executes 1-turn queries (`sym`, `type`, `callers`, `callees`, `path`, `impact`, `macro`/`reg`/`mmio`, `section`, `xref`, `search`), including regex/literal search and deterministic BM25 concept search. |
| **Layer 4 & 5: Facade, CLI & Auto-Sync Hooks** | `lib.rs`, `crates/chipsrc-cli/src/main.rs`, `hooks/hooks.json` | Library entrypoints (`inspect_repo`, `convert_repo`, `ensure_repo`, `auto_refresh_bundles`, `workspace_status`) and the `chipsrc` binary, including native `chipsrc hook session-start` and `chipsrc hook post-edit` subcommands for automatic Claude Code synchronization. |

### Cache Layout

- `cache/manifest.json` (schema `2.1.0`) maps every relative path to its BLAKE3 content hash, structural digest, language, and shard.
- Per-file shards are keyed by `blake3(rel_path + "\0" + content_hash)`. They are **not** purely content-addressed: byte-identical files at different paths must never alias, because a shard carries path-dependent data.
- Repositories with more than 500 source files pack 256 units into deterministic `cache/pack-<16hex>.json` files (12,471 files -> 49 packs); smaller repositories keep one shard per file.
- `cache/graph_state.json` persists the linked-graph annotations (PageRank/HITS/degree/SCC, god nodes, entrypoints, layer edges, cycles, vendor surface) that cannot be re-derived from a single file's AST.

### How Incremental Synchronization Works

`convert`, `ensure`, query auto-refresh, and both hooks share one tier ladder:

1. **Tier 0 — Integrity gate**: `meta.json`, `INDEX.md`, all six `index/*.tsv` (with valid headers), every `sections/*.md` listed in `index/sections.tsv`, `cache/manifest.json`, and every referenced shard must exist. Anything missing is treated as stale and rebuilt, so incomplete bundles self-heal.
2. **Tier 1 — Stat-only hit**: the walk compares `(size_bytes, mtime_secs, mtime_nanos)` and never opens an unchanged file. `CACHE HIT` costs 5–11 ms on a 123-file repository and a median 174 ms on a 12,471-file C HAL SDK.
3. **Tier 2 — Digest no-op**: the dirty file is re-parsed and its `structural_digest` is compared. When the digest **and** the line coordinates are unchanged, only that file's cache shard and `meta.json` are rewritten (< 25 ms budget).
4. **Tier 3 — Coordinate shift**: the digest is unchanged but line numbers or docstrings moved, and no C/C++ file, sharder threshold, or scope/layer change is involved. `resolve_and_link` and `analyze_graph` are skipped (`link=0ms graph=0ms`), the persisted graph metrics are re-attached 1:1, and only shard + emit run. Output is byte-identical to `convert --force`.
5. **Tier 4 — Structural**: full re-link, graph analysis, shard, and emit. On a 123-file repository this is a median 85 ms total with a 27 ms `emit` stage.

Concurrency: every write is temp-file + rename, and writers hold `cache/.lock` (create-new, 10 s stale window, heartbeat, owner-token deletion). Background callers (query auto-refresh, `hook post-edit`) wait at most **150 ms** and then skip the refresh and serve the on-disk bundle; explicit `convert`/`ensure` wait at most **5 s** and then fail with `BundleLocked`.

### Concept Search

`search --kind concept "<words>"` ranks rows of `index/symbols.tsv`, `index/types.tsv`, and `index/macros.tsv` with BM25 (`k1=1.2`, `b=0.75`) over camelCase / snake_case / acronym sub-tokens, weighting name x3, docstring x2, and signature/fields/value plus file stem x1, multiplied by `(matched_terms / |Q|)^2`, with pagerank/id tie-breaks. It is computed per query (no persisted index, no new dependencies) and takes ~16 ms on the `chipsrc` bundle. Multi-token `search` queries with zero literal/regex hits fall back to the same ranking automatically; `--source` / `--kind source` disable the fallback, and nonsense queries still return `[]`.

### C++ Coverage

`.h` headers are content-classified: a one-pass byte scan for C++ constructs (`class `, `template<`, `namespace `, `::`, `public:`/`private:`, `typename`, `nullptr`, `constexpr`, `virtual`, `operator`) skips comments, string/character literals, and raw strings, and selects the C++ grammar only when a marker appears in code. The detected language is stored on the scanned file and in `meta.json`, so `inspect` reports `cpp`. Class/struct templates drop their argument lists from names, types and symbols are namespace-qualified, out-of-line `ReturnT Class::method` definitions get `enclosing_type`/`qualified_name` and exact coordinates, and parameter lists longer than 80 characters collapse to `template<...>`.

---

## 3. Verification & Benchmarks (Delivered in 1.1.0)

### 3.1 Agent Efficiency Benchmark

Measured across 6 representative coding-agent tasks (point symbol lookup with body, struct layout inspection, direct callers, multi-hop call path, 5-hop blast radius, and module API skeleton reading):

| Metric | `chipsrc` | `ripgrep` + `Read` | Improvement |
| :--- | ---: | ---: | :--- |
| **Total LLM Turns (Tasks T1–T5)** | **5 turns** (1 turn per task) | **14–16 turns** | **9–11 fewer LLM round-trips (~25–45 s saved)** |
| **Cumulative Context Tokens (T1–T5)** | **2,852 tokens** | **19,334 tokens** | **6.8x token reduction** |
| **Multi-Hop Call Path (`path`)** | **229 tokens** (1 turn) | **3,418 tokens** (4 turns) | **14.9x token reduction** |
| **5-Hop Blast Radius (`impact`)** | **800 tokens** (1 turn) | **10,844 tokens** (5–6 turns) | **13.6x token reduction** |
| **Full Bundle Compression (`chipsrc` repo)** | **28,250 bundle tokens** | **158,265 raw source tokens** | **5.6x compression** |

### 3.2 End-to-End Black-Box Test Suites

- `cargo test --workspace`: Black-box integration and invariant E2E tests (`architecture_dag.rs`, `integration_tests.rs`, `invariants.rs`) verifying the 5-layer DAG, multi-language extraction, resolution tiers, graph analysis, sub-sharding, vendor filtering, MMIO normalization, query scoring, artifact integrity, line counting, duplicate-content shards, atomic writes/locks, concept scoring, and C++ extraction.
- `python qa/qa_blackbox.py`: Self-contained stdlib-only black-box CLI QA harness (`real`, `dup-content`, `concept`, `cpp`, `sfc`).
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` pass with zero warnings.

---

## 4. Delivered Features & Roadmap

### 4.1 Delivered in 1.1.0

| Item | Delivered behavior |
| :--- | :--- |
| **Sub-second freshness** | `mtime_nanos` on `FileStamp`/`ScannedFile`; `stamp_check` compares `(size, mtime_secs, mtime_nanos)`, so same-size edits within the same second are caught by `status --check` (exit 2), `convert`, `ensure`, hooks, and auto-refresh. |
| **Bundle artifact integrity** | `bundle_artifacts_complete` verifies `meta.json`, `INDEX.md`, all six `index/*.tsv` headers, every referenced `sections/*.md`, `cache/manifest.json`, and every shard; wired into `convert_repo`, `auto_refresh_bundles`, `workspace_status`, and both hooks. `--no-sync` queries on incomplete bundles exit non-zero naming the missing table. |
| **Unified line counting** | One `count_source_lines` (`\n` count plus 1 for a non-empty unterminated last line) used by full scan and incremental paths; incremental and `--force` artifacts are byte-identical. |
| **Duplicate-content aliasing** | Shards keyed by `blake3(rel_path + "\0" + content_hash)`; editing one of two byte-identical files preserves the sibling's section, symbols, and types. |
| **Cache schema 2.1.0** | Path-keyed shards and 256-unit packs (`cache/pack-<16hex>.json`) for repositories over 500 source files. |
| **Coordinate-shift tier** | Tier 3 skips `resolve_and_link`/`analyze_graph` via `cache/graph_state.json`; output byte-identical to `--force`. |
| **Atomic writes & lock** | `write_bytes_atomic` for every bundle write and the advisory `cache/.lock` (150 ms background / 5 s explicit budgets, heartbeat, owner-token release, stale reclamation). |
| **Call-noise pruning** | Two structural rules drop unresolved qualified calls to names defined nowhere and unresolved bare Rust `PascalCase` constructors; resolved edges unchanged. |
| **BM25 concept search** | `search --kind concept` plus automatic multi-token fallback; deterministic, ~16 ms, no persisted index, nonsense queries return `[]`. |
| **C++ coverage** | Content-based `.h` detection, class/struct templates, namespaces, nested classes, out-of-line methods, operators, ctors/dtors, `using` aliases, template-list collapsing. |
| **In-repo QA harness** | Self-contained black-box CLI QA harness (`qa/`) with checked-in fixtures and externalized oracles. |

### 4.2 Candidate Future Work

| Area | Candidate | Notes |
| :--- | :--- | :--- |
| Cold I/O | Further reduce artifact count (larger packs, fewer section shards, or a single cache database) | The `emit` stage is bounded by small-file creation on rotational disks; any change must preserve the path-keyed shard contract. |
| Query latency | Offset index for very large `macros.tsv` / `xref.tsv` tables | The macro prefilter already brings a 492k-row table query to ~140 ms (`--no-sync`); an offset index would help a 100 MB+ table further. |
| Coverage | More language grammars (Go, Java, C#) | Would require new dependencies; deliberately out of scope for 1.1.0. |
