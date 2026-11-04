# `chipsrc` — Agent Code Intelligence CLI & Auto-Sync Plugin for Firmware and Software Repositories

`chipsrc` is a fast, zero-LLM **Rust CLI, library, and Hybrid Claude Code plugin** — and the sister project to [`chipdoc`](https://github.com/umbramonarch/chipdoc) — that turns C, C++, Rust, Python, TypeScript, and JavaScript source repositories into a queryable **Hierarchical Agent Codebase Bundle** and **Code + Hardware Cross-Reference Graph** (`INDEX.md` + `index/*.tsv` + `sections/*.md` + `meta.json` + incremental AST `cache/` shards).

Instead of burning 25,000+ context tokens reading entire source files or running 6 sequential `Grep` + `Read` turns to trace call graphs, struct layouts, `#define` register macros, and ISR handlers, an AI coding agent uses `chipsrc` to resolve symbols, types, callers/callees, macros/MMIO addresses, and hardware cross-references in **a single deterministic CLI call (~120 tokens)** — while **automatic incremental AST synchronization** keeps the bundle up to date whenever source files change.

---

## Why `chipsrc`?

General-purpose repo packers (`repomix`, `code2prompt`) and naive `Grep` + `Read` loops waste massive context budgets on embedded and systems codebases for six concrete reasons:

1. **Full-File Reads Flood Context with Implementation Noise**: Reading a 2,500-line driver or HAL file just to check 3 function signatures and 1 struct layout wastes ~20,000 tokens. `chipsrc` shards the repository into **Module Signature Skeletons (`sections/*.md`)** containing docstrings, type definitions, constants, and function signatures with exact `file:start_line-end_line` coordinates, cutting structural browsing tokens by **80–92%**, while `-s` / `--show` extracts the exact implementation body on demand.
2. **Active Vendor-SDK Surface Filtering (`--vendor-mode active|all|none`)**: Embedded repositories often vendor 100,000+ lines of CMSIS, HAL, or SDK headers where only 2% is referenced by first-party firmware. With `--vendor-mode active` (the default), `chipsrc` indexes all vendor symbols in `index/*.tsv` for instant lookup, but filters `INDEX.md` and `sections/*.md` to surface only the **active vendor APIs, headers, and MMIO registers actually called or referenced by first-party code**.
3. **Zero-Build Multi-Language AST Extraction**: Embedded and full-stack projects mix C/C++ firmware (`CMSIS`, vendor HALs, RTOS), Rust services/crates, Python test harnesses, and TypeScript/JavaScript tooling — often requiring cross-compilers (`arm-none-eabi-gcc`) that aren't installed in agent environments. `chipsrc` uses native **Tree-sitter grammars (`C`, `C++`, `Rust`, `Python`, `TypeScript`, `TSX`, `JavaScript`, `JSX`)** + **Rayon** to parse thousands of files with zero compiler setup.
4. **1-Turn Static Call Graph & Architectural Diagnostics (`callers` / `callees`)**: `chipsrc` resolves `caller -> callee` edges across files with confidence tiers (`same_file`, `import_resolved`, `unique_global`, `ambiguous_name`, `external_or_macro`), ranks high-impact "god nodes" via deterministic PageRank, detects Tarjan SCC recursion cycles, and flags upward architectural layer violations (`drvs` calling `app`).
5. **Hardware Register & Macro Normalization (`macro` / `reg` / `mmio`)**: Firmware code accesses hardware via `#define` offsets (`0x41C00004`), CMSIS struct pointers (`GPIOA->MODER`), or peripheral bitmasks (`USART_CR1_UE`). `chipsrc` normalizes C/vendor hex (`0x400` $\leftrightarrow$ `400h`) and peripheral separators (`GPIOA_MODER` $\leftrightarrow$ `GPIOA->MODER` $\leftrightarrow$ `GPIOA.MODER`) so `chipsrc reg` and `chipdoc reg` speak the exact same language.
6. **Live Incremental AST Synchronization (`cache/` shards + Auto-Refresh + Native Hooks)**:
   - **Path-aware AST Cache Shards (`output/<repo>/cache/manifest.json` + `cache/<shard_key>.json`)**: Each extracted AST unit is stored in a shard named `blake3(rel_path + "\0" + content_hash)`, so byte-identical files at different paths never alias and never drop a sibling's section or symbols. Repositories with more than 500 source files pack 256 units into `cache/pack-<16hex>.json`; smaller repositories keep one shard per file. `cache/manifest.json` (schema `2.1.0`) maps every path to its BLAKE3 content hash, shard, and structural digest.
   - **Tiered sync**: a stat-only `stamp_check` over `(size_bytes, mtime_secs, mtime_nanos)` answers `[CACHE HIT]` in single-digit milliseconds on a small repository and in a median ~175 ms on a 12,471-file corpus without reading unchanged bytes (see [Performance](#performance-measured)). A file whose bytes changed is re-parsed in isolation; the bundle is then updated by the cheapest applicable tier (details [below](#incremental-synchronization-tiers)).
   - **Automatic Query Refresh (`auto_refresh_bundles`)**: Every query command (`sym`, `callers`, `callees`, `type`, `macro`/`reg`/`mmio`, `section`, `xref`, `path`, `impact`, `search`) automatically checks bundle freshness before executing and incrementally re-indexes any modified/added/deleted source files on the fly (disable with `--no-sync`).
   - **Claude Code Auto-Sync Hooks (`hooks/hooks.json`)**: `SessionStart` (`chipsrc hook session-start` with `scripts/session_start_hook.py` fallback) discovers and refreshes workspace bundles on startup, while `PostToolUse` (`chipsrc hook post-edit` on `Edit|Write|MultiEdit`) incrementally synchronizes affected bundles immediately after any code edit.

---

## Output Format: The Agent Codebase Bundle

Running `chipsrc convert /path/to/repo` (or `chipsrc ensure /path/to/repo -o output/`) produces:

```text
output/<repo_name>/
├── INDEX.md                        # Master entry point: architecture layers, god nodes, entrypoints/ISRs, active vendor surface, shard map
├── meta.json                       # Provenance, BLAKE3 Merkle fingerprint, language & scope breakdown, stage timings, sanity score, file_stamps
├── cache/
│   ├── manifest.json               # Schema 2.1.0 manifest: rel_path -> blake3_hash, structural_digest, shard
│   ├── graph_state.json            # Linked-graph annotations reused by the coordinate-shift tier
│   ├── <shard_key>.json            # Per-file ParsedFileUnit shards (repos with <= 500 files)
│   └── pack-<16hex>.json           # 256-unit packs (repos with > 500 files)
├── index/
│   ├── sections.tsv                # section_id | title | module_path | arch_layer | scope | files | symbols | types | macros | tokens | md_file
│   ├── symbols.tsv                 # symbol_id | name | qualified_name | kind | vis | file | lines | scope | layer | pagerank | in_deg | out_deg | signature | doc
│   ├── types.tsv                   # type_id | name | kind | vis | file | lines | scope | layer | fields_summary | doc | section_id
│   ├── calls.tsv                   # caller_id | caller_name | callee_name | callee_id | file | line | tier | section_id
│   ├── macros.tsv                  # name | kind | value_or_args | hex_addr | file | line | scope | layer | section_id | description
│   └── xref.tsv                    # symbol | category | relation | target | file | line | section_id | context
└── sections/                       # Module-sharded Markdown signature skeletons with YAML frontmatter
    ├── 01-app.md
    ├── 02-bsp.md
    ├── 03-drvs.md
    └── ...
```

`chipsrc` also adds `output/` to `.claudeignore` automatically (only when the bundle lives inside the indexed repository) so generating or updating bundles never invalidates Claude Code's prompt cache.

---

## Architecture: Strict Layered DAG (12 core modules)

The core crate keeps exactly twelve modules in a one-way `Layer 0 -> Layer 5` DAG, enforced by `crates/chipsrc-core/tests/architecture_dag.rs` (no upward imports, no new modules):

```text
Layer 5: crates/chipsrc-cli/src/main.rs         CLI binary + hook subcommands
   │
Layer 4: lib.rs                                 inspect_repo · convert_repo (tiered) · ensure_repo · auto_refresh_bundles · workspace_status
   │
Layer 3: emitter.rs (bundle writer, atomic writes, BundleLock) │ query.rs (bundle discovery, auto-refresh, 1-turn queries, BM25 search)
   │
Layer 2: resolver.rs (5-tier calls, xref graph, vendor surface) │ graph.rs (PageRank/HITS, SCC, layer edges)
         sharder.rs (module skeletons, sub-sharding)  │ sanity.rs (compression/parse/resolution scoring)
   │
Layer 1: scanner.rs (ignore walk, scope/layer, BLAKE3, stamp_check, line counting, artifact integrity)
         parser.rs (Tree-sitter multi-language, SFC projection, C++ templates/namespaces/out-of-line)
         mmio.rs (hex/peripheral normalization, linker sections)
   │
Layer 0: model.rs (domain types, CACHE_SCHEMA_VERSION) │ error.rs (typed ChipsrcError)
```

---

## Incremental Synchronization Tiers

`convert`, `ensure`, query auto-refresh, and both hooks all run the same decision ladder. Every tier leaves a complete bundle; any doubt falls back to the tier below it.

| Tier | Condition | Work | Measured / budget |
| --- | --- | --- | --- |
| 0 Integrity gate | `meta.json`, `INDEX.md`, `cache/manifest.json`, all six `index/*.tsv`, or a referenced `sections/*.md` / cache shard is missing or header-less | treat as stale and rebuild (self-heal) | — |
| 1 Stat-only hit | every file matches `(size_bytes, mtime_secs, mtime_nanos)`, no adds/deletes, blueprint hash equal | `CACHE HIT`; rewrite `meta.json` only if touched mtimes changed | 5–11 ms on a 123-file repo; **median 174 ms on 12,471 files** (budget < 300 ms) |
| 2 Digest no-op | dirty file re-parsed; `structural_digest` equal **and** coordinates/line counts unchanged | rewrite the affected cache shard + `meta.json` | < 25 ms budget |
| 3 Coordinate shift | digest equal but line numbers/docstrings moved; scope/layer unchanged; no C/C++ dirty file; no sharder threshold crossed (1,400-line file, 3,000-line / 8-file group) | skip `resolve_and_link` and `analyze_graph` (`link=0ms graph=0ms`), re-shard and re-emit | 131–151 ms total on `smart_locker` (link+graph skipped) |
| 4 Structural | anything else | full re-link, graph analysis, shard, and emit | **median total 85 ms / emit 27 ms** on `smart_locker` (123 files) |

Tier 1 never opens an unchanged file. Tier 2 only short-circuits when both the structural digest **and** the line coordinates are unchanged — an inserted comment line moves coordinates, so it takes Tier 3. Tier 3 uses `cache/graph_state.json` to re-attach PageRank/HITS/SCC annotations 1:1 and produces output byte-identical to `convert --force`; if the state is missing, truncated, or mismatched it falls back to Tier 4.

---

## Concurrency, Atomic Writes & `cache/.lock`

Bundle writers never leave a torn artifact:

- **Atomic writes**: every bundle file is written to a sibling `.<name>.<pid>.<seq>.tmp`, then `fs::rename`d over the target (5 attempts with 5/10/20/40 ms backoff on Windows sharing violations). Identical content is skipped without touching the file. Stale `*.tmp` files older than 60 s are pruned on the next write.
- **Advisory exclusive lock**: writers create `<out>/cache/.lock` with `create_new` (contents `pid:unix_ms[:nonce]`), refresh its mtime from a heartbeat thread while held, and treat a lock as stale only when its mtime is older than 10 s. `Drop` deletes the file only when its on-disk owner token still matches. On Windows the lock handle is held without delete sharing so a stale reclaimer can never unlink a live owner.
- **Background wait budget (150 ms)**: query auto-refresh and `hook post-edit` wait at most **150 ms** for the lock. On timeout they skip the refresh and answer from the consistent on-disk bundle (hooks still exit 0), so an in-flight convert never blocks an agent's query.
- **Explicit wait budget (5 s)**: `convert` and `ensure` wait up to **5 s** for the lock and then fail with `ChipsrcError::BundleLocked` naming `cache/.lock` and the holder, leaving the existing bundle untouched.

---

## Quick Start

### Prerequisites

- **Rust 1.85+** (`cargo` and `rustc` with a C compiler for Tree-sitter grammar compilation)

### Build

```powershell
cargo build --release
```

### 1-Turn Agent CLI Usage

```powershell
# 1. Inspect repository languages, first-party vs vendor SDK scope, and architectural layers
chipsrc inspect .
chipsrc inspect /path/to/firmware --vendor-mode active --json

# 2. Convert or ensure a repository is indexed
#    (stat-only cache hits in single-digit ms on small repos; 1-file structural sync under 100 ms on a 123-file repo)
chipsrc convert . -o output/chipsrc --vendor-mode active
chipsrc ensure . -o output/

# 3. Check workspace bundle freshness (`FRESH` vs `STALE (N files changed)`) and optionally sync
chipsrc status
chipsrc status --sync
chipsrc status --check --json          # exit 2 when any bundle is stale

# 4. Look up function/method/ISR signatures, PageRank, and inline source body (`-s / --show`)
chipsrc sym lock_actuator
chipsrc sym extract_symbols --kind fn --show

# 5. Traverse static call graphs in 1 turn (`-s / --show` for call-site source context)
chipsrc callers parse_register
chipsrc callees convert_repo --show

# 6. Look up struct/enum/union/trait/class definitions and field layouts (`type ivector` on a C++ corpus works too)
chipsrc type ConvertConfig
chipsrc type GPIO_TypeDef --show

# 7. Look up #define macros, constants, bitmasks, and MMIO hex register addresses (`macro`, `reg`, `mmio`)
chipsrc macro USART_CR1_UE
chipsrc reg 0x41C00004 --show
chipsrc mmio VENDOR_ADC1

# 8. Traverse the Unified Code + Hardware Cross-Reference Graph (`xref` / `explain`)
chipsrc xref GPIOA
chipsrc explain ConvertConfig

# 9. List architectural module shards or display a shard's Markdown signature skeleton (`-s / --show`)
chipsrc section
chipsrc section "drvs" --show

# 10. Parallel SIMD + Regex search across all indexed bundles
chipsrc search "BLAKE3" --compact
chipsrc search "GPIO" --kind macros -i

# 11. Deterministic BM25 concept search (`--kind concept`; also the automatic multi-token fallback)
chipsrc search "vendor mode" --kind concept --json --no-sync
chipsrc search "strongly connected cycles tarjan" --json   # zero literal hits -> concept ranking
```

### `--no-sync` and query latency

Every query command runs the freshness gate (Tier 0/1) before answering unless `--no-sync` is passed. On a warm bundle that gate costs a few milliseconds on a small repository and roughly 175–250 ms on `STM32CubeF4` (12,471 files). `--no-sync` bypasses discovery refresh entirely and answers from the on-disk bundle: on the same corpus a `type GPIO_TypeDef` query drops to ~45 ms. Use `--no-sync` when you just ran `ensure`/`convert` and want pure query latency (the QA suites measure it that way); on an incomplete bundle `--no-sync` exits non-zero naming the missing `index/*.tsv` instead of returning `[]`.

---

## Concept Search (`search --kind concept`)

```powershell
chipsrc search "vendor mode" --kind concept --json --no-sync
chipsrc search "strongly connected cycles tarjan" --json
```

Concept search scores the rows of `index/symbols.tsv`, `index/types.tsv`, and `index/macros.tsv` per query (no persisted index, no new dependencies). Identifiers are split on `snake_case`, `camelCase`, and acronym boundaries (`VendorMode` -> `vendor` + `mode`), lowercased, filtered for 1-character tokens and common stopwords, and lightly stemmed (`s`/`es`/`ed`/`ing`). Fields are weighted name x3, docstring x2, and signature/fields/value plus file stem x1; BM25 uses `k1=1.2`, `b=0.75`, and the score is multiplied by `(matched_terms / |Q|)^2` so rows matching more query words rank first, tie-breaking on pagerank and then row id.

**Automatic multi-token fallback:** any `search` query with two or more tokens that produces zero literal/regex hits — in the semantic TSV columns and in the raw-source pass — is retried automatically as a BM25 concept query. Pass `--source` (or `--kind source`) to search raw text only and disable the fallback. Nonsense queries, and single-token queries with zero hits, still return `[]`.

---

## Language Support & C++ Header Detection

| Language | Extensions | Notes |
| --- | --- | --- |
| C | `.c`, `.h` | `.h` files are content-classified (see below) |
| C++ | `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh`, `.hxx`, `.h` | class/struct templates, namespaces, nested classes, out-of-line `Class::method`, `operator` overloads, ctors/dtors, `using` aliases |
| Rust | `.rs` | functions, impl methods, traits, macros, `#[cfg(test)]` scoping |
| Python | `.py` | functions, async defs, classes, module imports |
| TypeScript / TSX | `.ts`, `.tsx` | functions, classes, interfaces, type aliases |
| JavaScript / JSX | `.js`, `.jsx`, `.mjs`, `.cjs` | functions, classes, components |
| Single-file components | `.astro`, `.vue`, `.svelte` | `<script>` blocks projected byte-for-byte; component symbols and PascalCase template usage |

`.h` headers are **not** assumed to be C. A one-pass byte heuristic looks for C++ constructs (`class `, `template<`, `namespace `, `::`, `public:`/`private:`, `typename`, `nullptr`, `constexpr`, `virtual`, `operator`) while skipping `//` and `/* ... */` comments, string/character literals, and raw strings; a match selects the C++ grammar and records `cpp` in `inspect --json` and `meta.json`. Plain C headers — including ones whose only C++ keywords appear in comments — stay `c`. On `etl` this lifts `cpp.first_party_files` to 370 of 1,221 files, while `STM32CubeF4` stays C-dominated (12,458 C of 12,471; 11 headers reclassified).

Template parameter lists longer than 80 characters collapse to `template<...>` in signatures, and out-of-line definitions carry `enclosing_type`/`qualified_name`, so `sym`, `type`, `callers`, and `callees` resolve across namespace-qualified template classes.

---

## Performance (measured)

All figures are medians measured on one Windows machine (12 logical cores, 15.9 GB RAM, NTFS rotational `D:` volume) with the release binary, using `convert|ensure --timings` and `meta.json` stage fields. Corpora: `smart_locker` (123 files / 41,247 lines), `STM32CubeF4` (12,471 files / 4,552,776 lines, `--vendor-mode all`), `etl` (1,221 files / 588,905 lines), `chipsrc` (self).

| Scenario | Corpus / scale | Measured (median) | Budget |
| --- | --- | --- | --- |
| 1-file structural edit, total sync | `smart_locker`, 123 files | **85 ms** | < 100 ms |
| 1-file structural edit, `emit` stage | `smart_locker`, 123 files | **27 ms** | < 50 ms |
| Coordinate-shift sync (link + graph skipped) | `smart_locker`, 123 files | 132–151 ms total, `link=0ms graph=0ms` | link/graph skipped |
| Warm `CACHE HIT` freshness check | `smart_locker`, 123 files | 5–11 ms | — |
| Warm `CACHE HIT` freshness check | `chipsrc`, 52 files | 5–7 ms | — |
| Warm `CACHE HIT` freshness check | `STM32CubeF4`, 12,471 files | **174 ms** (`scan`/`total`) | < 300 ms |
| Cold `convert --force --vendor-mode all` | `STM32CubeF4`, 12,471 files, 4.55M lines | **24.3 s total** (`link` 3.1 s, `emit` 8.1 s), peak working set 1.47 GiB | < 40 s, link ≤ 14.35 s, emit ≤ 16.45 s, RSS < 1.5 GiB |
| Auto-sync query on a warm bundle | `STM32CubeF4` | `type` 174 ms · `sym` 208 ms · `reg` 258 ms | < 500 ms |
| `--no-sync` query | `STM32CubeF4` | ~45 ms (`type GPIO_TypeDef`) | — |
| Cold link | `etl`, 1,221 files, 253k call edges | 0.6–1.4 s | ≤ 17.5 s |
| Concept-search compute | `chipsrc` bundle (~2.4k symbols) | ~16 ms (query wall minus `--version` spawn) | < 30 ms |

Cold `STM32CubeF4` runs ranged 17.3–25.7 s across sessions depending on write-back pressure on the test volume; the per-stage budgets above (link, emit, RSS) are the stable gates. Reproducible measurements live in the QA harness oracles (`qa/oracles/perf.json`) and its `scale`, `perf`, and `concurrency` suites.

---

## QA Harness (`qa/`)

The repository ships a stdlib-only Python black-box harness that drives the release binary and the hooks exactly as an agent or CI job would. Full documentation, flags, and suite details live in [`qa/README.md`](qa/README.md).

```powershell
cargo build --release
python qa/qa_blackbox.py --suite core --bin target/release/chipsrc.exe --repos-root D:/projects --corpus-root D:/projects/chipsrc-mission-corpus --out D:/projects/chipsrc-mission-corpus/qa-results
```

- **Flags**: `--bin`, `--repos-root`, `--corpus-root`, `--out` (default `qa/results/`, gitignored), `--suite` (repeatable), `--only`, `--skip`, `--timeout`, `--fixtures-mode build|require`, `--keep-sandboxes`.
- **Suites**: `core` (alias for `real`, `sync`, `boundary`, `focused`, `hooks`, `dup-content`), `perf`, `concurrency`, `scale`, `concept`, `cpp`, `corpus`, `sfc`.
- **Safety rules**: real repositories under `--repos-root` / `--corpus-root` are strictly read-only; every mutation test copies sources into `<out>/sandboxes/<suite>-<timestamp>/` first; fixtures live under `qa/fixtures/`; golden values live in `qa/oracles/*.json`.
- **Skip-if-missing**: a missing repository, corpus, or binary-adjacent prerequisite produces `skipped` records naming the path — never a traceback. The harness exits `0` when no assertion failed and `1` otherwise.

---

## Development & Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python qa/qa_blackbox.py --suite core --bin target/release/chipsrc.exe --repos-root D:/projects --corpus-root D:/projects/chipsrc-mission-corpus --out D:/projects/chipsrc-mission-corpus/qa-results
```

## License

MIT License — see [LICENSE](LICENSE).
