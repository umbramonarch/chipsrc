# `chipsrc` — Agent Code Intelligence CLI & Auto-Sync Plugin for Firmware and Software Repositories

`chipsrc` is a fast, zero-LLM **Rust CLI, library, and Hybrid Claude Code plugin** — and the sister project to [`chipdoc`](https://github.com/umbramonarch/chipdoc) — that turns C, C++, Rust, Python, TypeScript, and JavaScript source repositories into a queryable **Hierarchical Agent Codebase Bundle** and **Code + Hardware Cross-Reference Graph** (`INDEX.md` + `index/*.tsv` + `sections/*.md` + `meta.json` + per-file incremental `cache/*.json` shards).

Instead of burning 25,000+ context tokens reading entire source files or running 6 sequential `Grep` + `Read` turns to trace call graphs, struct layouts, `#define` register macros, and ISR handlers, an AI coding agent uses `chipsrc` to resolve symbols, types, callers/callees, macros/MMIO addresses, and hardware cross-references in **a single deterministic CLI call (~120 tokens)** — while **automatic incremental AST synchronization** keeps the bundle 100% up to date whenever source files change.

---

## Why `chipsrc`?

General-purpose repo packers (`repomix`, `code2prompt`) and naive `Grep` + `Read` loops waste massive context budgets on embedded and systems codebases for six concrete reasons:

1. **Full-File Reads Flood Context with Implementation Noise**: Reading a 2,500-line driver or HAL file just to check 3 function signatures and 1 struct layout wastes ~20,000 tokens. `chipsrc` shards the repository into **Module Signature Skeletons (`sections/*.md`)** containing docstrings, type definitions, constants, and function signatures with exact `file:start_line-end_line` coordinates, cutting structural browsing tokens by **80–92%**, while `-s` / `--show` extracts the exact implementation body on demand.
2. **Active Vendor-SDK Surface Filtering (`--vendor-mode active|all|none`)**: Embedded repositories often vendor 100,000+ lines of CMSIS, HAL, or SDK headers where only 2% is referenced by first-party firmware. With `--vendor-mode active` (the default), `chipsrc` indexes all vendor symbols in `index/*.tsv` for instant lookup, but filters `INDEX.md` and `sections/*.md` to surface only the **active vendor APIs, headers, and MMIO registers actually called or referenced by first-party code**.
3. **Zero-Build Multi-Language AST Extraction**: Embedded and full-stack projects mix C/C++ firmware (`CMSIS`, vendor HALs, RTOS), Rust services/crates, Python test harnesses, and TypeScript/JavaScript tooling — often requiring cross-compilers (`arm-none-eabi-gcc`) that aren't installed in agent environments. `chipsrc` uses native **Tree-sitter grammars (`C`, `C++`, `Rust`, `Python`, `TypeScript`, `TSX`, `JavaScript`, `JSX`)** + **Rayon** to parse thousands of files in milliseconds with zero compiler setup.
4. **1-Turn Static Call Graph & Architectural Diagnostics (`callers` / `callees`)**: `chipsrc` resolves `caller -> callee` edges across files with confidence tiers (`same_file`, `import_resolved`, `unique_global`, `ambiguous_name`, `external_or_macro`), ranks high-impact "god nodes" via deterministic PageRank, detects Tarjan SCC recursion cycles, and flags upward architectural layer violations (`drvs` calling `app`).
5. **Hardware Register & Macro Normalization (`macro` / `reg` / `mmio`)**: Firmware code accesses hardware via `#define` offsets (`0x41C00004`), CMSIS struct pointers (`GPIOA->MODER`), or peripheral bitmasks (`USART_CR1_UE`). `chipsrc` normalizes C/vendor hex (`0x400` $\leftrightarrow$ `400h`) and peripheral separators (`GPIOA_MODER` $\leftrightarrow$ `GPIOA->MODER` $\leftrightarrow$ `GPIOA.MODER`) so `chipsrc reg` and `chipdoc reg` speak the exact same language.
6. **Live Incremental AST Synchronization (`cache/` Shards + Auto-Refresh + Native Hooks)**:
   - **Per-File AST Cache Shards (`output/<repo>/cache/manifest.json` + `cache/<blake3>.json`)**: Stores extracted AST units as content-addressed per-file shards alongside a structural digest. Stat-only `stamp_check` returns `[CACHE HIT]` in **<2 ms** without reading unchanged files; comment-only edits short-circuit via structural digest in **<25 ms**; structural edits re-parse and write **only the modified shard (`[INCREMENTAL SYNC]`) in <50 ms**.
   - **Automatic Query Refresh (`auto_refresh_bundles`)**: Every query command (`sym`, `callers`, `callees`, `type`, `macro`/`reg`/`mmio`, `section`, `xref`, `path`, `impact`, `search`) automatically checks bundle freshness before executing and incrementally re-indexes any modified/added/deleted source files on the fly (disable with `--no-sync`).
   - **Claude Code Auto-Sync Hooks (`hooks/hooks.json`)**: `SessionStart` (`chipsrc hook session-start` with `scripts/session_start_hook.py` fallback) discovers and refreshes workspace bundles on startup, while `PostToolUse` (`chipsrc hook post-edit` on `Edit|Write|MultiEdit`) incrementally synchronizes affected bundles immediately after any code edit.

---

## Output Format: The Agent Codebase Bundle

Running `chipsrc convert /path/to/repo` (or `chipsrc ensure /path/to/repo -o output/`) produces:

```text
output/<repo_name>/
├── INDEX.md                        # Master entry point: architecture layers, god nodes, entrypoints/ISRs, active vendor surface, shard map
├── meta.json                       # Provenance, BLAKE3 Merkle fingerprint, language & scope breakdown, stage timings, sanity score
├── cache/
│   ├── manifest.json               # Schema 2.0.0 manifest mapping relative paths to BLAKE3 hashes & structural digests
│   └── <blake3>.json               # Content-addressed per-file ParsedFileUnit shards for <25ms incremental rebuilds
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

`chipsrc` also adds `output/` to `.claudeignore` automatically so generating or updating bundles never invalidates Claude Code's prompt cache.

---

## Architecture: Strict Layered DAG

```text
Layer 5: crates/chipsrc-cli (CLI binary) + .claude-plugin / hooks / scripts / skills/chipsrc
   │
Layer 4: emitter.rs (Bundle writer) │ sanity.rs (Scoring) │ query.rs (Auto-Refresh + 1-Turn Query Engine)
   │
Layer 3: xref.rs (PageRank, SCC, Layer Edges, Active Vendor Surface) │ sharding.rs (Module Skeleton Sharder)
   │
Layer 2: symbols.rs │ types.rs │ calls.rs │ macros.rs (AST Structural Extractors)
   │
Layer 1: scanner.rs (Ignore + Scope/Layer + BLAKE3) │ parser.rs (Tree-sitter Multi-Lang + cache.json)
   │
Layer 0: model.rs & error.rs (Canonical Domain Types & ChipsrcError)
```

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

# 2. Convert or ensure a repository is indexed (<2ms on BLAKE3 cache hit, <50ms incremental sync)
chipsrc convert . -o output/chipsrc --vendor-mode active
chipsrc ensure . -o output/

# 3. Check workspace bundle freshness (`FRESH` vs `STALE (N files changed)`) and optionally sync
chipsrc status
chipsrc status --sync

# 4. Look up function/method/ISR signatures, PageRank, and inline source body (`-s / --show`)
chipsrc sym lock_actuator
chipsrc sym extract_symbols --kind fn --show

# 5. Traverse static call graphs in 1 turn (`-s / --show` for call-site source context)
chipsrc callers parse_register
chipsrc callees convert_repo --show

# 6. Look up struct/enum/union/trait/interface definitions and field layouts
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

Concept search scores the rows of `index/symbols.tsv`, `index/types.tsv`, and `index/macros.tsv`
per query (no persisted index, no new dependencies). Identifiers are split on `snake_case`,
`camelCase`, and acronym boundaries (`VendorMode` -> `vendor` + `mode`), lowercased, filtered for
1-character tokens and common stopwords, and lightly stemmed (`s`/`es`/`ed`/`ing`). Fields are
weighted name x3, docstring x2, and signature/fields/value plus file stem x1; BM25 uses `k1=1.2`,
`b=0.75`, and the score is multiplied by `(matched_terms / |Q|)^2` so rows matching more query
words rank first, tie-breaking on pagerank and then row id. A multi-token `search` with zero
literal/regex hits falls back to the same ranking automatically; pass `--source` (or
`--kind source`) to search raw text only and disable the fallback. Queries whose tokens match no
row still return `[]`.

---

## Development & Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

MIT License — see [LICENSE](LICENSE).
