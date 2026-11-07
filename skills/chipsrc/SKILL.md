---
name: chipsrc
description: >-
  Index, auto-synchronize, and query C, C++, Rust, Python, TypeScript, and JavaScript source
  repositories using the `chipsrc` CLI. Use this skill whenever exploring a codebase, looking
  up function/method/ISR signatures, struct/enum/trait definitions, static callers/callees,
  `#define` register macros, MMIO hex addresses, hardware peripheral usage, or a natural-language
  concept, instead of reading entire source files into context or running blind multi-turn greps.
---

# `chipsrc` — Agent Code Intelligence CLI

Avoid reading multi-thousand-line source files or vendor SDK headers just to inspect function
signatures, struct layouts, or call graphs. Use `chipsrc` to index repositories locally at zero
LLM token cost into a **Hierarchical Agent Codebase Bundle** (`INDEX.md` + `index/*.tsv` +
`sections/*.md` signature skeletons + incremental `cache/` shards) and retrieve exact structural
facts in a **single CLI call**.

## 1. Check Workspace, Inspect, & Ensure Bundles Exist

Before running multi-turn `Grep` + `Read` loops, check which bundles exist or ensure the target
repository is indexed. `chipsrc` caches per-file AST extractions in `output/<repo>/cache/`
(path-keyed shards; repositories over 500 files use 256-unit packs). A stat-only stamp check
answers `CACHE HIT` in single-digit milliseconds on a small repository and about 175 ms on a
12,000-file corpus; a 1-file structural edit syncs in under 100 ms on a medium repository;
coordinate-only edits skip call-graph relinking entirely:

```bash
chipsrc status
chipsrc status --sync
chipsrc status --check

chipsrc inspect .

chipsrc ensure . -o output/ --vendor-mode active
chipsrc convert . -o output/my_repo --vendor-mode active
```

### Turn-1 Agent-Once Onboarding Blueprint (`.chipsrc.json`)
When `chipsrc inspect .` prints an `=== Onboarding Digest (.chipsrc.json missing) ===` with unclassified
directories, workspace roots, or custom C qualifier macros, write a root `.chipsrc.json` **once** before
running `chipsrc ensure . -o output/`:

```json
{
  "scopes": { "external/vendor_sdk": "vendor_sdk", "fw/app": "first_party" },
  "layers": { "fw/app": "app", "fw/board": "bsp", "fw/drivers": "drvs" },
  "shards": { "fw/drivers/can": "can-stack" },
  "ignore_dirs": ["legacy_archive"],
  "c_qualifiers": ["FAST_RAM_CODE", "BOARD_ATTR"],
  "entrypoints": ["custom_boot_entry"],
  "isr_patterns": ["_CustomISR"],
  "mmio_ranges": [{ "start": "0xB0000000", "end": "0xBFFFFFFF", "name": "Custom FPGA MMIO" }]
}
```

### Vendor SDK Active Surface Filtering (`--vendor-mode`)
- `--vendor-mode active` (default): Indexes all vendor SDK symbols in `index/*.tsv` for lookup,
  but keeps `INDEX.md` and `sections/*.md` focused on first-party modules plus only the active
  vendor APIs, headers, and MMIO registers actually called or referenced by first-party code.
- `--vendor-mode all`: Emits full shards for all vendor SDK directories.
- `--vendor-mode none`: Skips vendor SDK directories completely.

## 2. Use 1-Turn Domain Queries ("Build the Lever")

Every `chipsrc` query command automatically runs `auto_refresh_bundles` before querying (unless
`--no-sync` is passed), ensuring any edited, added, or deleted source files are incrementally
re-indexed on the fly. If another process holds `cache/.lock`, the refresh waits at most 150 ms
and then answers from the consistent on-disk bundle instead of blocking. Pass `--no-sync` for
pure query latency; on an incomplete bundle it exits non-zero naming the missing `index/*.tsv`
rather than returning `[]`:

```bash
# 1. Function / Method / ISR Signature & Inline Source Body Lookup (-s / --show)
chipsrc sym motor_set_duty
chipsrc sym motor_set_duty --show
chipsrc sym Handler --kind isr

# 2. Static Call-Graph Traversal (who calls X, what does X call, shortest path, and blast radius)
chipsrc callers parse_register
chipsrc callers parse_register --show
chipsrc callees ensure_repo --show
chipsrc path main motor_set_duty
chipsrc impact motor_set_duty

# 3. Struct / Enum / Union / Trait / Class Template Layout Lookup (-s / --show)
chipsrc type ConvertConfig
chipsrc type GPIO_TypeDef --show

# 4. Macro / Constant / MMIO Register Hex Offset Lookup (aliases: `reg`, `mmio`)
chipsrc macro USART_CR1_UE
chipsrc reg 0x41C00004 --show
chipsrc mmio VENDOR_ADC1

# 5. Unified Code + Hardware Cross-Reference Graph Traversal (alias: `explain`)
chipsrc xref GPIOA
chipsrc explain ConvertConfig

# 6. Architectural Module Signature Skeleton Shards (-s / --show)
chipsrc section
chipsrc section "drvs" --show

# 7. Parallel SIMD + Regex Search Across All Indexed Bundles
chipsrc search "BLAKE3" --compact
chipsrc search "MODER" --kind macros -i

# 8. Deterministic BM25 concept search when you do not know the identifier
chipsrc search "vendor mode" --kind concept --json --no-sync
chipsrc search "debounce button interrupt" --json
```
