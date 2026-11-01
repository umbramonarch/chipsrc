# `chipsrc` Black-Box QA Harness (`qa/`)

Reproducible, parameterized black-box regression harness for the `chipsrc` CLI and Claude Code hooks.

The harness runs entirely on the **Python 3.13 standard library** (`argparse`, `csv`, `difflib`, `hashlib`, `json`, `os`, `pathlib`, `shutil`, `statistics`, `subprocess`, `sys`, `time`) with **zero third-party pip packages**. It works under `python -I` (isolated mode) and from any working directory.

---

## Quick Start

Build the release binary and run the canonical `core` regression suite:

```powershell
cargo build --release
python qa/qa_blackbox.py --suite core --bin target/release/chipsrc.exe --repos-root D:/projects --corpus-root D:/projects/chipsrc-mission-corpus --out D:/projects/chipsrc-mission-corpus/qa-results
```

Run multiple specific suites in one invocation (`--suite` is repeatable):

```powershell
python qa/qa_blackbox.py --suite real --suite hooks --bin target/release/chipsrc.exe --repos-root D:/projects --corpus-root D:/projects/chipsrc-mission-corpus --out D:/projects/chipsrc-mission-corpus/qa-results
```

Run in Python isolated mode (`python -I`):

```powershell
python -I qa/qa_blackbox.py --suite core --bin target/release/chipsrc.exe --repos-root D:/projects --corpus-root D:/projects/chipsrc-mission-corpus --out D:/projects/chipsrc-mission-corpus/qa-results
```

---

## Command-Line Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--bin <PATH>` | `target/release/chipsrc.exe` | Path to the `chipsrc` executable under test. |
| `--repos-root <DIR>` | `<repo-parent>` | Root directory containing read-only repositories (`chipsrc`, `smart_locker`, `volt_website`, `beautiful-embedded-c`, `chipdoc`, `stock_screener`, `my-sunshine`, `work`). |
| `--corpus-root <DIR>` | `<repo-parent>/chipsrc-mission-corpus` | Root directory containing large mission corpora (`STM32CubeF4`, `etl`) and external sandboxes. |
| `--out <DIR>` | `qa/results/` | Output directory for `<suite>-results.json`, `summary.json`, `bundles/`, `fixture-bundles/`, and `sandboxes/`. Default `qa/results/` is gitignored; reruns into the same `--out` directory are idempotent. |
| `--suite <NAME>` | `core` | Suite to execute (repeatable, e.g. `--suite real --suite hooks`). `core` expands to `real`, `sync`, `boundary`, `focused`, `hooks`, and `dup-content`. |
| `--only <PATTERN>` | *(none)* | Only record/run assertions whose `label` matches `<PATTERN>` (case-insensitive substring, repeatable). |
| `--skip <PATTERN>` | *(none)* | Skip assertions whose `label` matches `<PATTERN>` (case-insensitive substring, repeatable). |
| `--timeout <SECONDS>` | `120.0` | Per-command subprocess timeout in seconds. Timeouts are recorded as failed records without uncaught Python tracebacks. |
| `--fixtures-mode <MODE>` | `build` | `build` (default) builds or refreshes missing/stale baseline bundles under `<out>/bundles/` when `meta.json` fingerprint or cache schema (`2.1.0`) differs from `inspect`. `require` fails if a required fixture bundle is missing or stale. |
| `-h`, `--help` | — | Display CLI usage, flags, and available suites. |

---

## Available Suites

- **`core`**: Alias expanding to `real`, `sync`, `boundary`, `focused`, `hooks`, and `dup-content`.
- **`real`**: Real-repository inspection, `inspect` vs `meta.json` count agreement, warm cache hits, `--force` determinism, symbol coordinate validity, and 1-turn queries across `chipsrc` (Rust), `smart_locker` (Python), `volt_website` (TypeScript/Astro), and `beautiful-embedded-c` (C/MMIO) (66 assertions).
- **`sync`**: Incremental synchronization across symbol renames, comment-only coordinate shifts, docstring edits, file additions/deletions/renames, equal-size same-second edits, `--single-file` updates, `status --sync --check`, malformed syntax, and invalid UTF-8 inputs (24 assertions).
- **`boundary`**: Cache and option boundaries (`--single-file` warm activation, missing `index/symbols.tsv` self-heal via `ensure` and auto-sync queries, Python/TypeScript/C same-second sub-second mtime detection, `--vendor-mode active|none|all`, hex notation equivalence, and paths with spaces) (26 assertions).
- **`focused`**: Unified source line counting (`incremental` vs `--force` agreement) and 1-file incremental edit timing observations (2 assertions + 1 observational record).
- **`hooks`**: Native `chipsrc hook session-start` and `chipsrc hook post-edit` refresh verification, including equal-size same-second edits and fail-open malformed payload handling (5 assertions).
- **`dup-content`**: Self-contained fixture suite (`qa/fixtures/dup-content/{alpha,beta}/mod.py` + `qa/oracles/dup-content.json`) verifying per-file cache shard disambiguation for byte-identical files at different paths across cold builds, single-copy incremental edits, `--force` count/hash equivalence, and incremental additions/deletions of duplicate copies (7 assertions).
- **`perf`**: Incremental `emit` (`< 50 ms`) and total (`< 100 ms`) latency budgets on `smart_locker` plus Tier 3 coordinate-shift (`link=0ms graph=0ms`) and 1,400-line threshold fallback checks.
- **`concurrency`**: Atomic bundle writes (`write_bytes_atomic`), absence of `*.tmp` or `cache/.lock` leftovers, live lock contention (`150 ms` background skip vs `5 s` explicit wait), stale lock reclamation, and 5+5 concurrent process stress tests.
- **`scale`**: Large-corpus (`STM32CubeF4` 12,471 files and `etl` 1,221 files) warm (`< 300 ms`), auto-sync query (`< 500 ms`), cold convert (`< 40 s`), peak RSS (`< 1.5 GB`), and determinism verification.
- **`concept`**: Deterministic BM25 `--kind concept` ranking, camelCase/snake_case sub-tokenization, automatic multi-token fallback, `< 30 ms` query latency, and nonsense-query empty results.
- **`cpp`**: Content-based `.h` C++ header detection, class templates, namespaces, nested classes, out-of-line `Class::method` definitions, and template signature collapsing (`qa/fixtures/cpp/` + `etl`).
- **`corpus`**: Full 10-repository (`chipsrc`, `chipdoc`, `smart_locker`, `volt_website`, `beautiful-embedded-c`, `stock_screener`, `my-sunshine`, `work`, `STM32CubeF4`, `etl`) count agreement, warm cache hits, `--force` determinism, coordinate validity, and sanity bounds.
- **`sfc`**: Standalone `.jsx`, `.vue`, and `.svelte` single-file component extraction and incremental coordinate shift verification (`qa/fixtures/sfc/`).

---

## Skip-if-Missing Preflight & Fixture-Only Execution

- When `--repos-root` or `--corpus-root` (or a specific repository required by a suite) is absent on disk, the preflight check prints a `SKIP [<suite>]` reason naming the missing path and writes `skipped` records (`"status": "skipped"`, `"skipped": true`, `"passed": null`, `"detail": "<reason>"`) to `<out>/<suite>-results.json`.
- Suites that only depend on `--repos-root` (such as `real`, `sync`, `boundary`, `focused`, `hooks`) are unaffected by a missing `--corpus-root`.
- Fixture-only suites (such as `dup-content` and `sfc`) use self-contained sources under `qa/fixtures/` and run with zero skips even when both `--repos-root` and `--corpus-root` point to non-existent directories.
- The harness exits `0` whenever `failed == 0` (including when missing external repositories produce `skipped` records) and exits `1` if any record has `status == "failed"`.

---

## Results Schema (`<suite>-results.json` & `summary.json`)

Each executed suite writes `<out>/<suite>-results.json` containing a JSON array of records. Every record includes:

```json
{
  "label": "Python definition exact coordinates",
  "kind": "assertion",
  "status": "passed",
  "passed": true,
  "skipped": false,
  "detail": null,
  "args": ["sym", "-b", "...", "pm_match_key", "--json"],
  "exit": 0,
  "wall_ms": 14.2
}
```

- `status`: `"passed"` | `"failed"` | `"skipped"`
- `passed`: `true` (passed), `false` (failed), or `null` (skipped)
- `skipped`: `true` when skipped due to missing repository/corpus, otherwise `false`
- `detail`: diagnostic value, mismatch diff, or skip/failure reason
- `args`: CLI argument list passed to `chipsrc`
- `exit`: process exit code (`0`, non-zero, `-1` on timeout/OS error, or `null` when skipped)
- `wall_ms`: elapsed wall-clock time in milliseconds

Intentionally negative CLI probes (`run(..., expected=None)`, such as `missing repo`, `missing bundle`, `bad vendor mode`, and `negative limit` in `real`) record their actual non-zero `exit` code, carry `"probe": true`, `"expected_exit": null`, `"expected_failure": true`, `"surfaced": true`, and `"paired_assertion": "<label>: fails without panic"`, and are listed under `surfaced_probes` in `<out>/summary.json`.

`<out>/summary.json` aggregates per-suite and overall counts (`suites`, `suite_names`, `total`, `passed`, `failed`, `skipped`, `assertions_total`, `assertions_passed`, `assertions_failed`, `assertions_skipped`, `failed_labels`, `surfaced_probes`, `wall_ms`). When `--out` is omitted, results default to `qa/results/` (which is ignored by `.gitignore`).

---

## Oracles (`qa/oracles/*.json`) & Sandbox Isolation

- **Externalized Oracles**: All repository-specific and fixture golden values (symbol names, file paths, line numbers, cross-module caller `(file, line)` pairs, section counts, and expected substrings) live in `qa/oracles/<repo>.json` (`chipsrc.json`, `smart_locker.json`, `volt_website.json`, `beautiful-embedded-c.json`, `dup-content.json`). No drive letters (`[A-Za-z]:\`) or hardcoded golden numbers are inlined in `qa/**/*.py`.
- **Read-Only Real Repositories**: Real repositories under `--repos-root` and `--corpus-root` are treated as strictly **read-only**. The harness never writes bundles (`-o`) or edits inside real repositories; all mutation tests copy source files into isolated sandboxes under `<out>/sandboxes/<suite>-<timestamp>/`.
- **Same-Second Sub-Second Mutation**: `qa/lib/mutate.py` (`mutate_same_second`) applies equal-byte replacements and shifts `st_mtime_ns` by `±100 ms` with carry protection (`os.utime(..., ns=...)`) so the integer second (`int(st_mtime)`) never rolls over into the next second.

---

## Adding a New Suite

1. Create `qa/suites/<name>.py` using only Python standard library imports and expose `run_suite(ctx)`.
2. Store any golden expectations or timing budgets in `qa/oracles/<name>.json`.
3. Register the module in `qa/qa_blackbox.py` (`SUITE_REGISTRY`) and document it in `SUITE_HELP_TEXT` and this `README.md`.
