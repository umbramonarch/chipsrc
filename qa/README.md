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
| `--fixtures-mode <MODE>` | `build` | `build` (default) builds or refreshes missing/stale baseline repo bundles under `<out>/bundles/` and fixture bundles under `<out>/fixture-bundles/` when the recorded `.binary_sha256` differs from the SHA-256 of `--bin` (a rebuilt `chipsrc.exe` forces a clean rebuild), or when `meta.json` fingerprint or cache schema (`2.1.0`) differs from `inspect` (recording a failed check if a build fails). `require` fails if a required bundle is missing or stale. |
| `--keep-sandboxes` | `false` | Preserve per-suite `<out>/sandboxes/<suite>-<timestamp>/` directories after a successful suite run (removed by default when a suite passes with 0 failures). |
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
- **`perf`**: Milestone 2 incremental-sync budgets on a `smart_locker` sandbox copy: `emit < 50 ms` and `total < 100 ms` (median of three measured rounds after one warm-up; a round whose total exceeds `150 ms` because of a rotational-disk writeback spike is retried up to twice; a pre-walk and 300 ms settle keep filesystem metadata warm-up out of the measurement), incremental output byte-identical to `convert --force`, content-identical `index/*.tsv` tables skipped on a docstring-only edit (`calls`/`xref`/`macros` keep SHA-256 and mtime while `types.tsv` updates), coordinate-shift Tier 3 (`link=0ms graph=0ms` with `meta.metadata.incremental_tier == "coordinate_shift"`, shifted symbol lines, `--force`-identical output), and the 1,400-line threshold fallback (`incremental_tier == "structural"`, `--force`-identical output) (6 assertions).
- **`concurrency`**: Atomic bundle writes and advisory `cache/.lock` contention: a mixed CLI+hook pipeline leaves zero `*.tmp`/`cache/.lock` leftovers with a parseable `meta.json`; a live lock held by a helper process makes an auto-sync query answer from the on-disk bundle in `< 1500 ms` and `hook post-edit` exit `0` in `< 1500 ms` without touching the bundle; explicit `ensure` waits `4.5–20 s` then fails naming the lock while the bundle hashes stay unchanged; a 30-second-old stale lock is reclaimed in `< 5 s`; `meta.json` is sampled every `5 ms` during three forced rebuilds (≥ 20 samples each, zero empty/invalid reads); the 5 concurrent `ensure` + 5 concurrent `sym` processes all exit `0` with intact TSV headers and no leftovers; and, checked **immediately after those 10 processes finish and before the follow-up `ensure`**, `procs.missing_artifacts` reports nothing — every artifact present, `cache/manifest.json` a `2.1.0` manifest with a non-empty `files` map, and every referenced shard on disk (8 assertions).
- **`scale`**: Large-corpus budgets from `library/perf-baselines.md` against read-only `STM32CubeF4` (12,471 files) and `etl`: STM32 `--vendor-mode all` cold `convert --force` (`total < 40 s`, `link ≤ 14,350 ms`, `emit ≤ 16,450 ms`, peak working set `< 1.5 GiB` sampled every 100 ms via the Windows process API), complete bundle artifacts, warm `ensure` median `total`/`scan` `< 300 ms` with unchanged `index/*` hashes, auto-sync `type GPIO_TypeDef` / `sym HAL_GPIO_Init` / `reg GPIO_MODER` medians `< 500 ms` plus an `xref GPIOA` control and a fresh final `status --check`, two independent STM32 cold builds byte-identical across `index/`, `sections/`, and `INDEX.md`, and the ETL cold `link ≤ 17,500 ms` complete bundle (12 assertions). Every auto-sync round **and** the `type GPIO_TypeDef --no-sync` control must return a non-empty JSON array whose `GPIO_TypeDef` row has a non-empty `fields_summary`; all three `sym HAL_GPIO_Init` rounds must resolve in `stm32f4xx_hal_gpio.c`; all three `reg GPIO_MODER` rounds must return `GPIO_MODER*` rows; the median-budget assertion also requires that content check, so a fast empty response cannot pass a timing budget. Cold conversions are serialized across harness runs and validators through the `<corpus-root>/validators/.large-convert.lock` directory; when another large convert holds it (180 s wait) the suite records `skipped` assertions with the holder path instead of overlapping or failing.
- **`concept`**: Deterministic BM25 concept search on the `chipsrc` bundle (10 assertions): `--kind concept` ranks `structural_digest` in `crates/chipsrc-core/src/model.rs` inside the top 5 for a three-token query and at index 0 for a two-token query; camelCase sub-tokenization surfaces `VendorMode` for a spaced query; default-kind multi-token queries with zero literal/regex hits fall back to BM25 (`analyze_graph` in `graph.rs`, `structural_digest` in `model.rs`); `--source` and `--kind source` never fall back and return `[]`; four nonsense queries return `[]`; five identical runs plus a rebuild into a second bundle produce byte-identical ranking; median query compute time (wall time minus the median `--version` spawn cost) is `< 30 ms`; every hit joins back to its `index/{symbols,types,macros}.tsv` row with a valid source coordinate; `--limit 3`, `-n 1`, and the default length are honored; and no concept index file is persisted. Every literal query string, golden target, and budget lives in `qa/oracles/concept.json` — an in-source copy would be indexed into the bundle under test and defeat the zero-hit fallback.
- **`cpp`**: C++ coverage against checked-in fixtures and the `etl` corpus (11 assertions): the git-tracked `qa/fixtures/cpp/` sources exercise a class template, namespace, nested class, out-of-line `Class::method`, `operator` overload, constructor, destructor, `using` alias, and a template parameter list longer than 80 characters; `index/{types,symbols}.tsv` must carry the expected kinds and `start_line`/`end_line` spans containing the identifier; `include/plain_c.h` (C++ keywords only in comments and strings) must stay classified as C (`inspect`: `c=2`, `cpp=2`, with no `Fake`/`demo`/`thing` symbols leaking). On `etl`: `.h` headers classified as C++ by content (`cpp.first_party_files >= 360`, `c` between 20 and 98, `total_files == 1221`), `parse_clean_ratio >= 0.90`, cold `link` within the Scale-area budget, `type ivector` / `type etl::ivector` returning the `include/etl/vector.h` class template with a non-empty `fields_summary`, `sym etl::ivector::push_back` at one of lines 454/468/1526, out-of-line `DeferredTestReporter::ReportTestStart`/`GetResults` at lines 9/28, `callees ivector::push_back` + `callers create_back` resolving `create_back` at `include/etl/vector.h:458`, and every `> 80`-character template parameter list collapsing to `template<...>` with no raw list and `len(signature) <= 160`. On `STM32CubeF4`: `total_files == 12471` with `c.files >= 12000` (no mass reclassification). The ETL conversion runs under the same mission-wide large-convert guard as `scale`.
- **`corpus`**: Full 10-repository (`chipsrc`, `chipdoc`, `smart_locker`, `volt_website`, `beautiful-embedded-c`, `stock_screener`, `my-sunshine`, `work`, `STM32CubeF4`, `etl`) count agreement, warm cache hits, `--force` determinism, coordinate validity, and sanity bounds.
- **`sfc`**: Standalone `.jsx`, `.vue`, and `.svelte` single-file component extraction and incremental coordinate shift verification (`qa/fixtures/sfc/`).

---

## Skip-if-Missing Preflight & Fixture-Only Execution

- When `--repos-root` or `--corpus-root` (or a specific repository required by a suite) is absent on disk, the preflight check prints a `SKIP [<suite>]` reason naming the missing path and writes `skipped` records (`"status": "skipped"`, `"skipped": true`, `"passed": null`, `"detail": "<reason>"`) to `<out>/<suite>-results.json`.
- Suites that only depend on `--repos-root` (such as `real`, `sync`, `boundary`, `focused`, `hooks`) are unaffected by a missing `--corpus-root`.
- Fixture-only suites (such as `dup-content` and `sfc`) use self-contained sources under `qa/fixtures/` and run with zero skips even when both `--repos-root` and `--corpus-root` point to non-existent directories.
- The harness exits `0` whenever `failed == 0` (including when missing external repositories produce `skipped` records) and exits `1` if any record has `status == "failed"`.

- **`perf` / `concurrency` / `scale` require the release binary built from the current sources and (for `scale`) the `STM32CubeF4` + `etl` corpora; when a required repository or corpus is missing those assertions become `skipped` with the missing path, never a traceback. `perf` and `concurrency` only need `--repos-root/smart_locker`.
- **Large-corpus serialization**: `scale` claims the mission-wide directory `<corpus-root>/validators/.large-convert.lock` (the same one `library/user-testing.md` reserves for validators) before its first cold conversion and releases it in a `finally` block. If the guard is still held after the 180 s wait, the suite records skipped assertions naming the holder. A guard directory older than 30 minutes is treated as stale and reclaimed.
- **Scale-run housekeeping (before timing)**: while holding the guard, `scale` deletes leftover `scale-*` sandbox trees from earlier interrupted runs, warms the STM32CubeF4 corpus into the OS page cache, and pauses 2 s so NTFS lazy-writer flushes from the preceding suites settle. Both steps are recorded as observational records (`scale: stale scale sandboxes removed`, `scale: STM32 corpus cache warm-up`); they do not change any budget. The budgets were calibrated with a warm corpus, and without the warm-up the first timed run pays the drive's cold sequential-read cost inside its `scan` stage (measured `18 s` versus `0.4 s`). The warm-up stats every corpus entry and reads only the indexed source extensions (`.c/.h/.cpp/...`, ~330 MB of STM32CubeF4's 759 MB) with eight parallel readers, which takes ~30 s on this machine's rotational volume instead of ~150 s for a serial full read.

---

## Large-Convert Guard Ownership (`qa/lib/lockguard.py`)

The guard directory is a real mutual-exclusion primitive, so it is ownership-safe:

- `acquire()` creates the directory and immediately writes `owner.json` (`{"pid": <int>, "token": "<uuid4 hex>", "created_ms": <int>, "owner": "<suite>"}`). If the owner file cannot be written, the claim is released and the suite fails rather than holding a nameless lock. The writer keeps a **live file handle** to `owner.json` for the whole hold; on Windows NTFS an open handle without delete sharing makes `os.rename` of the containing directory fail with `PermissionError`, so a stale reclaimer can never displace a live owner. The handle is closed in `release()`/`__del__()` before the directory is removed.
- Holder age comes from `owner.json.created_ms` and falls back to the directory mtime when the file is missing or malformed (e.g. a validator's plain `mkdir` claim).
- Stale reclamation (`age > stale_s`) is itself serialized through a sibling `<lock>.reclaim` directory: `acquire()` refuses to `mkdir` the canonical path while a fresh reclaim claim exists, the reclaimer re-checks the holder age **after** claiming it (so a replacement claim that appeared in between aborts the reclamation), and only then renames `<lock>` to `<lock>.stale.<uuid>` before `shutil.rmtree`. If the rename captured a fresh lock, the directory is renamed back untouched. An abandoned claim (older than 60 s, e.g. a crashed reclaimer) is cleared by the next contender.
- `release()` re-reads `owner.json` and removes the directory only when `token` equals this guard's token, so a guard never deletes a lock now owned by another process.
- `qa/tests/test_lockguard.py` (stdlib `unittest`) covers the three-contender injected schedule, live-owner displacement, token-safe release, and abandoned-claim recovery. Run it with `python -m unittest discover -s qa/tests -p "test_*.py"` from the repository root.

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
  "args": null,
  "exit": null,
  "wall_ms": null
}
```

- `status`: `"passed"` | `"failed"` | `"skipped"`
- `passed`: `true` (passed), `false` (failed), or `null` (skipped)
- `skipped`: `true` when skipped due to missing repository/corpus, otherwise `false`
- `detail`: diagnostic value, mismatch diff, or skip/failure reason
- `args`: CLI argument list passed to `chipsrc` for command invocations, or `null` for non-command assertion/skip/observational records
- `exit`: process exit code (`0`, non-zero, `-1` on timeout/OS error, or `null` when not a command or skipped)
- `wall_ms`: elapsed wall-clock time in milliseconds for command invocations, or `null` when not a command

Intentionally negative CLI probes (`run(..., expected=None)`, such as `missing repo`, `missing bundle`, `bad vendor mode`, and `negative limit` in `real`) record their actual non-zero `exit` code, carry `"probe": true`, `"expected_exit": null`, `"expected_failure": true`, `"surfaced": true`, and `"paired_assertion": "<label>: fails without panic"`, and are listed under `surfaced_probes` in `<out>/summary.json`.

Monitored invocations additionally carry sampling evidence: `samples`, `empty_reads`, `read_errors`, `read_error_details`, `parse_failures`, `distinct_hashes`, and `sample_hashes` (for `--suite concurrency`'s `meta.json` polling), and `peak_working_set_bytes` + `rss_samples` (for `--suite scale`'s cold-convert RSS budget). A sampled open that races the atomic rename is retried up to three times before it is counted as a `read_error`.

`<out>/summary.json` aggregates per-suite and overall counts (`suites`, `suite_names`, `total`, `passed`, `failed`, `skipped`, `assertions_total`, `assertions_passed`, `assertions_failed`, `assertions_skipped`, `failed_labels`, `surfaced_probes`, `wall_ms`). When `--out` is omitted, results default to `qa/results/` (which is ignored by `.gitignore`).

---

## Oracles (`qa/oracles/*.json`) & Sandbox Isolation

- **Externalized Oracles**: All repository-specific and fixture golden values (symbol names, file paths, line numbers, cross-module caller `(file, line)` pairs, section counts, and expected substrings) live in `qa/oracles/<repo>.json` (`chipsrc.json`, `smart_locker.json`, `volt_website.json`, `beautiful-embedded-c.json`, `dup-content.json`). The concept-search query strings, ranked targets, determinism/latency budgets, and limit expectations live in `qa/oracles/concept.json`; the C++ fixture/ETL/STM32 golden values and large-convert guard timings live in `qa/oracles/cpp.json`. The Milestone 2 timing budgets and large-corpus scenario values — smart_locker `emit`/`total` budgets, spike-retry/warm-up settings, coordinate-shift and threshold expectations, concurrency wait budgets and sample intervals, STM32CubeF4/ETL warm, cold, RSS, query and determinism budgets, query golden values, and the large-convert guard timings — live in `qa/oracles/perf.json` (shared by the `perf`, `concurrency`, and `scale` suites). No drive letters (`[A-Za-z]:\`) or hardcoded golden numbers are inlined in `qa/**/*.py`.
- **Bundle Layout Separation**: Real-repository baseline bundles (`chipsrc`, `smart_locker`, `volt_website`, `beautiful-embedded-c`) live under `<out>/bundles/<repo>`, while checked-in fixture bundles (`dup-content`, `cpp`, etc.) are built under `<out>/fixture-bundles/<fixture>` so multi-bundle status checks on `<out>/bundles/` remain idempotent across reruns.
- **Per-Binary Bundle Marker**: every bundle built in `--fixtures-mode build` records `.binary_sha256` (the SHA-256 of `--bin`) in its bundle root. The next run compares that marker before reusing a cached bundle; a mismatch deletes the bundle and rebuilds it from scratch, so tables emitted by an older call graph or parser can never be mistaken for fresh output. `require` mode never compares or rewrites the marker.
- **Read-Only Real Repositories & Sandbox Cleanup**: Real repositories under `--repos-root` and `--corpus-root` are treated as strictly **read-only**. The harness never writes bundles (`-o`) or edits inside real repositories; all mutation tests copy source files into isolated sandboxes under `<out>/sandboxes/<suite>-<timestamp>/`. Per-suite sandboxes under `<out>/sandboxes/` are removed at the end of a successful suite unless `--keep-sandboxes` is passed.
- **Same-Second Sub-Second Mutation**: `qa/lib/mutate.py` (`mutate_same_second`) applies equal-byte replacements and shifts `st_mtime_ns` by `±100 ms` with carry protection (`os.utime(..., ns=...)`) so the integer second (`int(st_mtime)`) never rolls over into the next second.
- **Artifact Validation (`qa/lib/procs.py::missing_artifacts`)**: besides the six `index/*.tsv` header checks and `meta.json` JSON parse, the manifest is validated as a real cache: `cache/manifest.json` must parse as a JSON object with `schema_version == "2.1.0"` and a non-empty `files` object whose entries each carry a `shard` string, and every referenced shard (per-file `cache/<key>.json` or packed `cache/pack-<16hex>.json`) must exist on disk. Truncated/invalid JSON, a wrong schema version, an empty or non-object `files` map, or an entry without a shard returns `["invalid cache/manifest.json"]`; a missing shard returns its bundle-relative path. `procs.manifest_file_count(bundle)` reports the number of manifest entries for assertion evidence.

---

## Adding a New Suite

1. Create `qa/suites/<name>.py` using only Python standard library imports and expose `run_suite(ctx)`.
2. Store any golden expectations or timing budgets in `qa/oracles/<name>.json`.
3. Register the module in `qa/qa_blackbox.py` (`SUITE_REGISTRY`) and document it in `SUITE_HELP_TEXT` and this `README.md`.
