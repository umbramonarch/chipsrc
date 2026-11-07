# `chipsrc` Black-Box QA Harness (`qa/`)

Reproducible, self-contained black-box E2E regression harness for the `chipsrc` CLI.

The harness runs entirely on the **Python 3.13 standard library** (`argparse`, `csv`, `hashlib`, `json`, `os`, `pathlib`, `shutil`, `statistics`, `subprocess`, `sys`, `time`) with **zero third-party pip packages**. It works under `python -I` (isolated mode) and requires no external repositories outside the `chipsrc` checkout.

---

## Quick Start

Build the release binary and run the default `core` regression suite:

```powershell
cargo build --release
python qa/qa_blackbox.py
```

Run one or more specific suites (`--suite` is repeatable):

```powershell
python qa/qa_blackbox.py --suite real --suite cpp --suite sfc
```

Run in Python isolated mode (`python -I`):

```powershell
python -I qa/qa_blackbox.py --suite core
```

---

## Command-Line Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--bin <PATH>` | `target/release/chipsrc.exe` | Path to the `chipsrc` executable under test. |
| `--repos-root <DIR>` | `<repo-parent>` | Root directory containing the `chipsrc` checkout. |
| `--out <DIR>` | `qa/results/` | Output directory for `<suite>-results.json`, `summary.json`, `bundles/`, `fixture-bundles/`, and `sandboxes/`. Default `qa/results/` is gitignored; reruns into the same `--out` directory are idempotent. |
| `--suite <NAME>` | `core` | Suite to execute (repeatable). `core` expands to `real`, `dup-content`, `concept`, `cpp`, and `sfc`. |
| `--only <PATTERN>` | *(none)* | Only record/run assertions whose `label` matches `<PATTERN>` (case-insensitive substring, repeatable). |
| `--skip <PATTERN>` | *(none)* | Skip assertions whose `label` matches `<PATTERN>` (case-insensitive substring, repeatable). |
| `--timeout <SECONDS>` | `120.0` | Per-command subprocess timeout in seconds. |
| `--fixtures-mode <MODE>` | `build` | `build` (default) builds or refreshes missing/stale baseline and fixture bundles when `.binary_sha256` or `meta.json` fingerprint/schema (`2.1.0`) changes. `require` fails if a required bundle is missing or stale. |
| `--keep-sandboxes` | `false` | Preserve per-suite `<out>/sandboxes/<suite>-<timestamp>/` directories after a successful suite run. |
| `-h`, `--help` | — | Display CLI usage, flags, and available suites. |

---

## Available Suites

- **`core`**: Alias expanding to `real`, `dup-content`, `concept`, `cpp`, and `sfc`.
- **`real`**: Repository inspection, `inspect` vs `meta.json` count agreement, warm cache hits, `--force` determinism, symbol coordinate validity, 1-turn queries (`sym`, `type`, `callers`, `callees`, `path`, `impact`, `macro`, `xref`, `section`, `search`), multi-bundle fixture discovery, `--limit` enforcement, and negative CLI probes.
- **`dup-content`**: Self-contained fixture suite (`qa/fixtures/dup-content/{alpha,beta}/mod.py` + `qa/oracles/dup-content.json`) verifying per-file cache shard disambiguation for byte-identical files at different paths across cold builds, single-copy incremental edits, `--force` count/hash equivalence, and incremental additions/deletions of duplicate copies (7 assertions).
- **`concept`**: Deterministic BM25 concept search on the `chipsrc` bundle (`qa/oracles/concept.json`, 10 assertions): `--kind concept` ranking, camelCase sub-tokenization (`VendorMode`), automatic multi-token zero-hit fallback, `--source`/`--kind source` opt-out, nonsense emptiness, determinism across repeated runs and rebuilds, `< 30 ms` compute latency, TSV coordinate resolution, `--limit` clamping, and absence of persisted concept index files.
- **`cpp`**: C++ coverage against git-tracked `qa/fixtures/cpp/` sources (`qa/oracles/cpp.json`, 3 assertions): class templates, namespaces, nested classes, out-of-line `Class::method`, `operator` overloads, constructors, destructors, `using` aliases, `> 80`-character template parameter list collapsing (`template<...>`), and plain-C header classification when C++ keywords appear only in comments or strings.
- **`sfc`**: Standalone `.jsx`, `.vue`, and `.svelte` single-file component extraction and incremental coordinate mapping against git-tracked `qa/fixtures/sfc/` sources (`qa/oracles/sfc.json`, 8 assertions).

---

## Oracles (`qa/oracles/*.json`) & Sandbox Isolation

- **Externalized Oracles**: Golden expectations and query inputs live in `qa/oracles/{chipsrc,dup-content,concept,cpp,sfc}.json`.
- **Bundle Layout Separation**: The `chipsrc` baseline bundle lives under `<out>/bundles/chipsrc`, while checked-in fixture bundles (`dup-content`, `cpp`, `sfc`) live under `<out>/fixture-bundles/<fixture>`.
- **Per-Binary Bundle Marker**: Every bundle built in `--fixtures-mode build` records `.binary_sha256` in its root so a rebuilt `chipsrc` binary forces a clean rebuild.
- **Sandbox Isolation**: Mutation suites (`dup-content`, `sfc`, `concept` rebuilds) copy sources into `<out>/sandboxes/<suite>-<timestamp>/` and never touch checked-in files.
