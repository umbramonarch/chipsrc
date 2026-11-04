"""Full-corpus verification suite over the ten mission repositories.

Every repository gets the same five check classes:

1. ``inspect`` and the cold ``convert`` agree on file/line/language counts (and, for the
   eight repositories under ``--repos-root``, the source tree's ``git status --porcelain``
   is identical before and after the conversion).
2. A second ``convert`` on the unchanged source is a ``CACHE HIT`` that rewrites no
   ``INDEX.md`` / ``index/*.tsv`` / ``sections/*.md`` artifact (SHA-256 map unchanged).
3. Two consecutive ``--force`` rebuilds are byte-identical to each other and to the cold
   build, with equal ``total_files`` / ``total_lines`` metadata.
4. Every ``index/symbols.tsv`` row has a non-empty ``name`` and ``symbol_id`` and satisfies
   ``1 <= start_line <= end_line <= count_source_lines(file)``.
5. ``meta.json.sanity`` carries an in-range ``score``, unit-interval ratios, positive token
   estimates/compression, and a ``warnings`` list.

Repositories that are absent from ``--repos-root`` / ``--corpus-root`` are recorded as
``skipped`` with the missing path instead of failing. The two large corpora
(``STM32CubeF4`` and ``etl``) run one at a time under the mission-wide
``<corpus-root>/validators/.large-convert.lock`` guard.
"""
from pathlib import Path
import json
import shutil
import subprocess

from lib import procs
from lib.lockguard import LargeConvertLock, default_lock_path
from lib.runner import HarnessContext

#: Metadata counters that ``chipsrc inspect`` and ``meta.json.metadata`` must agree on.
COUNT_FIELDS = (
    "total_files",
    "first_party_files",
    "vendor_files",
    "test_files",
    "total_lines",
)

#: Five check-class suffixes; the label order is part of the results contract evidence.
CHECK_SUFFIXES = (
    "inspect and convert counts agree",
    "source tree unchanged by convert",
    "warm convert is a cache hit that rewrites no artifact",
    "force rebuilds are byte-identical to the cold build",
    "symbol coordinates are valid",
    "sanity metrics within bounds",
)

#: Suffixes emitted for repositories that live under ``--corpus-root`` (no git snapshot).
CORPUS_ROOT_SUFFIXES = tuple(
    suffix for suffix in CHECK_SUFFIXES if suffix != "source tree unchanged by convert"
)


def repo_labels(repo: str, under_repos_root: bool) -> list[str]:
    """Stable assertion labels for one repository, in check-class order."""
    suffixes = CHECK_SUFFIXES if under_repos_root else CORPUS_ROOT_SUFFIXES
    return [f"corpus: {repo} {suffix}" for suffix in suffixes]


def _read_meta_full(bundle: Path) -> dict:
    try:
        data = json.loads((bundle / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _metadata(bundle: Path) -> dict:
    meta = _read_meta_full(bundle)
    metadata = meta.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _count_source_lines(path: Path) -> int | None:
    """Newline count plus a trailing unterminated line (``None`` when unreadable)."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)


def _git_snapshot(repo_path: Path) -> dict:
    """`git status --porcelain` exit code and output (non-git dirs compare as-is)."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_path), "status", "--porcelain"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"exit": None, "stdout": "", "error": type(exc).__name__}
    return {
        "exit": proc.returncode,
        "stdout": proc.stdout.replace("\r\n", "\n"),
    }


def _language_tuples(entries: object) -> dict[str, tuple[int, int]]:
    if not isinstance(entries, list):
        return {}
    result: dict[str, tuple[int, int]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        language = str(entry.get("language") or "")
        if not language:
            continue
        result[language] = (
            int(entry.get("files") or 0),
            int(entry.get("lines") or 0),
        )
    return result


def _count_mismatches(inspect_payload: dict, metadata: dict) -> dict:
    """Field-level differences between `inspect --json` and `meta.json.metadata`."""
    mismatches: dict[str, object] = {}
    for field in COUNT_FIELDS:
        left, right = inspect_payload.get(field), metadata.get(field)
        if left != right:
            mismatches[field] = [left, right]
    inspect_languages = _language_tuples(inspect_payload.get("languages"))
    meta_languages = _language_tuples(metadata.get("languages"))
    if inspect_languages != meta_languages:
        mismatches["languages"] = {
            "inspect": {key: list(value) for key, value in sorted(inspect_languages.items())},
            "meta": {key: list(value) for key, value in sorted(meta_languages.items())},
        }
    return mismatches


def _coordinate_report(bundle: Path, metadata: dict, source: Path) -> dict:
    """Validate every `index/symbols.tsv` row against the source files on disk."""
    rows = HarnessContext.read_tsv(bundle, "symbols")
    raw_root = metadata.get("source_root")
    source_root = Path(str(raw_root)) if raw_root else source
    line_counts: dict[str, int | None] = {}
    invalid: list[dict] = []
    empty_names = 0
    for row in rows:
        file_rel = str(row.get("file") or "")
        name = str(row.get("name") or "").strip()
        symbol_id = str(row.get("symbol_id") or "").strip()
        if not name or not symbol_id:
            empty_names += 1
            invalid.append(
                {
                    "file": file_rel,
                    "name": row.get("name"),
                    "symbol_id": row.get("symbol_id"),
                    "reason": "empty name or symbol_id",
                }
            )
            continue
        if file_rel not in line_counts:
            line_counts[file_rel] = _count_source_lines(source_root / file_rel)
        line_count = line_counts[file_rel]
        if line_count is None:
            invalid.append(
                {
                    "file": file_rel,
                    "name": name,
                    "reason": "source file missing under source_root",
                }
            )
            continue
        try:
            start_line = int(str(row.get("start_line") or ""))
            end_line = int(str(row.get("end_line") or ""))
        except ValueError:
            invalid.append(
                {
                    "file": file_rel,
                    "name": name,
                    "start_line": row.get("start_line"),
                    "end_line": row.get("end_line"),
                    "reason": "non-integer coordinates",
                }
            )
            continue
        if not 1 <= start_line <= end_line <= line_count:
            invalid.append(
                {
                    "file": file_rel,
                    "name": name,
                    "start_line": start_line,
                    "end_line": end_line,
                    "line_count": line_count,
                }
            )
    return {
        "rows": len(rows),
        "files_checked": len(line_counts),
        "empty_names": empty_names,
        "invalid": invalid[:10],
        "invalid_count": len(invalid),
        "source_root": str(source_root),
    }


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _sanity_report(bundle: Path) -> dict:
    meta = _read_meta_full(bundle)
    sanity = meta.get("sanity")
    if not isinstance(sanity, dict):
        return {"sanity": sanity, "violations": ["meta.json.sanity is not a JSON object"]}
    score = sanity.get("score")
    parse_clean = sanity.get("parse_clean_ratio")
    call_ratio = sanity.get("call_resolution_ratio")
    raw_tokens = sanity.get("raw_source_tokens_est")
    bundle_tokens = sanity.get("bundle_index_tokens_est")
    compression = sanity.get("token_compression_ratio")
    warnings = sanity.get("warnings")
    violations: list[str] = []
    if not isinstance(score, int) or isinstance(score, bool) or not 1 <= score <= 100:
        violations.append(f"score out of 1..=100: {score!r}")
    if not _is_number(parse_clean) or not 0.0 <= float(parse_clean) <= 1.0:
        violations.append(f"parse_clean_ratio out of [0, 1]: {parse_clean!r}")
    if not _is_number(call_ratio) or not 0.0 <= float(call_ratio) <= 1.0:
        violations.append(f"call_resolution_ratio out of [0, 1]: {call_ratio!r}")
    if not _is_number(raw_tokens) or float(raw_tokens) <= 0:
        violations.append(f"raw_source_tokens_est not positive: {raw_tokens!r}")
    if not _is_number(bundle_tokens) or float(bundle_tokens) <= 0:
        violations.append(f"bundle_index_tokens_est not positive: {bundle_tokens!r}")
    if not _is_number(compression) or float(compression) <= 0:
        violations.append(f"token_compression_ratio not positive: {compression!r}")
    if not isinstance(warnings, list):
        violations.append(f"warnings is not a list: {type(warnings).__name__}")
    return {
        "score": score,
        "parse_clean_ratio": parse_clean,
        "call_resolution_ratio": call_ratio,
        "raw_source_tokens_est": raw_tokens,
        "bundle_index_tokens_est": bundle_tokens,
        "token_compression_ratio": compression,
        "warnings_len": len(warnings) if isinstance(warnings, list) else None,
        "violations": violations,
    }


def _meta_counts(metadata: dict) -> dict:
    return {
        "total_files": metadata.get("total_files"),
        "total_lines": metadata.get("total_lines"),
    }


def _run_repo(ctx: HarnessContext, spec: dict) -> None:
    repo = str(spec["name"])
    under_repos_root = str(spec.get("root") or "repos") == "repos"
    source_root = ctx.repos_root if under_repos_root else ctx.corpus_root
    source = source_root / repo
    bundle = ctx.bundles_dir / repo
    vendor_mode = str(spec.get("vendor_mode") or "active")
    labels = repo_labels(repo, under_repos_root)
    if under_repos_root:
        (
            count_label,
            unchanged_label,
            warm_label,
            determinism_label,
            coordinates_label,
            sanity_label,
        ) = labels
    else:
        (
            count_label,
            warm_label,
            determinism_label,
            coordinates_label,
            sanity_label,
        ) = labels
        unchanged_label = None

    # A cold build must start from an empty output directory even on reruns into the same
    # `--out`, so remove this repository's bundle (never the source tree) first.
    if bundle.exists():
        shutil.rmtree(bundle, ignore_errors=True)
    git_before = _git_snapshot(source)

    cold = ctx.run(
        f"corpus: {repo} cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--vendor-mode",
        vendor_mode,
        "--timings",
    )
    metadata = _metadata(bundle)
    hashes_cold = procs.bundle_hashes(bundle, include_index_md=True)
    artifacts = procs.missing_artifacts(bundle)

    inspect = ctx.run(
        f"corpus: {repo} inspect",
        "inspect",
        source,
        "--vendor-mode",
        vendor_mode,
        "--json",
    )
    inspect_payload = inspect.get("json") if isinstance(inspect.get("json"), dict) else {}
    mismatches = _count_mismatches(inspect_payload, metadata)
    counts_ok = (
        cold["exit"] == 0
        and "INDEXED" in str(cold.get("stdout") or "")
        and "CACHE HIT" not in str(cold.get("stdout") or "")
        and "INCREMENTAL SYNC" not in str(cold.get("stdout") or "")
        and inspect["exit"] == 0
        and "panicked" not in (str(cold.get("stderr") or "") + str(inspect.get("stderr") or "")).lower()
        and bool(metadata)
        and not mismatches
        and not artifacts
    )
    ctx.check(
        count_label,
        counts_ok,
        {
            "repo": repo,
            "vendor_mode": vendor_mode,
            "cold_exit": cold["exit"],
            "cold_wall_ms": cold["wall_ms"],
            "inspect_exit": inspect["exit"],
            "counts": {field: [inspect_payload.get(field), metadata.get(field)] for field in COUNT_FIELDS},
            "mismatches": mismatches,
            "missing_artifacts": artifacts,
            "artifact_count": len(hashes_cold),
            "source_root": str(metadata.get("source_root") or ""),
        },
    )

    if unchanged_label is not None:
        git_after = _git_snapshot(source)
        ctx.check(
            unchanged_label,
            git_before == git_after,
            {
                "repo": repo,
                "git_exit": [git_before.get("exit"), git_after.get("exit")],
                "before": str(git_before.get("stdout") or "")[:500],
                "after": str(git_after.get("stdout") or "")[:500],
                "changed": git_before != git_after,
            },
        )

    warm = ctx.run(
        f"corpus: {repo} warm convert",
        "convert",
        source,
        "-o",
        bundle,
        "--vendor-mode",
        vendor_mode,
        "--timings",
    )
    hashes_warm = procs.bundle_hashes(bundle, include_index_md=True)
    warm_diffs = procs.hash_diffs(hashes_cold, hashes_warm)
    warm_stdout = str(warm.get("stdout") or "")
    ctx.check(
        warm_label,
        warm["exit"] == 0
        and "CACHE HIT" in warm_stdout
        and "INCREMENTAL SYNC" not in warm_stdout
        and bool(hashes_cold)
        and not warm_diffs,
        {
            "repo": repo,
            "exit": warm["exit"],
            "wall_ms": warm["wall_ms"],
            "cache_hit": "CACHE HIT" in warm_stdout,
            "artifact_count": len(hashes_cold),
            "hash_diffs": warm_diffs[:10],
            "diff_count": len(warm_diffs),
        },
    )

    force_runs: list[dict] = []
    force_hashes: list[dict[str, str]] = []
    force_counts: list[dict] = []
    for index in (1, 2):
        run = ctx.run(
            f"corpus: {repo} force convert {index}",
            "convert",
            source,
            "-o",
            bundle,
            "--vendor-mode",
            vendor_mode,
            "--force",
            "--timings",
        )
        force_runs.append(run)
        force_hashes.append(procs.bundle_hashes(bundle, include_index_md=True))
        force_counts.append(_meta_counts(_metadata(bundle)))
    diffs_cold_force1 = procs.hash_diffs(hashes_cold, force_hashes[0])
    diffs_force1_force2 = procs.hash_diffs(force_hashes[0], force_hashes[1])
    determinism_ok = (
        all(run["exit"] == 0 for run in force_runs)
        and all("INDEXED" in str(run.get("stdout") or "") for run in force_runs)
        and bool(hashes_cold)
        and not diffs_cold_force1
        and not diffs_force1_force2
        and force_counts[0] == force_counts[1] == _meta_counts(metadata)
    )
    ctx.check(
        determinism_label,
        determinism_ok,
        {
            "repo": repo,
            "force_exits": [run["exit"] for run in force_runs],
            "artifact_count": len(hashes_cold),
            "cold_vs_force1_diffs": diffs_cold_force1[:10],
            "force1_vs_force2_diffs": diffs_force1_force2[:10],
            "cold_vs_force1_diff_count": len(diffs_cold_force1),
            "force1_vs_force2_diff_count": len(diffs_force1_force2),
            "counts_cold": _meta_counts(metadata),
            "counts_force": force_counts,
        },
    )

    report = _coordinate_report(bundle, metadata, source)
    ctx.check(
        coordinates_label,
        report["rows"] > 0 and report["invalid_count"] == 0,
        report,
    )

    sanity = _sanity_report(bundle)
    ctx.check(
        sanity_label,
        not sanity["violations"],
        sanity,
    )


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["corpus"])
    if oracles is None:
        return
    corpus = oracles["corpus"]
    budgets = corpus["budgets"]
    specs = [spec for spec in corpus["repos"] if isinstance(spec, dict) and spec.get("name")]

    runnable: list[dict] = []
    for spec in specs:
        repo = str(spec["name"])
        under_repos_root = str(spec.get("root") or "repos") == "repos"
        root = ctx.repos_root if under_repos_root else ctx.corpus_root
        source = root / repo
        labels = repo_labels(repo, under_repos_root)
        if source.is_dir():
            runnable.append(spec)
            continue
        reason = f"repository not found: {source}"
        print(f"SKIP [corpus] {reason}")
        for label in labels:
            ctx.skip_record(label, reason)

    small = [spec for spec in runnable if not spec.get("large")]
    large = [spec for spec in runnable if spec.get("large")]

    for spec in small:
        _run_repo(ctx, spec)

    if not large:
        return

    guard = LargeConvertLock(
        default_lock_path(ctx.corpus_root),
        wait_seconds=float(budgets["lock_wait_s"]),
        stale_seconds=float(budgets["lock_stale_s"]),
        owner="qa-corpus",
    )
    acquired, reason = guard.acquire()
    if not acquired:
        for spec in large:
            repo = str(spec["name"])
            under_repos_root = str(spec.get("root") or "repos") == "repos"
            for label in repo_labels(repo, under_repos_root):
                ctx.skip_record(label, reason)
        return

    previous_timeout = ctx.timeout
    ctx.timeout = max(previous_timeout, float(budgets["command_timeout_s"]))
    try:
        for spec in large:
            _run_repo(ctx, spec)
    finally:
        ctx.timeout = previous_timeout
        guard.release()
