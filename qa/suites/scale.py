"""Large-corpus scale suite (STM32CubeF4 + ETL), Milestone 2 budgets.

All timing/RSS budgets, query golden values, and the large-convert guard settings live in
`qa/oracles/perf.json` (section `scale`). Cold conversions run one at a time under the
mission-wide `<corpus-root>/validators/.large-convert.lock` directory; when another large
convert holds it the suite records `skipped` assertions instead of failing or overlapping.
"""
from pathlib import Path
import statistics

from lib import procs
from lib.lockguard import LargeConvertLock, default_lock_path
from lib.runner import HarnessContext

STM32_REPOS = ["STM32CubeF4"]
ETL_REPOS = ["etl"]

STM32_ASSERTION_LABELS = [
    "scale: STM32 bundle artifacts complete after cold convert",
    "scale: STM32 cold convert total, link, and emit within budget",
    "scale: STM32 cold convert peak working set within budget",
    "scale: STM32 warm ensure total and scan within budget",
    "scale: type GPIO_TypeDef returns struct rows with fields",
    "scale: sym HAL_GPIO_Init resolves in the HAL GPIO source",
    "scale: reg GPIO_MODER returns macro rows",
    "scale: xref GPIOA returns cross-reference rows",
    "scale: STM32 auto-sync query median within budget",
    "scale: STM32 cold converts are deterministic",
]

ETL_ASSERTION_LABELS = [
    "scale: ETL cold convert link within budget",
    "scale: ETL cold convert produces a complete bundle",
]


def _budget_timings(timings: dict[str, int], scale: dict) -> dict:
    budgets = scale["budgets"]
    return {
        "total_ms": timings.get("total"),
        "total_budget_ms": budgets["stm32_cold_total_ms"],
        "link_ms": timings.get("link"),
        "link_budget_ms": budgets["stm32_cold_link_ms"],
        "emit_ms": timings.get("emit"),
        "emit_budget_ms": budgets["stm32_cold_emit_ms"],
    }


def _json_row_dicts(run: dict) -> list[dict]:
    """Object rows from a query invocation whose stdout parsed as a non-empty JSON array."""
    rows = run.get("json")
    if not isinstance(rows, list) or not rows:
        return []
    return [row for row in rows if isinstance(row, dict)]


def _type_response(run: dict, name: str) -> dict:
    """Validate one `type <name> --json` response and summarise the matched struct row."""
    rows = _json_row_dicts(run)
    matched = [row for row in rows if row.get("name") == name]
    fields_summary = matched[0].get("fields_summary") if matched else None
    return {
        "label": run["label"],
        "exit": run["exit"],
        "rows": len(rows),
        "matched_rows": len(matched),
        "file": matched[0].get("file") if matched else None,
        "fields_summary": fields_summary,
        "valid": run["exit"] == 0
        and bool(rows)
        and bool(matched)
        and bool(str(fields_summary or "").strip()),
    }


def _sym_response(run: dict, name: str, expected_file: str) -> dict:
    """Validate one `sym <name> --json` response and locate the expected defining file."""
    rows = _json_row_dicts(run)
    matched = [row for row in rows if row.get("name") == name]
    files = sorted({row.get("file") for row in matched if row.get("file")})
    return {
        "label": run["label"],
        "exit": run["exit"],
        "rows": len(rows),
        "matched_rows": len(matched),
        "files": files,
        "expected_file": expected_file,
        "valid": run["exit"] == 0 and expected_file in files,
    }


def _reg_response(run: dict, prefix: str) -> dict:
    """Validate one `reg <name> --json` response and locate matching macro rows."""
    rows = _json_row_dicts(run)
    names = [str(row.get("name", "")) for row in rows]
    matched = [name for name in names if name.startswith(prefix)]
    return {
        "label": run["label"],
        "exit": run["exit"],
        "rows": len(rows),
        "matched_rows": len(matched),
        "names": names[:10],
        "valid": run["exit"] == 0 and bool(rows) and bool(matched),
    }


def _run_stm32(ctx: HarnessContext, scale: dict) -> None:
    budgets = scale["budgets"]
    corpus = ctx.corpus_root / "STM32CubeF4"
    root = ctx.sandbox_dir / "stm32" / "bundles"
    bundle = root / "STM32CubeF4"

    cold = ctx.run_monitored(
        "scale: STM32 cold convert",
        "convert",
        corpus,
        "-o",
        bundle,
        "--vendor-mode",
        "all",
        "--force",
        "--timings",
        sample_process_rss=True,
        sample_interval_ms=budgets["rss_sample_interval_ms"],
    )
    cold_timings = procs.parse_timings(cold["stdout"])
    meta = ctx.read_meta(bundle)
    artifacts = procs.missing_artifacts(bundle)
    cold_ok = (
        cold["exit"] == 0
        and "INDEXED" in cold["stdout"]
        and cold_timings.get("total", 1 << 30) < budgets["stm32_cold_total_ms"]
        and cold_timings.get("link", 1 << 30) <= budgets["stm32_cold_link_ms"]
        and cold_timings.get("emit", 1 << 30) <= budgets["stm32_cold_emit_ms"]
    )
    ctx.check(
        "scale: STM32 cold convert total, link, and emit within budget",
        cold_ok,
        {
            **_budget_timings(cold_timings, scale),
            "exit": cold["exit"],
            "wall_ms": cold["wall_ms"],
            "timings_line": cold_timings,
        },
    )
    peak = cold.get("peak_working_set_bytes")
    ctx.check(
        "scale: STM32 cold convert peak working set within budget",
        peak is not None
        and int(peak) < budgets["stm32_peak_rss_bytes"]
        and (cold.get("rss_samples") or 0) >= budgets["rss_min_samples"],
        {
            "peak_working_set_bytes": peak,
            "peak_working_set_gib": (
                round(int(peak) / (1 << 30), 4) if peak is not None else None
            ),
            "budget_bytes": budgets["stm32_peak_rss_bytes"],
            "rss_samples": cold.get("rss_samples"),
            "min_samples": budgets["rss_min_samples"],
            "sample_interval_ms": budgets["rss_sample_interval_ms"],
        },
    )
    ctx.check(
        "scale: STM32 bundle artifacts complete after cold convert",
        cold["exit"] == 0
        and meta.get("total_files") == scale["stm32_total_files"]
        and not artifacts,
        {
            "total_files": meta.get("total_files"),
            "expected_total_files": scale["stm32_total_files"],
            "symbol_count": meta.get("symbol_count"),
            "missing_artifacts": artifacts,
        },
    )

    warm_runs: list[dict] = []
    hashes_before = procs.bundle_hashes(bundle, include_index_md=False)
    for index in range(1, budgets["warm_runs"] + 1):
        run = ctx.run(
            f"scale: STM32 warm ensure {index}",
            "ensure",
            corpus,
            "-o",
            root,
            "--vendor-mode",
            "all",
            "--timings",
        )
        timings = procs.parse_timings(run["stdout"])
        warm_runs.append(
            {
                "exit": run["exit"],
                "wall_ms": run["wall_ms"],
                "cache_hit": "CACHE HIT" in run["stdout"],
                "timings": timings,
            }
        )
    hashes_after = procs.bundle_hashes(bundle, include_index_md=False)
    hash_diffs = procs.hash_diffs(hashes_before, hashes_after)
    leftovers = procs.find_leftovers(bundle)
    totals = [
        item["timings"].get("total")
        for item in warm_runs
        if item["timings"].get("total") is not None
    ]
    scans = [
        item["timings"].get("scan")
        for item in warm_runs
        if item["timings"].get("scan") is not None
    ]
    warm_ok = (
        all(item["exit"] == 0 and item["cache_hit"] for item in warm_runs)
        and len(totals) == len(warm_runs)
        and len(scans) == len(warm_runs)
        and statistics.median(totals) < budgets["stm32_warm_total_ms"]
        and statistics.median(scans) < budgets["stm32_warm_scan_ms"]
        and not hash_diffs
        and not leftovers["tmp_files"]
        and not leftovers["lock_files"]
    )
    ctx.check(
        "scale: STM32 warm ensure total and scan within budget",
        warm_ok,
        {
            "runs": warm_runs,
            "total_median_ms": statistics.median(totals) if totals else None,
            "scan_median_ms": statistics.median(scans) if scans else None,
            "total_budget_ms": budgets["stm32_warm_total_ms"],
            "scan_budget_ms": budgets["stm32_warm_scan_ms"],
            "index_hash_diffs": len(hash_diffs),
            "tmp_files": leftovers["tmp_files"],
            "lock_files": leftovers["lock_files"],
        },
    )

    limit = str(budgets["query_limit"])
    type_runs = [
        ctx.run(
            f"scale: type GPIO_TypeDef auto-sync {index}",
            "type",
            "-b",
            str(bundle),
            scale["stm32_type_query"],
            "--json",
            "--limit",
            limit,
        )
        for index in range(1, budgets["query_runs"] + 1)
    ]
    type_control = ctx.run(
        "scale: type GPIO_TypeDef no-sync control",
        "type",
        "-b",
        str(bundle),
        scale["stm32_type_query"],
        "--json",
        "--no-sync",
        "--limit",
        limit,
    )
    type_checks = [
        _type_response(run, scale["stm32_type_query"])
        for run in [*type_runs, type_control]
    ]
    type_rows = ctx.exact(type_runs[-1]["json"], scale["stm32_type_query"])
    ctx.check(
        "scale: type GPIO_TypeDef returns struct rows with fields",
        all(item["valid"] for item in type_checks),
        {
            "runs": type_checks,
            "rows": len(type_rows),
            "file": type_rows[0].get("file") if type_rows else None,
            "fields_summary": type_rows[0].get("fields_summary") if type_rows else None,
        },
    )

    sym_runs = [
        ctx.run(
            f"scale: sym HAL_GPIO_Init auto-sync {index}",
            "sym",
            "-b",
            str(bundle),
            scale["stm32_sym_query"],
            "--json",
            "--limit",
            limit,
        )
        for index in range(1, budgets["query_runs"] + 1)
    ]
    sym_checks = [
        _sym_response(run, scale["stm32_sym_query"], scale["stm32_hal_gpio_file"])
        for run in sym_runs
    ]
    sym_rows = ctx.exact(sym_runs[-1]["json"], scale["stm32_sym_query"])
    ctx.check(
        "scale: sym HAL_GPIO_Init resolves in the HAL GPIO source",
        all(item["valid"] for item in sym_checks),
        {
            "runs": sym_checks,
            "rows": len(sym_rows),
            "files": sorted({row.get("file") for row in sym_rows if row.get("file")}),
            "expected_file": scale["stm32_hal_gpio_file"],
        },
    )

    reg_runs = [
        ctx.run(
            f"scale: reg GPIO_MODER auto-sync {index}",
            "reg",
            "-b",
            str(bundle),
            scale["stm32_reg_query"],
            "--json",
            "--limit",
            limit,
        )
        for index in range(1, budgets["query_runs"] + 1)
    ]
    reg_checks = [_reg_response(run, scale["stm32_reg_prefix"]) for run in reg_runs]
    reg_rows = reg_runs[-1]["json"] if isinstance(reg_runs[-1]["json"], list) else []
    ctx.check(
        "scale: reg GPIO_MODER returns macro rows",
        all(item["valid"] for item in reg_checks),
        {
            "runs": reg_checks,
            "rows": len(reg_rows),
        },
    )

    xref = ctx.run(
        "scale: xref GPIOA",
        "xref",
        "-b",
        str(bundle),
        scale["stm32_xref_query"],
        "--json",
        "--no-sync",
    )
    ctx.check(
        "scale: xref GPIOA returns cross-reference rows",
        xref["exit"] == 0
        and isinstance(xref["json"], list)
        and len(xref["json"]) > 0,
        {
            "rows": len(xref["json"]) if isinstance(xref["json"], list) else None,
            "wall_ms": xref["wall_ms"],
        },
    )

    medians = {
        "type": statistics.median(item["wall_ms"] for item in type_runs),
        "sym": statistics.median(item["wall_ms"] for item in sym_runs),
        "reg": statistics.median(item["wall_ms"] for item in reg_runs),
    }
    status = ctx.run(
        "scale: STM32 final status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    status_fresh = (
        isinstance(status["json"], list)
        and len(status["json"]) == 1
        and status["json"][0].get("is_fresh") is True
    )
    query_content_valid = all(
        item["valid"] for item in [*type_checks, *sym_checks, *reg_checks]
    )
    ctx.check(
        "scale: STM32 auto-sync query median within budget",
        all(item["exit"] == 0 for item in [*type_runs, *sym_runs, *reg_runs])
        and query_content_valid
        and all(
            value < budgets["stm32_query_median_ms"] for value in medians.values()
        )
        and status["exit"] == 0
        and status_fresh,
        {
            "medians_ms": medians,
            "budget_ms": budgets["stm32_query_median_ms"],
            "content_valid": query_content_valid,
            "runs": {
                "type": [item["wall_ms"] for item in type_runs],
                "sym": [item["wall_ms"] for item in sym_runs],
                "reg": [item["wall_ms"] for item in reg_runs],
            },
            "status_exit": status["exit"],
            "status_fresh": status_fresh,
        },
    )

    det_root = ctx.sandbox_dir / "stm32" / "determinism"
    det_bundle = det_root / "STM32CubeF4"
    second = ctx.run(
        "scale: STM32 determinism convert",
        "convert",
        corpus,
        "-o",
        det_bundle,
        "--vendor-mode",
        "all",
        "--force",
        "--timings",
    )
    hashes_a = procs.bundle_hashes(bundle)
    hashes_b = procs.bundle_hashes(det_bundle)
    all_diffs = procs.hash_diffs(hashes_a, hashes_b)
    second_meta = ctx.read_meta(det_bundle)
    ctx.check(
        "scale: STM32 cold converts are deterministic",
        second["exit"] == 0
        and meta.get("total_files") == scale["stm32_total_files"]
        and second_meta.get("total_files") == scale["stm32_total_files"]
        and bool(hashes_a)
        and not all_diffs,
        {
            "files": len(hashes_a),
            "second_files": len(hashes_b),
            "diff_count": len(all_diffs),
            "diffs": all_diffs[:10],
            "total_files": [meta.get("total_files"), second_meta.get("total_files")],
            "second_exit": second["exit"],
        },
    )


def _run_etl(ctx: HarnessContext, scale: dict) -> None:
    budgets = scale["budgets"]
    corpus = ctx.corpus_root / "etl"
    root = ctx.sandbox_dir / "etl" / "bundles"
    bundle = root / "etl"
    run = ctx.run(
        "scale: ETL cold convert",
        "convert",
        corpus,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    timings = procs.parse_timings(run["stdout"])
    meta = ctx.read_meta(bundle)
    ctx.check(
        "scale: ETL cold convert link within budget",
        run["exit"] == 0
        and "INDEXED" in run["stdout"]
        and timings.get("link", 1 << 30) <= budgets["etl_link_ms"],
        {
            "link_ms": timings.get("link"),
            "link_budget_ms": budgets["etl_link_ms"],
            "total_ms": timings.get("total"),
            "wall_ms": run["wall_ms"],
            "call_edge_count": meta.get("call_edge_count"),
        },
    )
    artifacts = procs.missing_artifacts(bundle)
    ctx.check(
        "scale: ETL cold convert produces a complete bundle",
        not artifacts and int(meta.get("call_edge_count") or 0) > 0,
        {
            "missing_artifacts": artifacts,
            "call_edge_count": meta.get("call_edge_count"),
            "total_files": meta.get("total_files"),
        },
    )


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["perf"])
    if oracles is None:
        return
    scale = oracles["perf"]["scale"]
    stm32_available = ctx.check_repos_available(
        STM32_REPOS, STM32_ASSERTION_LABELS, use_corpus_root=True
    )
    etl_available = ctx.check_repos_available(
        ETL_REPOS, ETL_ASSERTION_LABELS, use_corpus_root=True
    )
    if not stm32_available and not etl_available:
        return

    guard = LargeConvertLock(
        default_lock_path(ctx.corpus_root),
        wait_seconds=scale["lock_wait_s"],
        stale_seconds=scale["lock_stale_s"],
        owner="qa-scale",
    )
    acquired, reason = guard.acquire()
    if not acquired:
        if stm32_available:
            for label in STM32_ASSERTION_LABELS:
                ctx.skip_record(label, reason)
        if etl_available:
            for label in ETL_ASSERTION_LABELS:
                ctx.skip_record(label, reason)
        return

    previous_timeout = ctx.timeout
    ctx.timeout = max(previous_timeout, float(scale["command_timeout_s"]))
    try:
        if stm32_available:
            _run_stm32(ctx, scale)
        if etl_available:
            _run_etl(ctx, scale)
    finally:
        ctx.timeout = previous_timeout
        guard.release()
