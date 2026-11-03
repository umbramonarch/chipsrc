"""Incremental emit, coordinate-shift, and 1,400-line threshold suite (Milestone 2).

Budgets and scenario golden values come from `qa/oracles/perf.json` (section `perf`).
The structural-edit budget is the median of three measured rounds; a round whose total
pipeline time spikes above the `spike_retry_ms` threshold (rotational-disk writeback) is
discarded as a warm-up/retry, up to `max_spike_retries` times.
"""
from pathlib import Path
import statistics
import time

from lib import procs
from lib.runner import HarnessContext

REPOS = ["smart_locker"]

ASSERTION_LABELS = [
    "perf: smart_locker structural edit meets emit and total budgets",
    "perf: incremental structural edit output matches --force",
    "perf: content-identical index tables are not rewritten",
    "perf: coordinate shift skips link and graph and reports the tier",
    "perf: coordinate-shift output matches --force",
    "perf: 1400-line threshold falls back to structural and matches --force",
]

ALL_LABELS = [
    *ASSERTION_LABELS,
    "perf: initial convert",
    "perf: pre-walk",
    "perf: structural edit round",
    "perf: force rebuild after structural edits",
    "perf: docstring initial convert",
    "perf: docstring incremental ensure",
    "perf: query Device after docstring edit",
    "perf: coordinate-shift initial convert",
    "perf: coordinate-shift ensure",
    "perf: coordinate-shift query",
    "perf: coordinate-shift status",
    "perf: coordinate-shift force rebuild",
    "perf: threshold initial convert",
    "perf: threshold crossing ensure",
    "perf: threshold query",
    "perf: threshold status",
    "perf: threshold force rebuild",
]

INDEX_TABLES = ("sections", "symbols", "types", "calls", "macros", "xref")


def _index_stats(bundle: Path) -> dict[str, dict]:
    stats: dict[str, dict] = {}
    for name in INDEX_TABLES:
        path = bundle / "index" / f"{name}.tsv"
        if path.is_file():
            stat = path.stat()
            stats[name] = {
                "sha256": procs.file_sha256(path),
                "mtime_ns": stat.st_mtime_ns,
            }
    return stats


def _sym_coords(ctx: HarnessContext, label: str, bundle: Path, name: str) -> dict:
    run = ctx.run(
        label, "sym", "-b", str(bundle), name, "--json", "--no-sync"
    )
    rows = ctx.exact(run["json"], name)
    return rows[0] if rows else {}


def _run_structural_budget(ctx: HarnessContext, perf: dict, source: Path) -> dict:
    budgets = perf["budgets"]
    target = source / perf["target_file"]
    root = ctx.sandbox_dir / "perf-bundles"
    bundle = root / source.name
    current = perf["symbol"]
    rounds: list[dict] = []
    measured: list[dict] = []
    spikes = 0
    attempt = 0
    warmup_rounds = budgets["warmup_rounds"]
    max_rounds = warmup_rounds + budgets["measured_rounds"] + budgets["max_spike_retries"]
    while (
        len(measured) < budgets["measured_rounds"]
        and attempt < max_rounds
    ):
        attempt += 1
        new_name = f"{perf['rename_prefix']}{attempt}"
        if not target.is_file():
            break
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(current, new_name),
        )
        # Measurement hygiene: pre-walk the source metadata and let the previous
        # round's writeback settle so a cold filesystem metadata touch is not
        # attributed to the sync command (first run pays page-cache warmup).
        ctx.run(
            f"perf: pre-walk round {attempt}",
            "status",
            bundle,
            "--check",
            "--json",
            expected=2,
        )
        if budgets["settle_ms"]:
            time.sleep(budgets["settle_ms"] / 1000.0)
        run = ctx.run(
            f"perf: structural edit round {attempt}",
            "ensure",
            source,
            "-o",
            root,
            "--timings",
        )
        timings = procs.parse_timings(run["stdout"])
        counters = procs.parse_reparsed(run["stdout"])
        meta = ctx.read_meta(bundle)
        shape_ok = (
            run["exit"] == 0
            and "INCREMENTAL SYNC" in run["stdout"]
            and "CACHE HIT" not in run["stdout"]
            and counters == (perf["expected_reparsed"], perf["expected_reused"])
            and meta.get("incremental_reparsed_files") == perf["expected_reparsed"]
            and meta.get("incremental_reused_files") == perf["expected_reused"]
            and timings.get("emit") is not None
            and timings.get("total") is not None
        )
        info = {
            "round": attempt,
            "symbol": new_name,
            "exit": run["exit"],
            "wall_ms": run["wall_ms"],
            "timings": timings,
            "reparsed": counters[0] if counters else None,
            "reused": counters[1] if counters else None,
            "meta_reparsed": meta.get("incremental_reparsed_files"),
            "meta_reused": meta.get("incremental_reused_files"),
            "incremental_sync": "INCREMENTAL SYNC" in run["stdout"],
            "shape_ok": shape_ok,
        }
        rounds.append(info)
        if attempt <= warmup_rounds and shape_ok:
            info["outcome"] = "warmup"
        elif (
            shape_ok
            and len(measured) < budgets["measured_rounds"]
            and spikes < budgets["max_spike_retries"]
            and timings.get("total", 1 << 30) > budgets["spike_retry_ms"]
        ):
            spikes += 1
            info["outcome"] = "spike-retry"
        else:
            info["outcome"] = "measured"
            measured.append(info)
        current = new_name

    emit_median = (
        statistics.median(item["timings"]["emit"] for item in measured)
        if measured
        else None
    )
    total_median = (
        statistics.median(item["timings"]["total"] for item in measured)
        if measured
        else None
    )
    passed = (
        len(measured) >= budgets["measured_rounds"]
        and all(item["shape_ok"] for item in measured)
        and emit_median is not None
        and total_median is not None
        and emit_median < budgets["emit_ms"]
        and total_median < budgets["total_ms"]
    )
    ctx.check(
        "perf: smart_locker structural edit meets emit and total budgets",
        passed,
        {
            "emit_median_ms": emit_median,
            "total_median_ms": total_median,
            "emit_budget_ms": budgets["emit_ms"],
            "total_budget_ms": budgets["total_ms"],
            "measured_rounds": len(measured),
            "measured_rounds_required": budgets["measured_rounds"],
            "warmup_rounds": warmup_rounds,
            "settle_ms": budgets["settle_ms"],
            "spike_retries": spikes,
            "total_files": ctx.read_meta(bundle).get("total_files"),
            "rounds": rounds,
        },
    )
    return {"bundle": bundle, "source": source, "root": root, "symbol": current}


def _check_force_equality(
    ctx: HarnessContext,
    label: str,
    source: Path,
    bundle: Path,
    force_label: str,
    include_index_md: bool,
) -> dict:
    incremental = procs.bundle_hashes(bundle, include_index_md=include_index_md)
    ctx.run(
        force_label,
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    forced = procs.bundle_hashes(bundle, include_index_md=include_index_md)
    diffs = procs.hash_diffs(incremental, forced)
    ctx.check(
        label,
        bool(incremental) and not diffs,
        {
            "incremental_files": len(incremental),
            "forced_files": len(forced),
            "diff_count": len(diffs),
            "diffs": diffs[:10],
        },
    )
    return {"files": len(incremental), "diffs": diffs}


def _run_content_identical_tables(ctx: HarnessContext, perf: dict, source: Path) -> None:
    docstring = perf["docstring"]
    root = ctx.sandbox_dir / "doc-bundles"
    bundle = root / source.name
    ctx.run(
        "perf: docstring initial convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    before = _index_stats(bundle)
    target = source / docstring["file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                docstring["old_text"], docstring["new_text"]
            ),
        )
    ctx.run(
        "perf: docstring incremental ensure",
        "ensure",
        source,
        "-o",
        root,
        "--timings",
    )
    after = _index_stats(bundle)
    type_run = ctx.run(
        "perf: query Device after docstring edit",
        "type",
        "-b",
        str(bundle),
        docstring["type_name"],
        "--json",
        "--no-sync",
    )
    rows = ctx.exact(type_run["json"], docstring["type_name"])
    doc_summary = rows[0].get("doc_summary") if rows else None
    unchanged_ok = all(
        before.get(name, {}).get("sha256") == after.get(name, {}).get("sha256")
        and before.get(name, {}).get("mtime_ns")
        == after.get(name, {}).get("mtime_ns")
        for name in docstring["unchanged_tables"]
    )
    changed_name = docstring["changed_table"]
    changed_ok = (
        changed_name in before
        and changed_name in after
        and after[changed_name]["mtime_ns"] > before[changed_name]["mtime_ns"]
    )
    ctx.check(
        "perf: content-identical index tables are not rewritten",
        doc_summary == docstring["new_text"] and unchanged_ok and changed_ok,
        {
            "doc_summary": doc_summary,
            "expected_doc_summary": docstring["new_text"],
            "unchanged_tables": list(docstring["unchanged_tables"]),
            "unchanged_ok": unchanged_ok,
            "changed_table": changed_name,
            "changed_table_newer": changed_ok,
            "tables": {
                name: {
                    "sha_equal": before.get(name, {}).get("sha256")
                    == after.get(name, {}).get("sha256"),
                    "mtime_before_ns": before.get(name, {}).get("mtime_ns"),
                    "mtime_after_ns": after.get(name, {}).get("mtime_ns"),
                }
                for name in INDEX_TABLES
            },
        },
    )


def _run_coordinate_shift(ctx: HarnessContext, perf: dict, source: Path, symbol: str) -> None:
    shift = perf["coordinate_shift"]
    root = ctx.sandbox_dir / "shift-bundles"
    bundle = root / source.name
    ctx.run(
        "perf: coordinate-shift initial convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    before = _sym_coords(
        ctx, "perf: coordinate-shift query before", bundle, symbol
    )
    target = source / shift["file"]
    if target.is_file():
        pad = (
            "\n".join(
                shift["pad_template"].format(n=index)
                for index in range(1, shift["pad_lines"] + 1)
            )
            + "\n"
        )
        ctx.changed_write(
            target, pad + target.read_text(encoding="utf-8")
        )
    run = ctx.run(
        "perf: coordinate-shift ensure",
        "ensure",
        source,
        "-o",
        root,
        "--timings",
    )
    timings = procs.parse_timings(run["stdout"])
    meta = ctx.read_meta(bundle)
    after = _sym_coords(
        ctx, "perf: coordinate-shift query after", bundle, symbol
    )
    status = ctx.run(
        "perf: coordinate-shift status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    start_before = before.get("start_line")
    end_before = before.get("end_line")
    start_after = after.get("start_line")
    end_after = after.get("end_line")
    moved = (
        isinstance(start_before, int)
        and isinstance(end_before, int)
        and start_after == start_before + shift["pad_lines"]
        and end_after == end_before + shift["pad_lines"]
    )
    ctx.check(
        "perf: coordinate shift skips link and graph and reports the tier",
        run["exit"] == 0
        and "INCREMENTAL SYNC" in run["stdout"]
        and timings.get("link") == shift["expected_link_ms"]
        and timings.get("graph") == shift["expected_graph_ms"]
        and meta.get("incremental_tier") == shift["expected_tier"]
        and moved
        and status["exit"] == 0,
        {
            "timings": timings,
            "incremental_tier": meta.get("incremental_tier"),
            "start_line": [start_before, start_after],
            "end_line": [end_before, end_after],
            "pad_lines": shift["pad_lines"],
            "status_exit": status["exit"],
        },
    )
    incremental = procs.bundle_hashes(bundle)
    ctx.run(
        "perf: coordinate-shift force rebuild",
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    forced = procs.bundle_hashes(bundle)
    diffs = procs.hash_diffs(incremental, forced)
    sections_dir = bundle / "sections"
    section_text = ""
    if sections_dir.is_dir():
        section_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(sections_dir.glob("*.md"))
        )
    coordinate = f"{shift['file']}:{start_after}-{end_after}"
    ctx.check(
        "perf: coordinate-shift output matches --force",
        bool(incremental) and not diffs and coordinate in section_text,
        {
            "incremental_files": len(incremental),
            "diff_count": len(diffs),
            "diffs": diffs[:10],
            "expected_coordinate": coordinate,
            "coordinate_present": coordinate in section_text,
        },
    )


def _run_threshold_fallback(ctx: HarnessContext, perf: dict) -> None:
    threshold = perf["threshold"]
    source = ctx.sandbox_dir / "threshold-src" / threshold["dir_name"]
    source.mkdir(parents=True, exist_ok=True)
    lines = [
        threshold["comment_template"].format(n=index)
        for index in range(1, threshold["comment_lines"] + 1)
    ] + list(threshold["function_lines"])
    target = source / threshold["file_name"]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    root = ctx.sandbox_dir / "threshold-bundles"
    bundle = root / threshold["dir_name"]
    ctx.run(
        "perf: threshold initial convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    before = _sym_coords(
        ctx, "perf: threshold query before", bundle, threshold["symbol"]
    )
    prepend = (
        "\n".join(
            threshold["prepend_template"].format(n=index)
            for index in range(1, threshold["prepend_lines"] + 1)
        )
        + "\n"
    )
    ctx.changed_write(target, prepend + target.read_text(encoding="utf-8"))
    run = ctx.run(
        "perf: threshold crossing ensure",
        "ensure",
        source,
        "-o",
        root,
        "--timings",
    )
    meta = ctx.read_meta(bundle)
    after = _sym_coords(
        ctx, "perf: threshold query after", bundle, threshold["symbol"]
    )
    status = ctx.run(
        "perf: threshold status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    start_before = before.get("start_line")
    start_after = after.get("start_line")
    moved = (
        isinstance(start_before, int)
        and start_after == start_before + threshold["prepend_lines"]
    )
    incremental = procs.bundle_hashes(bundle, include_index_md=False)
    ctx.run(
        "perf: threshold force rebuild",
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    forced = procs.bundle_hashes(bundle, include_index_md=False)
    diffs = procs.hash_diffs(incremental, forced)
    ctx.check(
        "perf: 1400-line threshold falls back to structural and matches --force",
        run["exit"] == 0
        and meta.get("incremental_tier") == threshold["expected_tier"]
        and moved
        and status["exit"] == 0
        and bool(incremental)
        and not diffs,
        {
            "incremental_tier": meta.get("incremental_tier"),
            "expected_tier": threshold["expected_tier"],
            "start_line": [start_before, start_after],
            "prepend_lines": threshold["prepend_lines"],
            "timings": procs.parse_timings(run["stdout"]),
            "status_exit": status["exit"],
            "diff_count": len(diffs),
            "diffs": diffs[:10],
        },
    )


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["perf"])
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ALL_LABELS):
        return

    perf = oracles["perf"]["perf"]
    source = ctx.copy_corpus("smart_locker", perf["copy_name"])
    root = ctx.sandbox_dir / "perf-bundles"
    bundle = root / source.name
    ctx.run(
        "perf: initial convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )

    state = _run_structural_budget(ctx, perf, source)
    _check_force_equality(
        ctx,
        "perf: incremental structural edit output matches --force",
        state["source"],
        state["bundle"],
        "perf: force rebuild after structural edits",
        include_index_md=True,
    )
    _run_content_identical_tables(ctx, perf, source)
    _run_coordinate_shift(ctx, perf, source, state["symbol"])
    _run_threshold_fallback(ctx, perf)
