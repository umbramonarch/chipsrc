"""Atomic-write and advisory-lock concurrency suite (Milestone 2, P2.2).

Budgets and lock timings come from `qa/oracles/perf.json` (section `concurrency`).
Held locks are owned by a real helper process (`lib.procs.hold_lock_process`) that keeps
`cache/.lock` alive by touching it, so the deferral/wait behavior is exercised exactly as
a second chipsrc writer would.
"""
from pathlib import Path
import json
import os
import time

from lib import procs
from lib.runner import HarnessContext

REPOS = ["smart_locker"]

ASSERTION_LABELS = [
    "concurrency: mixed CLI and hook pipeline leaves no tmp or lock files",
    "concurrency: held lock makes auto-sync query skip within budget",
    "concurrency: held lock makes hook post-edit defer within budget",
    "concurrency: held lock makes explicit ensure wait then fail with a lock error",
    "concurrency: stale lock is reclaimed by ensure",
    "concurrency: meta.json never observed torn during forced rebuilds",
    "concurrency: five concurrent ensure and five concurrent queries keep the bundle valid",
    "concurrency: concurrent processes leave cache manifest and shards intact",
]

ALL_LABELS = [
    *ASSERTION_LABELS,
    "concurrency: pipeline",
    "concurrency: held-lock",
    "concurrency: post-unlock",
    "concurrency: stale-lock",
    "concurrency: forced rebuild",
    "concurrency: concurrent",
    "concurrency: follow-up",
]

COPY_NAMES = {
    "pipeline": "locker-pipeline",
    "lock": "locker-lock",
    "hook": "locker-hook",
    "wait": "locker-wait",
    "stale": "locker-stale",
    "samples": "locker-samples",
    "concurrent": "locker-concurrent",
}


def _bundle_for(source: Path, root: Path) -> Path:
    return root / source.name


def _read_lock(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _stop_and_release(helper, lock_file: Path) -> None:
    procs.stop_process(helper)
    try:
        if lock_file.exists():
            lock_file.unlink()
    except OSError:
        pass


def _run_pipeline(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["pipeline"])
    output = source / "output"
    bundle = _bundle_for(source, output)
    ctx.run(
        "concurrency: pipeline cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    ctx.run("concurrency: pipeline warm ensure", "ensure", source, "-o", output, "--timings")
    target = source / conc["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                conc["symbol"], conc["pipeline_symbol"]
            ),
        )
    ctx.run(
        "concurrency: pipeline incremental ensure",
        "ensure",
        source,
        "-o",
        output,
        "--timings",
    )
    ctx.run(
        "concurrency: pipeline auto-sync query",
        "sym",
        "-b",
        str(bundle),
        conc["pipeline_symbol"],
        "--json",
    )
    payload = json.dumps(
        {
            "cwd": str(source),
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(target)},
        }
    )
    ctx.run_hook("concurrency: pipeline hook post-edit", source, "post-edit", payload)
    session = ctx.run_hook(
        "concurrency: pipeline hook session-start",
        source,
        "session-start",
        json.dumps(
            {"cwd": str(source), "hook_event_name": "SessionStart", "source": "startup"}
        ),
    )
    leftovers = procs.find_leftovers(bundle)
    status = ctx.run(
        "concurrency: pipeline status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    meta_ok = bool(ctx.read_meta(bundle))
    ctx.check(
        "concurrency: mixed CLI and hook pipeline leaves no tmp or lock files",
        not leftovers["tmp_files"]
        and not leftovers["lock_files"]
        and meta_ok
        and session["exit"] == 0
        and status["exit"] == 0,
        {
            "tmp_files": leftovers["tmp_files"],
            "lock_files": leftovers["lock_files"],
            "meta_json_parses": meta_ok,
            "session_start_exit": session["exit"],
            "status_exit": status["exit"],
        },
    )


def _run_held_lock_query(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["lock"])
    root = ctx.sandbox_dir / "lock-bundles"
    bundle = _bundle_for(source, root)
    ctx.run(
        "concurrency: held-lock cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    target = source / conc["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                conc["symbol"], conc["locked_symbol"]
            ),
        )
    stale_before = ctx.run(
        "concurrency: held-lock stale status",
        "status",
        bundle,
        "--check",
        "--json",
        expected=2,
    )
    lock_file = bundle / "cache" / ".lock"
    helper = procs.hold_lock_process(lock_file, 120)
    lock_contents = ""
    try:
        lock_present = procs.wait_for_path(lock_file, timeout=10)
        lock_contents = _read_lock(lock_file)
        query = ctx.run(
            "concurrency: held-lock auto-sync query",
            "sym",
            "-b",
            str(bundle),
            conc["symbol"],
            "--json",
        )
        locked_status = ctx.run(
            "concurrency: held-lock status while locked",
            "status",
            bundle,
            "--check",
            "--json",
            expected=2,
        )
    finally:
        _stop_and_release(helper, lock_file)
    refreshed = ctx.run(
        "concurrency: post-unlock auto-sync query",
        "sym",
        "-b",
        str(bundle),
        conc["locked_symbol"],
        "--json",
    )
    fresh_status = ctx.run(
        "concurrency: post-unlock status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    ctx.check(
        "concurrency: held lock makes auto-sync query skip within budget",
        lock_present
        and stale_before["exit"] == 2
        and query["exit"] == 0
        and query["wall_ms"] is not None
        and query["wall_ms"] <= budgets["background_wait_ms"]
        and "panicked at" not in query["stderr"]
        and bool(ctx.exact(query["json"], conc["symbol"]))
        and locked_status["exit"] == 2
        and refreshed["exit"] == 0
        and bool(ctx.exact(refreshed["json"], conc["locked_symbol"]))
        and fresh_status["exit"] == 0,
        {
            "lock_present": lock_present,
            "lock_contents": lock_contents,
            "query_wall_ms": query["wall_ms"],
            "budget_ms": budgets["background_wait_ms"],
            "query_exit": query["exit"],
            "on_disk_symbol_rows": len(ctx.exact(query["json"], conc["symbol"])),
            "status_while_locked_exit": locked_status["exit"],
            "refreshed_rows": len(ctx.exact(refreshed["json"], conc["locked_symbol"])),
            "status_after_unlock_exit": fresh_status["exit"],
        },
    )


def _run_held_lock_hook(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["hook"])
    output = source / "output"
    bundle = _bundle_for(source, output)
    ctx.run(
        "concurrency: held-lock hook convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    target = source / conc["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                conc["symbol"], conc["hook_symbol"]
            ),
        )
    before = procs.bundle_hashes(bundle, include_index_md=False)
    lock_file = bundle / "cache" / ".lock"
    helper = procs.hold_lock_process(lock_file, 120)
    lock_contents = ""
    try:
        lock_present = procs.wait_for_path(lock_file, timeout=10)
        lock_contents = _read_lock(lock_file)
        payload = json.dumps(
            {
                "cwd": str(source),
                "hook_event_name": "PostToolUse",
                "tool_name": "Edit",
                "tool_input": {"file_path": str(target)},
            }
        )
        hook = ctx.run_hook(
            "concurrency: held-lock hook post-edit", source, "post-edit", payload
        )
        after = procs.bundle_hashes(bundle, include_index_md=False)
        locked_status = ctx.run(
            "concurrency: held-lock hook status while locked",
            "status",
            bundle,
            "--check",
            "--json",
            expected=2,
        )
    finally:
        _stop_and_release(helper, lock_file)
    ctx.run(
        "concurrency: post-unlock hook ensure",
        "ensure",
        source,
        "-o",
        output,
        "--timings",
    )
    query = ctx.run(
        "concurrency: post-unlock hook query",
        "sym",
        "-b",
        str(bundle),
        conc["hook_symbol"],
        "--json",
    )
    fresh_status = ctx.run(
        "concurrency: post-unlock hook status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    diffs = procs.hash_diffs(before, after)
    ctx.check(
        "concurrency: held lock makes hook post-edit defer within budget",
        lock_present
        and hook["exit"] == 0
        and hook["wall_ms"] is not None
        and hook["wall_ms"] <= budgets["background_wait_ms"]
        and "panicked at" not in hook["stderr"]
        and not diffs
        and locked_status["exit"] == 2
        and bool(ctx.exact(query["json"], conc["hook_symbol"]))
        and fresh_status["exit"] == 0,
        {
            "lock_present": lock_present,
            "lock_contents": lock_contents,
            "hook_wall_ms": hook["wall_ms"],
            "budget_ms": budgets["background_wait_ms"],
            "hook_exit": hook["exit"],
            "bundle_diff_count": len(diffs),
            "status_while_locked_exit": locked_status["exit"],
            "query_rows": len(ctx.exact(query["json"], conc["hook_symbol"])),
            "status_after_unlock_exit": fresh_status["exit"],
        },
    )


def _run_explicit_wait(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["wait"])
    root = ctx.sandbox_dir / "wait-bundles"
    bundle = _bundle_for(source, root)
    ctx.run(
        "concurrency: explicit-wait cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    target = source / conc["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                conc["symbol"], conc["wait_symbol"]
            ),
        )
    before = procs.bundle_hashes(bundle, include_index_md=False)
    meta_before = ctx.read_meta(bundle)
    lock_file = bundle / "cache" / ".lock"
    helper = procs.hold_lock_process(lock_file, 120)
    lock_contents = ""
    try:
        lock_present = procs.wait_for_path(lock_file, timeout=10)
        lock_contents = _read_lock(lock_file)
        result = ctx.run(
            "concurrency: held-lock explicit ensure",
            "ensure",
            source,
            "-o",
            root,
            "--timings",
            expected=1,
        )
        after = procs.bundle_hashes(bundle, include_index_md=False)
    finally:
        _stop_and_release(helper, lock_file)
    combined = (result["stdout"] + result["stderr"]).lower()
    diffs = procs.hash_diffs(before, after)
    meta_after = ctx.read_meta(bundle)
    ctx.check(
        "concurrency: held lock makes explicit ensure wait then fail with a lock error",
        lock_present
        and result["exit"] != 0
        and result["wall_ms"] is not None
        and budgets["explicit_wait_min_ms"] <= result["wall_ms"] <= budgets["explicit_wait_max_ms"]
        and "lock" in combined
        and "panicked at" not in result["stderr"]
        and not diffs
        and bool(meta_before)
        and bool(meta_after),
        {
            "lock_present": lock_present,
            "lock_contents": lock_contents,
            "exit": result["exit"],
            "wall_ms": result["wall_ms"],
            "expected_wait_ms": [
                budgets["explicit_wait_min_ms"],
                budgets["explicit_wait_max_ms"],
            ],
            "mentions_lock": "lock" in combined,
            "bundle_diff_count": len(diffs),
            "meta_json_parses": bool(meta_after),
        },
    )


def _run_stale_lock(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["stale"])
    root = ctx.sandbox_dir / "stale-bundles"
    bundle = _bundle_for(source, root)
    ctx.run(
        "concurrency: stale-lock cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    target = source / conc["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                conc["symbol"], conc["stale_symbol"]
            ),
        )
    lock_file = bundle / "cache" / ".lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    now_ms = int(time.time() * 1000)
    stale_age_s = budgets["stale_lock_age_s"]
    lock_file.write_text(
        f"999999:{now_ms - stale_age_s * 1000}\n", encoding="utf-8"
    )
    past = time.time() - stale_age_s
    os.utime(lock_file, (past, past))
    result = ctx.run(
        "concurrency: stale-lock ensure",
        "ensure",
        source,
        "-o",
        root,
        "--timings",
    )
    query = ctx.run(
        "concurrency: stale-lock query",
        "sym",
        "-b",
        str(bundle),
        conc["stale_symbol"],
        "--json",
    )
    fresh_status = ctx.run(
        "concurrency: stale-lock status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    ctx.check(
        "concurrency: stale lock is reclaimed by ensure",
        result["exit"] == 0
        and result["wall_ms"] is not None
        and result["wall_ms"] < budgets["stale_ensure_max_ms"]
        and bool(ctx.exact(query["json"], conc["stale_symbol"]))
        and fresh_status["exit"] == 0
        and not lock_file.exists(),
        {
            "wall_ms": result["wall_ms"],
            "budget_ms": budgets["stale_ensure_max_ms"],
            "rows": len(ctx.exact(query["json"], conc["stale_symbol"])),
            "status_exit": fresh_status["exit"],
            "lock_remains": lock_file.exists(),
        },
    )
    try:
        if lock_file.exists():
            lock_file.unlink()
    except OSError:
        pass


def _run_meta_sampling(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["samples"])
    root = ctx.sandbox_dir / "sample-bundles"
    bundle = _bundle_for(source, root)
    ctx.run(
        "concurrency: forced rebuild cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    target = source / conc["target_file"]
    meta_path = bundle / "meta.json"
    rebuilds: list[dict] = []
    hashes: set[str] = set()
    current = conc["symbol"]
    for index in range(1, budgets["meta_rebuilds"] + 1):
        new_name = f"{conc['sample_symbol_prefix']}{index}"
        if target.is_file():
            ctx.changed_write(
                target,
                target.read_text(encoding="utf-8").replace(current, new_name),
            )
        run = ctx.run_monitored(
            f"concurrency: forced rebuild sample {index}",
            "convert",
            source,
            "-o",
            bundle,
            "--force",
            "--timings",
            sample_path=meta_path,
            sample_interval_ms=budgets["meta_sample_interval_ms"],
        )
        hashes.update(run.get("sample_hashes") or [])
        rebuilds.append(
            {
                "rebuild": index,
                "exit": run["exit"],
                "wall_ms": run["wall_ms"],
                "samples": run.get("samples"),
                "empty_reads": run.get("empty_reads"),
                "read_errors": run.get("read_errors"),
                "read_error_details": run.get("read_error_details"),
                "parse_failures": run.get("parse_failures"),
                "distinct_hashes": run.get("distinct_hashes"),
            }
        )
        current = new_name
    ctx.check(
        "concurrency: meta.json never observed torn during forced rebuilds",
        all(
            item["exit"] == 0
            and (item["samples"] or 0) >= budgets["meta_min_samples"]
            and item["empty_reads"] == 0
            and item["read_errors"] == 0
            and item["parse_failures"] == 0
            for item in rebuilds
        )
        and len(hashes) >= 2,
        {
            "rebuilds": rebuilds,
            "min_samples": budgets["meta_min_samples"],
            "sample_interval_ms": budgets["meta_sample_interval_ms"],
            "distinct_hashes_total": len(hashes),
        },
    )


def _run_concurrent_processes(ctx: HarnessContext, conc: dict, budgets: dict) -> None:
    source = ctx.copy_corpus("smart_locker", COPY_NAMES["concurrent"])
    root = ctx.sandbox_dir / "conc-bundles"
    bundle = _bundle_for(source, root)
    ctx.run(
        "concurrency: concurrent cold convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    reference_headers = procs.index_headers(bundle)
    target = source / conc["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                conc["symbol"], conc["concurrent_symbol"]
            ),
        )
    count = budgets["concurrent_processes"]
    items: list[tuple[str, list[object]]] = []
    for index in range(1, count + 1):
        items.append(
            (
                f"concurrency: concurrent ensure {index}",
                ["ensure", source, "-o", root],
            )
        )
    for index in range(1, count + 1):
        items.append(
            (
                f"concurrency: concurrent query {index}",
                ["sym", "-b", str(bundle), conc["symbol"], "--json"],
            )
        )
    records = ctx.run_many(items)
    editors = records[:count]
    queries = records[count:]
    headers_after = procs.index_headers(bundle)
    sections_ok = all(
        (bundle / "sections" / md_file).is_file()
        for md_file in procs.section_md_files(bundle)
    )
    artifacts = procs.missing_artifacts(bundle)
    ctx.check(
        "concurrency: concurrent processes leave cache manifest and shards intact",
        not artifacts,
        {
            "missing_artifacts": artifacts,
            "manifest_files": procs.manifest_file_count(bundle),
            "exit_codes": [item["exit"] for item in records],
        },
    )
    leftovers = procs.find_leftovers(bundle)
    follow_up = ctx.run(
        "concurrency: follow-up ensure",
        "ensure",
        source,
        "-o",
        root,
        "--timings",
    )
    fresh_status = ctx.run(
        "concurrency: follow-up status",
        "status",
        bundle,
        "--check",
        "--json",
    )
    query = ctx.run(
        "concurrency: follow-up query",
        "sym",
        "-b",
        str(bundle),
        conc["concurrent_symbol"],
        "--json",
    )
    ctx.check(
        "concurrency: five concurrent ensure and five concurrent queries keep the bundle valid",
        all(item["exit"] == 0 for item in records)
        and all("panicked at" not in item["stderr"] for item in records)
        and all(isinstance(item["json"], list) for item in queries)
        and headers_after == reference_headers
        and sections_ok
        and not artifacts
        and not leftovers["tmp_files"]
        and not leftovers["lock_files"]
        and follow_up["exit"] == 0
        and fresh_status["exit"] == 0
        and bool(ctx.exact(query["json"], conc["concurrent_symbol"])),
        {
            "exit_codes": [item["exit"] for item in records],
            "panics": [
                item["label"]
                for item in records
                if "panicked at" in item["stderr"]
            ],
            "query_json_arrays": sum(
                1 for item in queries if isinstance(item["json"], list)
            ),
            "headers_match_reference": headers_after == reference_headers,
            "missing_artifacts": artifacts,
            "tmp_files": leftovers["tmp_files"],
            "lock_files": leftovers["lock_files"],
            "follow_up_exit": follow_up["exit"],
            "status_exit": fresh_status["exit"],
            "renamed_rows": len(ctx.exact(query["json"], conc["concurrent_symbol"])),
        },
    )


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["perf"])
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ALL_LABELS):
        return

    conc = oracles["perf"]["concurrency"]
    budgets = conc["budgets"]

    _run_pipeline(ctx, conc, budgets)
    _run_held_lock_query(ctx, conc, budgets)
    _run_held_lock_hook(ctx, conc, budgets)
    _run_explicit_wait(ctx, conc, budgets)
    _run_stale_lock(ctx, conc, budgets)
    _run_meta_sampling(ctx, conc, budgets)
    _run_concurrent_processes(ctx, conc, budgets)
