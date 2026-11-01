"""Focused line-count and incremental-sync timing suite (2 assertions + 1 observational)."""
import difflib
import shutil
import statistics

from lib.runner import HarnessContext

REPOS = ["smart_locker"]

ASSERTION_LABELS = [
    "Incremental and forced source line counts agree",
    "Performance edits only parse one file",
]


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(REPOS)
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ASSERTION_LABELS):
        return

    foc = oracles["smart_locker"]["focused"]

    source = ctx.sandbox_dir / "copies" / "linecount"
    source.mkdir(parents=True, exist_ok=True)
    original = ctx.repos_root / "smart_locker" / foc["linecount_file"]
    target = source / original.name
    shutil.copy2(original, target)

    bundle = ctx.sandbox_dir / "focused-bundles" / "linecount"
    ctx.run("Line count initial index", "convert", source, "-o", bundle, "--timings")
    ctx.changed_write(
        target,
        foc["linecount_comment"] + target.read_text(encoding="utf-8"),
    )
    ctx.run("Line count incremental update", "convert", source, "-o", bundle, "--timings")
    incremental_meta = ctx.read_meta(bundle)
    sections_dir = bundle / "sections"
    before = (
        {p.name: p.read_text(encoding="utf-8") for p in sections_dir.glob("*.md")}
        if sections_dir.is_dir()
        else {}
    )
    ctx.run(
        "Line count full update",
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    forced_meta = ctx.read_meta(bundle)
    inc_lines = incremental_meta.get("total_lines")
    frc_lines = forced_meta.get("total_lines")
    ctx.check(
        "Incremental and forced source line counts agree",
        inc_lines is not None and inc_lines == frc_lines,
        {
            "incremental": inc_lines,
            "forced": frc_lines,
            "actual_splitlines": len(target.read_text(encoding="utf-8").splitlines()),
            "newline_count": target.read_bytes().count(b"\n"),
        },
    )
    if sections_dir.is_dir():
        for path in sections_dir.glob("*.md"):
            if path.name in before:
                diff = "".join(
                    difflib.unified_diff(
                        before[path.name].splitlines(True),
                        path.read_text(encoding="utf-8").splitlines(True),
                        fromfile="incremental/" + path.name,
                        tofile="forced/" + path.name,
                    )
                )
                if diff:
                    (ctx.sandbox_dir / "linecount.diff").write_text(
                        diff,
                        encoding="utf-8",
                    )

    perf_source = ctx.copy_corpus("smart_locker", "locker-performance")
    perf_bundle = ctx.sandbox_dir / "focused-bundles" / "locker-performance"
    ctx.run(
        "Performance initial index",
        "convert",
        perf_source,
        "-o",
        perf_bundle,
        "--timings",
    )
    perf_target = perf_source / foc["perf_target_file"]
    measurements = []
    prefix = foc["perf_symbol_prefix"]
    for index in range(foc["perf_iterations"]):
        warm = ctx.run(
            f"Performance warm {index}",
            "convert",
            perf_source,
            "-o",
            perf_bundle,
            "--timings",
        )
        name = (
            foc["perf_initial_symbol"]
            if index == 0
            else f"{prefix}{index - 1:02d}"
        )
        new_name = f"{prefix}{index:02d}"
        if perf_target.is_file():
            ctx.changed_write(
                perf_target,
                perf_target.read_text(encoding="utf-8").replace(name, new_name),
            )
        updated = ctx.run(
            f"Performance edit {index}",
            "convert",
            perf_source,
            "-o",
            perf_bundle,
            "--timings",
        )
        meta = ctx.read_meta(perf_bundle)
        measurements.append(
            {
                "warm_wall_ms": warm["wall_ms"],
                "edit_wall_ms": updated["wall_ms"],
                "edit_core_ms": meta.get("elapsed_ms", 0),
                "parse_ms": meta.get("parse_ms", 0),
                "emit_ms": meta.get("emit_ms", 0),
                "reparsed": meta.get("incremental_reparsed_files"),
            }
        )
    ctx.check(
        "Performance edits only parse one file",
        bool(measurements)
        and all(x["reparsed"] == foc["perf_expected_reparsed"] for x in measurements),
    )
    ctx.record_observational(
        "Performance measurements (observational)",
        {
            "measurements": measurements,
            "median_edit_core_ms": (
                statistics.median(x["edit_core_ms"] for x in measurements)
                if measurements
                else 0
            ),
            "median_edit_wall_ms": (
                statistics.median(x["edit_wall_ms"] for x in measurements)
                if measurements
                else 0
            ),
            "median_warm_wall_ms": (
                statistics.median(x["warm_wall_ms"] for x in measurements)
                if measurements
                else 0
            ),
        },
    )
