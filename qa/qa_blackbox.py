from pathlib import Path
import argparse
import json
import os
import sys
import time

QA_ROOT = Path(__file__).resolve().parent
if str(QA_ROOT) not in sys.path:
    sys.path.insert(0, str(QA_ROOT))

from lib import mutate, runner
from suites import concept, cpp, dup_content, real, sfc

SUITE_REGISTRY: dict[str, object] = {
    "real": real.run_suite,
    "dup-content": dup_content.run_suite,
    "concept": concept.run_suite,
    "cpp": cpp.run_suite,
    "sfc": sfc.run_suite,
}

CORE_ORDER = ["real", "dup-content", "concept", "cpp", "sfc"]


def qualify_failed_label(suite_name: str, label: str) -> str:
    prefix = f"{suite_name}:"
    return label if label.startswith(prefix) else f"{prefix} {label}"


SUITE_HELP_TEXT = "\n".join(
    [
        "Available suites:",
        "  core         Alias expanding to: real, dup-content, concept, cpp, sfc",
        "  real         Repository inspection, determinism, coordinates, and 1-turn queries",
        "  dup-content  Duplicate-content per-file cache shard disambiguation on checked-in fixtures",
        "  concept      Deterministic BM25 concept search and multi-token fallback",
        "  cpp          C++ header classification, class templates, namespaces, out-of-line methods",
        "  sfc          Standalone JSX, Vue, and Svelte single-file component extraction and sync",
    ]
)


def build_parser() -> argparse.ArgumentParser:
    default_exe = "chipsrc.exe" if os.name == "nt" else "chipsrc"
    default_bin = QA_ROOT.parent / "target" / "release" / default_exe
    default_repos_root = QA_ROOT.parent.parent
    default_out = QA_ROOT / "results"

    parser = argparse.ArgumentParser(
        prog="qa_blackbox.py",
        description="Reproducible black-box CLI verification harness for chipsrc.",
        epilog=SUITE_HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--bin",
        default=str(default_bin),
        help="Path to the chipsrc executable under test.",
    )
    parser.add_argument(
        "--repos-root",
        default=str(default_repos_root),
        help="Root directory containing the chipsrc repository checkout.",
    )
    parser.add_argument(
        "--out",
        default=str(default_out),
        help="Output directory for <suite>-results.json, summary.json, bundles/, fixture-bundles/, and sandboxes/.",
    )
    parser.add_argument(
        "--suite",
        action="append",
        dest="suites",
        metavar="SUITE",
        help="Suite to run (repeatable): core, real, dup-content, concept, cpp, sfc.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Run/record only assertions whose label matches PATTERN (case-insensitive substring; repeatable).",
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Skip assertions whose label matches PATTERN (case-insensitive substring; repeatable).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="Per-command subprocess timeout in seconds (default: 120.0).",
    )
    parser.add_argument(
        "--fixtures-mode",
        choices=["build", "require"],
        default="build",
        help="Whether to build missing/stale fixture bundles ('build', default) or fail if absent ('require').",
    )
    parser.add_argument(
        "--keep-sandboxes",
        action="store_true",
        default=False,
        help="Preserve per-suite <out>/sandboxes/<suite>-<timestamp>/ directories after a successful run.",
    )
    parser.add_argument(
        "positional_suites",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    return parser


def resolve_bin_path(raw_bin: str) -> Path:
    candidate = Path(raw_bin)
    if candidate.is_absolute():
        return candidate
    if candidate.exists():
        return candidate.resolve()
    repo_relative = QA_ROOT.parent / candidate
    if repo_relative.exists():
        return repo_relative.resolve()
    return candidate.resolve()


def resolve_suites(
    parser: argparse.ArgumentParser,
    raw_suites: list[str],
) -> list[str]:
    requested = raw_suites if raw_suites else ["core"]
    expanded: list[str] = []
    for item in requested:
        for part in item.split(","):
            name = part.strip()
            if not name:
                continue
            if name == "core":
                for member in CORE_ORDER:
                    if member in SUITE_REGISTRY and member not in expanded:
                        expanded.append(member)
            elif name in SUITE_REGISTRY:
                if name not in expanded:
                    expanded.append(name)
            else:
                valid = ["core", *SUITE_REGISTRY.keys()]
                parser.error(
                    f"Unknown suite '{name}'. Valid suites: {', '.join(valid)}"
                )
    return expanded


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    raw_suites = (args.suites or []) + (args.positional_suites or [])
    suites_to_run = resolve_suites(parser, raw_suites)

    if args.timeout <= 0:
        parser.error("--timeout must be > 0")

    bin_path = resolve_bin_path(args.bin)
    repos_root = Path(args.repos_root).resolve()
    out_dir = Path(args.out).resolve()
    oracles_dir = QA_ROOT / "oracles"
    fixtures_dir = QA_ROOT / "fixtures"

    out_dir.mkdir(parents=True, exist_ok=True)

    overall_started = time.perf_counter()
    suites_summary: dict[str, dict] = {}
    all_surfaced_probes: list[dict] = []
    all_failed_labels: list[str] = []

    total_records = 0
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    total_assertions = 0
    total_assertions_passed = 0
    total_assertions_failed = 0
    total_assertions_skipped = 0

    for suite_name in suites_to_run:
        suite_started = time.perf_counter()
        ctx = runner.HarnessContext(
            suite_name=suite_name,
            bin_path=bin_path,
            repos_root=repos_root,
            out_dir=out_dir,
            oracles_dir=oracles_dir,
            fixtures_dir=fixtures_dir,
            only_patterns=args.only,
            skip_patterns=args.skip,
            timeout=args.timeout,
            fixtures_mode=args.fixtures_mode,
        )
        ctx.changed_write = mutate.changed_write
        ctx.mutate_same_second = mutate.mutate_same_second

        suite_fn = SUITE_REGISTRY[suite_name]
        try:
            suite_fn(ctx)
        except Exception as exc:
            ctx.check(
                f"{suite_name}: unexpected error",
                False,
                f"{type(exc).__name__}: {exc}",
            )
        ctx.save()

        suite_wall_ms = round((time.perf_counter() - suite_started) * 1000, 2)
        records = ctx.results

        s_passed = sum(1 for r in records if r.get("status") == "passed")
        s_failed = sum(1 for r in records if r.get("status") == "failed")
        s_skipped = sum(1 for r in records if r.get("status") == "skipped")
        s_total = len(records)

        if s_failed == 0 and not args.keep_sandboxes:
            ctx.cleanup_sandbox()

        a_records = [r for r in records if r.get("kind") == "assertion"]
        a_passed = sum(1 for r in a_records if r.get("status") == "passed")
        a_failed = sum(1 for r in a_records if r.get("status") == "failed")
        a_skipped = sum(1 for r in a_records if r.get("status") == "skipped")
        a_total = len(a_records)
        inv_total = sum(
            1 for r in records if r.get("kind") in ("invocation", "probe")
        )

        label_map = {r["label"]: r for r in records if "label" in r}
        for probe in ctx.surfaced_probes:
            paired_lbl = probe.get("paired_assertion")
            if paired_lbl and paired_lbl in label_map:
                probe["paired_passed"] = label_map[paired_lbl].get("passed")
            all_surfaced_probes.append(probe)

        s_failed_labels = [
            r["label"] for r in records if r.get("status") == "failed"
        ]
        all_failed_labels.extend(
            qualify_failed_label(suite_name, lbl) for lbl in s_failed_labels
        )

        suites_summary[suite_name] = {
            "suite": suite_name,
            "total": s_total,
            "records": s_total,
            "passed": s_passed,
            "failed": s_failed,
            "skipped": s_skipped,
            "assertions": a_total,
            "assertions_passed": a_passed,
            "assertions_failed": a_failed,
            "assertions_skipped": a_skipped,
            "invocations": inv_total,
            "failed_labels": s_failed_labels,
            "wall_ms": suite_wall_ms,
            "results_file": f"{suite_name}-results.json",
        }

        total_records += s_total
        total_passed += s_passed
        total_failed += s_failed
        total_skipped += s_skipped

        total_assertions += a_total
        total_assertions_passed += a_passed
        total_assertions_failed += a_failed
        total_assertions_skipped += a_skipped

    overall_wall_ms = round((time.perf_counter() - overall_started) * 1000, 2)
    summary = {
        "suites": suites_summary,
        "suite_names": suites_to_run,
        "total": total_records,
        "records": total_records,
        "passed": total_passed,
        "failed": total_failed,
        "failures": total_failed,
        "skipped": total_skipped,
        "assertions_total": total_assertions,
        "assertions_passed": total_assertions_passed,
        "assertions_failed": total_assertions_failed,
        "assertions_skipped": total_assertions_skipped,
        "failed_labels": all_failed_labels,
        "surfaced_probes": all_surfaced_probes,
        "wall_ms": overall_wall_ms,
    }

    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        f"Summary: {total_assertions_passed} assertions passed, "
        f"{total_assertions_failed} failed, {total_assertions_skipped} skipped "
        f"({total_records} total records across {', '.join(suites_to_run)} in {overall_wall_ms} ms)"
    )
    print(json.dumps(summary, indent=2))
    return 1 if total_failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
