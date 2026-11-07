from pathlib import Path
import hashlib
import statistics

from lib.runner import HarnessContext

REPO = "chipsrc"

HIT_KEYS = ("bundle_name", "kind", "file", "line", "snippet")
SNIPPET_SEPARATOR = " \u2014 "

ASSERTION_LABELS = [
    "concept: explicit --kind concept ranks structural_digest in the top 5",
    "concept: two-token concept query ranks structural_digest at index 0",
    "concept: camelCase sub-token ranking finds VendorMode in the top 5",
    "concept: automatic fallback fires on multi-token zero-hit queries",
    "concept: --source and --kind source disable concept fallback",
    "concept: nonsense multi-token and single-token queries return []",
    "concept: concept ranking is deterministic across runs and rebuilds",
    "concept: concept query compute time under 30 ms",
    "concept: concept hits resolve to valid TSV rows and honor --limit",
    "concept: no persisted concept index and search help lists the concept kind",
]


def _rows(run: dict) -> list[dict]:
    payload = run.get("json")
    if not isinstance(payload, list):
        return []
    return [row for row in payload if isinstance(row, dict)]


def _well_formed(rows: list[dict], kinds: list[str]) -> bool:
    return all(
        all(key in row for key in HIT_KEYS)
        and row.get("kind") in kinds
        and isinstance(row.get("line"), int)
        and bool(str(row.get("snippet") or "").strip())
        for row in rows
    )


def _snippet_name(row: dict) -> str:
    return str(row.get("snippet") or "").split(SNIPPET_SEPARATOR, 1)[0].strip()


def _matching_index(rows: list[dict], name: str, file: str) -> int | None:
    for index, row in enumerate(rows):
        if row.get("file") == file and _snippet_name(row) == name:
            return index
    return None


def _tuples(rows: list[dict]) -> list[tuple]:
    return [
        (row.get("kind"), row.get("file"), row.get("line"), row.get("snippet"))
        for row in rows
    ]


def _stdout_hashes(runs: list[dict]) -> list[str]:
    return [
        hashlib.sha256(str(run.get("stdout") or "").encode("utf-8", "replace")).hexdigest()
        for run in runs
    ]


def _source_line_counts(paths: set[str], source_root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel in paths:
        path = source_root / rel
        try:
            body = path.read_bytes()
        except OSError:
            counts[rel] = 0
            continue
        counts[rel] = body.count(10) + (1 if body and not body.endswith(b"\n") else 0)
    return counts


def _tsv_line(row: dict, kind: str) -> int | None:
    raw = row.get("line") if kind == "macro" else row.get("start_line")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["concept"])
    if oracles is None:
        return
    if not ctx.check_repos_available([REPO], ASSERTION_LABELS):
        return

    oracle = oracles["concept"]
    queries = oracle["queries"]
    budgets = oracle["budgets"]
    limits = oracle["limits"]
    kinds = oracle["hit_kinds"]
    top_n = int(queries["ranking_top_n"])
    source_root = ctx.repos_root / REPO

    if not ctx.ensure_repo_bundle(REPO, source_root):
        return
    bundle = ctx.bundles_dir / REPO
    if not ctx.any_label_matches(ASSERTION_LABELS):
        return

    def concept(label: str, text: str, *extra: object) -> dict:
        return ctx.run(label, "search", "-b", bundle, "--kind", "concept", text, "--json",
                       "--no-sync", *extra)

    def default(label: str, text: str, *extra: object) -> dict:
        return ctx.run(label, "search", "-b", bundle, text, "--json", "--no-sync", *extra)

    help_run = ctx.run("concept: search help", "search", "--help")
    help_text = str(help_run.get("stdout") or "")
    help_ok = help_run["exit"] == 0 and "concept" in help_text and "--kind" in help_text

    r_rank = concept("concept: ranking query", queries["ranking"])
    rank_rows = _rows(r_rank)
    rank_ok = (
        r_rank["exit"] == 0
        and bool(rank_rows)
        and _well_formed(rank_rows, kinds)
        and _matching_index(rank_rows[:top_n], queries["ranking_name"], queries["ranking_file"])
        is not None
    )
    ctx.check(
        ASSERTION_LABELS[0],
        rank_ok,
        {
            "repo": REPO,
            "rows": len(rank_rows),
            "top": _tuples(rank_rows[:top_n]),
            "expected": [queries["ranking_name"], queries["ranking_file"]],
        },
    )

    r_two = concept("concept: two-token query", queries["two_token"])
    two_rows = _rows(r_two)
    two_index = _matching_index(two_rows, queries["two_token_name"], queries["ranking_file"])
    ctx.check(
        ASSERTION_LABELS[1],
        r_two["exit"] == 0 and bool(two_rows) and two_index == 0,
        {"rows": len(two_rows), "index": two_index, "top": _tuples(two_rows[:top_n])},
    )

    r_camel = concept("concept: camelCase query", queries["camel"])
    camel_rows = _rows(r_camel)
    camel_index = _matching_index(camel_rows[:top_n], queries["camel_name"], queries["camel_file"])
    ctx.check(
        ASSERTION_LABELS[2],
        r_camel["exit"] == 0 and bool(camel_rows) and camel_index is not None,
        {"rows": len(camel_rows), "index": camel_index, "top": _tuples(camel_rows[:top_n])},
    )

    r_fb_graph = default("concept: fallback graph query", queries["fallback_graph"])
    r_fb_struct = default("concept: fallback structural query", queries["fallback_structural"])
    fb_graph_rows = _rows(r_fb_graph)
    fb_struct_rows = _rows(r_fb_struct)
    fb_graph_index = _matching_index(
        fb_graph_rows[:top_n], queries["fallback_graph_name"], queries["fallback_graph_file"]
    )
    fb_struct_index = _matching_index(
        fb_struct_rows[:top_n],
        queries["fallback_structural_name"],
        queries["fallback_structural_file"],
    )
    ctx.check(
        ASSERTION_LABELS[3],
        r_fb_graph["exit"] == 0
        and r_fb_struct["exit"] == 0
        and _well_formed(fb_graph_rows, kinds)
        and _well_formed(fb_struct_rows, kinds)
        and fb_graph_index is not None
        and fb_struct_index is not None,
        {
            "graph": {"rows": len(fb_graph_rows), "index": fb_graph_index,
                      "top": _tuples(fb_graph_rows[:top_n])},
            "structural": {"rows": len(fb_struct_rows), "index": fb_struct_index,
                           "top": _tuples(fb_struct_rows[:top_n])},
        },
    )

    r_source = ctx.run(
        "concept: literal source query", "search", "-b", bundle, "-S",
        queries["fallback_structural"], "--json", "--no-sync",
    )
    r_kind_source = ctx.run(
        "concept: kind source query", "search", "-b", bundle, "--kind", "source",
        queries["fallback_structural"], "--json", "--no-sync",
    )
    ctx.check(
        ASSERTION_LABELS[4],
        r_source["exit"] == 0
        and r_kind_source["exit"] == 0
        and r_source.get("json") == []
        and r_kind_source.get("json") == [],
        {"source": r_source.get("json"), "kind_source": r_kind_source.get("json")},
    )

    nonsense_runs = [
        concept("concept: nonsense concept query", queries["nonsense_multi"]),
        default("concept: nonsense default query", queries["nonsense_multi"]),
        concept("concept: nonsense single concept query", queries["nonsense_single"]),
        default("concept: nonsense single default query", queries["nonsense_single"]),
    ]
    nonsense_ok = all(
        run["exit"] == 0
        and run.get("json") == []
        and "panicked" not in str(run.get("stderr") or "").lower()
        for run in nonsense_runs
    )
    ctx.check(
        ASSERTION_LABELS[5],
        nonsense_ok,
        {"results": [run.get("json") for run in nonsense_runs]},
    )

    det_runs = [
        concept(f"concept: determinism run {index}", queries["ranking"])
        for index in range(int(budgets["determinism_runs"]))
    ]
    det_hashes = _stdout_hashes(det_runs)
    rebuild_bundle = ctx.sandbox_dir / "concept-rebuild" / REPO
    r_rebuild = ctx.run(
        "concept: rebuild chipsrc bundle",
        "convert",
        source_root,
        "-o",
        rebuild_bundle,
        "--timings",
    )
    r_rebuilt = ctx.run(
        "concept: rebuilt bundle query",
        "search",
        "-b",
        rebuild_bundle,
        "--kind",
        "concept",
        queries["ranking"],
        "--json",
        "--no-sync",
    )
    rebuilt_rows = _rows(r_rebuilt)
    det_ok = (
        all(run["exit"] == 0 for run in det_runs)
        and len(set(det_hashes)) == 1
        and r_rebuild["exit"] == 0
        and r_rebuilt["exit"] == 0
        and _tuples(rebuilt_rows) == _tuples(_rows(det_runs[-1]))
    )
    ctx.check(
        ASSERTION_LABELS[6],
        det_ok,
        {
            "hashes": det_hashes,
            "rebuild_exit": r_rebuild["exit"],
            "rebuilt_rows": len(rebuilt_rows),
            "rebuilt_top": _tuples(rebuilt_rows[:top_n]),
            "bundle_top": _tuples(_rows(det_runs[-1])[:top_n]),
        },
    )

    concept("concept: latency warm-up", queries["ranking"])
    concept_times = []
    content_ok = True
    for index in range(int(budgets["timing_runs"])):
        run = concept(f"concept: latency query {index}", queries["ranking"])
        concept_times.append(run["wall_ms"])
        rows = _rows(run)
        content_ok = content_ok and _matching_index(
            rows[:top_n], queries["ranking_name"], queries["ranking_file"]
        ) is not None
    spawn_times = []
    for index in range(int(budgets["spawn_runs"])):
        run = ctx.run(f"concept: spawn baseline {index}", "--version")
        spawn_times.append(run["wall_ms"])
    concept_median = statistics.median(concept_times)
    spawn_median = statistics.median(spawn_times)
    compute_median = round(concept_median - spawn_median, 2)
    ctx.check(
        ASSERTION_LABELS[7],
        content_ok and compute_median < float(budgets["concept_compute_ms"]),
        {
            "concept_wall_ms": concept_times,
            "spawn_wall_ms": spawn_times,
            "concept_median_ms": round(concept_median, 2),
            "spawn_median_ms": round(spawn_median, 2),
            "compute_median_ms": compute_median,
            "budget_ms": budgets["concept_compute_ms"],
            "content_valid": content_ok,
        },
    )

    join_limit = int(limits["join_limit"])
    r_join = concept("concept: limit join query", queries["ranking"], "--limit", join_limit)
    r_limit3 = concept("concept: limit three", queries["ranking"], "--limit", limits["limit_three"])
    r_single = concept(
        "concept: single hit", queries["ranking"], "-n", limits["single"]
    )
    r_default = concept("concept: default limit", queries["ranking"])

    join_rows = _rows(r_join)
    tables = {"symbol": "symbols", "type": "types", "macro": "macros"}
    table_cache: dict[str, list[dict]] = {}
    unresolved: list[dict] = []
    resolved = 0
    for row in join_rows:
        kind = row.get("kind")
        table = tables.get(str(kind))
        if table is None:
            unresolved.append({"row": row, "reason": "unknown kind"})
            continue
        if table not in table_cache:
            table_cache[table] = ctx.read_tsv(bundle, table)
        line = row.get("line")
        name = _snippet_name(row)
        matches = [
            candidate
            for candidate in table_cache[table]
            if candidate.get("file") == row.get("file")
            and candidate.get("name") == name
            and _tsv_line(candidate, str(kind)) == line
        ]
        if len(matches) != 1:
            unresolved.append({"row": row, "reason": f"{table} matches={len(matches)}"})
            continue
        resolved += 1

    line_counts = _source_line_counts(
        {str(row.get("file")) for row in join_rows if row.get("file")},
        source_root,
    )
    coordinate_violations = [
        row
        for row in join_rows
        if not (
            isinstance(row.get("line"), int)
            and 1 <= int(row["line"]) <= line_counts.get(str(row.get("file")), 0)
        )
    ]
    len_join = len(join_rows)
    len_limit3 = len(_rows(r_limit3))
    len_single = len(_rows(r_single))
    len_default = len(_rows(r_default))
    limits_ok = (
        r_join["exit"] == 0
        and r_limit3["exit"] == 0
        and r_single["exit"] == 0
        and r_default["exit"] == 0
        and 1 <= len_join <= join_limit
        and 0 < len_limit3 <= int(limits["limit_three"])
        and len_single == int(limits["single"])
        and 1 <= len_default <= int(limits["default_max"])
    )
    ctx.check(
        ASSERTION_LABELS[8],
        limits_ok and not unresolved and not coordinate_violations and resolved == len_join,
        {
            "rows": len_join,
            "resolved": resolved,
            "unresolved": unresolved[:5],
            "coordinate_violations": [row.get("snippet") for row in coordinate_violations[:5]],
            "lengths": {"join": len_join, "limit3": len_limit3, "single": len_single,
                        "default": len_default},
        },
    )

    index_dir = bundle / "index"
    index_files = (
        sorted(path.name for path in index_dir.iterdir() if path.is_file())
        if index_dir.is_dir()
        else []
    )
    expected_tables = sorted(oracle["expected_index_tables"])
    ctx.check(
        ASSERTION_LABELS[9],
        help_ok and index_files == expected_tables,
        {"help_has_concept": help_ok, "index_files": index_files,
         "expected_index_files": expected_tables},
    )
