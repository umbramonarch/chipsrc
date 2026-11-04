"""C++ coverage suite: checked-in fixtures, ETL headers/templates/methods, STM32 sanity.

Fixture sources live in `qa/fixtures/cpp/` (self-written, no third-party code); the ETL and
STM32CubeF4 expectations are externalized in `qa/oracles/cpp.json`. The ETL cold conversion
runs under the mission-wide `<corpus-root>/validators/.large-convert.lock` guard so it never
overlaps another large-corpus convert.
"""
from pathlib import Path
import json
import re
import subprocess

from lib import procs
from lib.lockguard import LargeConvertLock, default_lock_path
from lib.runner import HarnessContext

QA_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = QA_ROOT.parent

FIXTURE_LABELS = [
    "cpp: fixture sources cover templates, namespace, nested class, alias, operators, ctor, and dtor",
    "cpp: fixture constructs extracted with expected kinds and coordinates",
    "cpp: plain-C header with C++ keywords only in comments and strings stays C",
]

ETL_LABELS = [
    "cpp: etl headers classified as C++ by content",
    "cpp: etl clean-parse ratio at least 0.90",
    "cpp: etl cold convert link within budget",
    "cpp: etl class template ivector and namespace-qualified symbols extracted",
    "cpp: etl out-of-line methods carry enclosing type and coordinates",
    "cpp: etl callers and callees resolve across a template class",
    "cpp: etl long template parameter lists collapse to template<...>",
]

STM32_LABELS = [
    "cpp: STM32CubeF4 is not mass-reclassified as C++",
]

ASSERTION_LABELS = [*FIXTURE_LABELS, *ETL_LABELS, *STM32_LABELS]

TEMPLATE_RE = re.compile(r"template\s*<")


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


def _json_rows(run: dict) -> list[dict]:
    payload = run.get("json")
    if not isinstance(payload, list):
        return []
    return [row for row in payload if isinstance(row, dict)]


def _language_map(inspect_payload: object) -> dict[str, dict]:
    if not isinstance(inspect_payload, dict):
        return {}
    languages = inspect_payload.get("languages")
    if not isinstance(languages, list):
        return {}
    return {
        str(entry.get("language")): entry
        for entry in languages
        if isinstance(entry, dict) and entry.get("language")
    }


def _source_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _identifier_span_ok(root: Path, file_rel: str, name: str, start: int, end: int) -> bool:
    """The identifier must appear inside the reported `[start_line, end_line]` span."""
    lines = _source_lines(root / file_rel)
    if start < 1 or end < start or end > len(lines):
        return False
    return any(name in line for line in lines[start - 1:end])


def _git_tracked(root: Path, rel_dir: str) -> set[str] | None:
    """`git ls-files` inside the harness repository, or None when git is unavailable."""
    if not (root / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--", rel_dir],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {
        line.strip().replace("\\", "/")
        for line in proc.stdout.splitlines()
        if line.strip()
    }


def _raw_template_params(text: str) -> str | None:
    match = TEMPLATE_RE.search(text)
    if match is None:
        return None
    depth = 0
    index = match.end() - 1
    while index < len(text):
        char = text[index]
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth == 0:
                return text[match.start():index + 1]
        index += 1
    return None


def _fixture_assertions(
    ctx: HarnessContext,
    fixture: dict,
    fixture_src: Path,
    bundle: Path,
) -> None:
    required = [str(rel) for rel in fixture["files"]]
    missing = [rel for rel in required if not (fixture_src / rel).is_file()]
    fixture_rel = f"qa/fixtures/{fixture['name']}"
    tracked = _git_tracked(REPO_ROOT, fixture_rel)
    tracking_ok = tracked is None or all(
        f"{fixture_rel}/{rel}" in tracked for rel in required
    )
    ctx.check(
        FIXTURE_LABELS[0],
        not missing and tracking_ok,
        {
            "fixture_dir": str(fixture_src),
            "missing": missing,
            "git_tracked": sorted(tracked) if tracked is not None else "not verified (no git repository)",
            "tracking_ok": tracking_ok,
        },
    )
    if not ctx.ensure_fixture_bundle(str(fixture["name"]), fixture_src):
        return

    inspect_run = ctx.run("cpp: fixture inspect", "inspect", fixture_src, "--json")
    languages = _language_map(inspect_run.get("json"))
    inspect_payload = inspect_run.get("json") if isinstance(inspect_run.get("json"), dict) else {}
    expected_languages = {str(key): int(value) for key, value in fixture["languages"].items()}
    actual_languages = {
        name: int(entry.get("files") or 0)
        for name, entry in languages.items()
        if int(entry.get("files") or 0) > 0
    }

    type_rows = ctx.read_tsv(bundle, "types")
    symbol_rows = ctx.read_tsv(bundle, "symbols")

    def type_row(spec: dict) -> list[dict]:
        return [
            row
            for row in type_rows
            if row.get("name") == spec["name"]
            and row.get("file") == spec["file"]
            and str(row.get("type_id") or "").endswith(spec["type_id_contains"])
        ]

    def symbol_row(spec: dict, id_contains: str | None = None) -> list[dict]:
        return [
            row
            for row in symbol_rows
            if row.get("file") == spec["file"]
            and row.get("name") == spec.get("name")
            and (id_contains is None or id_contains in str(row.get("symbol_id") or ""))
        ]

    checks: dict[str, bool] = {}

    template_type = fixture["template_type"]
    rows = type_row(template_type)
    checks["template_type"] = bool(rows) and rows[0].get("kind") in template_type["kinds"]
    template_start = int(rows[0].get("start_line") or 0) if rows else 0
    template_end = int(rows[0].get("end_line") or 0) if rows else 0
    checks["template_type_coords"] = (
        template_start == int(template_type["start_line"])
        and template_end >= int(template_type["min_end_line"])
        and _identifier_span_ok(
            fixture_src, template_type["file"], template_type["name"], template_start, template_end
        )
    )

    nested_type = fixture["nested_type"]
    rows = type_row(nested_type)
    checks["nested_type"] = bool(rows) and rows[0].get("kind") in nested_type["kinds"]
    checks["nested_type_coords"] = bool(rows) and (
        int(rows[0].get("start_line") or 0) == int(nested_type["start_line"])
        and _identifier_span_ok(
            fixture_src,
            nested_type["file"],
            nested_type["name"],
            int(rows[0]["start_line"]),
            int(rows[0]["end_line"]),
        )
    )

    alias = fixture["alias"]
    rows = [
        row
        for row in type_rows
        if row.get("name") == alias["name"]
        and row.get("file") == alias["file"]
        and row.get("kind") == alias["kind"]
    ]
    checks["alias"] = bool(rows) and int(rows[0].get("start_line") or 0) == int(alias["start_line"])
    checks["alias_coords"] = checks["alias"] and _identifier_span_ok(
        fixture_src,
        alias["file"],
        alias["name"],
        int(rows[0]["start_line"]),
        int(rows[0]["end_line"]),
    )

    plain_type = fixture["plain_type"]
    rows = [
        row
        for row in type_rows
        if row.get("name") == plain_type["name"]
        and row.get("file") == plain_type["file"]
        and row.get("kind") == plain_type["kind"]
    ]
    checks["plain_type"] = bool(rows) and int(rows[0].get("start_line") or 0) == int(
        plain_type["start_line"]
    )

    ctor = fixture["ctor"]
    rows = symbol_row(ctor, ctor["symbol_id_contains"])
    checks["ctor"] = (
        bool(rows)
        and rows[0].get("kind") == ctor["kind"]
        and int(rows[0].get("start_line") or 0) == int(ctor["start_line"])
        and _identifier_span_ok(
            fixture_src, ctor["file"], ctor["name"],
            int(rows[0]["start_line"]), int(rows[0]["end_line"]),
        )
    )

    dtor = fixture["dtor"]
    rows = [
        row
        for row in symbol_rows
        if row.get("file") == dtor["file"]
        and dtor["signature_contains"] in str(row.get("signature") or "")
    ]
    checks["dtor"] = bool(rows) and int(rows[0].get("start_line") or 0) == int(dtor["start_line"])

    out_of_line = fixture["out_of_line"]
    rows = symbol_row(out_of_line, out_of_line["symbol_id_contains"])
    checks["out_of_line"] = (
        bool(rows)
        and rows[0].get("kind") == out_of_line["kind"]
        and int(rows[0].get("start_line") or 0) == int(out_of_line["start_line"])
        and _identifier_span_ok(
            fixture_src, out_of_line["file"], out_of_line["name"],
            int(rows[0]["start_line"]), int(rows[0]["end_line"]),
        )
    )

    nested_out_of_line = fixture["nested_out_of_line"]
    rows = symbol_row(nested_out_of_line, nested_out_of_line["symbol_id_contains"])
    checks["nested_out_of_line"] = (
        bool(rows)
        and rows[0].get("kind") == nested_out_of_line["kind"]
        and int(rows[0].get("start_line") or 0) == int(nested_out_of_line["start_line"])
        and _identifier_span_ok(
            fixture_src, nested_out_of_line["file"], nested_out_of_line["name"],
            int(rows[0]["start_line"]), int(rows[0]["end_line"]),
        )
    )

    operator = fixture["operator"]
    rows = [
        row
        for row in symbol_rows
        if row.get("file") == operator["file"]
        and operator["signature_contains"] in str(row.get("signature") or "")
    ]
    checks["operator"] = bool(rows) and int(rows[0].get("start_line") or 0) == int(
        operator["start_line"]
    )

    template_operator = fixture["template_operator"]
    rows = [
        row
        for row in symbol_rows
        if row.get("name") == template_operator["name"]
        and row.get("file") == template_operator["file"]
    ]
    checks["template_operator"] = (
        bool(rows)
        and int(rows[0].get("start_line") or 0) == int(template_operator["start_line"])
        and str(rows[0].get("signature") or "").startswith(template_operator["signature_prefix"])
        and len(str(rows[0].get("signature") or ""))
        <= int(fixture["template_signature_max_len"])
    )

    plain_symbol = fixture["plain_symbol"]
    rows = [
        row
        for row in symbol_rows
        if row.get("name") == plain_symbol["name"]
        and row.get("file") == plain_symbol["file"]
        and row.get("kind") == plain_symbol["kind"]
    ]
    checks["plain_symbol"] = bool(rows) and int(rows[0].get("start_line") or 0) == int(
        plain_symbol["start_line"]
    )

    ctx.check(
        FIXTURE_LABELS[1],
        all(checks.values()),
        {"checks": checks},
    )

    comment_only = set(fixture["comment_only_identifiers"])
    leaked = [
        {"table": table, "name": row.get("name"), "file": row.get("file")}
        for table, rows in (("types", type_rows), ("symbols", symbol_rows))
        for row in rows
        if row.get("file") == fixture["plain_header"] and row.get("name") in comment_only
    ]
    language_ok = actual_languages == expected_languages
    ctx.check(
        FIXTURE_LABELS[2],
        language_ok
        and int(inspect_payload.get("total_files") or 0) == int(fixture["total_files"])
        and not leaked,
        {
            "languages": actual_languages,
            "expected_languages": expected_languages,
            "total_files": inspect_payload.get("total_files"),
            "leaked_comment_only_symbols": leaked,
            "plain_header": fixture["plain_header"],
        },
    )


def _run_etl(ctx: HarnessContext, etl: dict, budgets: dict) -> None:
    corpus = ctx.corpus_root / str(etl["repo"])
    sandbox = ctx.sandbox_dir / "cpp-bundles"
    bundle = sandbox / str(etl["repo"])

    inspect_run = ctx.run("cpp: ETL inspect", "inspect", corpus, "--json")
    languages = _language_map(inspect_run.get("json"))
    inspect_payload = inspect_run.get("json") if isinstance(inspect_run.get("json"), dict) else {}
    first_party = sum(int(entry.get("first_party_files") or 0) for entry in languages.values())
    cpp_entry = languages.get("cpp", {})
    c_entry = languages.get("c", {})
    ctx.check(
        ETL_LABELS[0],
        inspect_run["exit"] == 0
        and int(inspect_payload.get("total_files") or 0) == int(etl["total_files"])
        and int(cpp_entry.get("first_party_files") or 0) >= int(etl["cpp_first_party_min"])
        and int(etl["c_first_party_min"])
        <= int(c_entry.get("first_party_files") or 0)
        <= int(etl["c_first_party_max"])
        and first_party == int(etl["first_party_total"]),
        {
            "repo": str(etl["repo"]),
            "total_files": inspect_payload.get("total_files"),
            "cpp_first_party": cpp_entry.get("first_party_files"),
            "cpp_min": etl["cpp_first_party_min"],
            "c_first_party": c_entry.get("first_party_files"),
            "c_range": [etl["c_first_party_min"], etl["c_first_party_max"]],
            "first_party_total": first_party,
            "expected_first_party_total": etl["first_party_total"],
        },
    )

    convert_run = ctx.run(
        "cpp: ETL cold convert",
        "convert",
        corpus,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    timings = procs.parse_timings(convert_run["stdout"])
    meta = _read_meta_full(bundle)
    metadata = meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
    sanity = meta.get("sanity") if isinstance(meta.get("sanity"), dict) else {}
    parse_ratio = sanity.get("parse_clean_ratio")
    warnings = sanity.get("warnings")
    warning_list = warnings if isinstance(warnings, list) else []
    ctx.check(
        ETL_LABELS[1],
        convert_run["exit"] == 0
        and parse_ratio is not None
        and float(parse_ratio) >= float(etl["parse_clean_ratio_min"])
        and int(metadata.get("total_files") or 0) == int(etl["total_files"]),
        {
            "repo": str(etl["repo"]),
            "parse_clean_ratio": parse_ratio,
            "min": etl["parse_clean_ratio_min"],
            "total_files": metadata.get("total_files"),
            "warning_count": len(warning_list),
            "warnings": warning_list[:3],
        },
    )
    ctx.check(
        ETL_LABELS[2],
        convert_run["exit"] == 0
        and "INDEXED" in convert_run["stdout"]
        and timings.get("link", 1 << 30) <= int(budgets["etl_link_ms"]),
        {
            "repo": str(etl["repo"]),
            "link_ms": timings.get("link"),
            "link_budget_ms": budgets["etl_link_ms"],
            "total_ms": timings.get("total"),
            "call_edge_count": metadata.get("call_edge_count"),
        },
    )

    template_type = etl["template_type"]
    type_runs = [
        ctx.run("cpp: type ivector", "type", "-b", bundle, "ivector", "--json", "--no-sync"),
        ctx.run("cpp: type etl::ivector", "type", "-b", bundle, "etl::ivector", "--json", "--no-sync"),
    ]
    type_matches: list[dict] = []
    type_ok = True
    for run in type_runs:
        rows = [
            row
            for row in _json_rows(run)
            if row.get("name") == template_type["name"]
            and row.get("file") == template_type["file"]
            and row.get("kind") in template_type["kinds"]
            and template_type["type_id_contains"] in str(row.get("type_id") or "")
        ]
        if rows:
            type_matches = rows
        type_ok = type_ok and run["exit"] == 0 and bool(rows)
    best_type = type_matches[0] if type_matches else {}
    start_line = int(best_type.get("start_line") or 0)
    end_line = int(best_type.get("end_line") or 0)
    type_ok = (
        type_ok
        and bool(best_type)
        and int(template_type["start_line_min"]) <= start_line <= int(template_type["start_line_max"])
        and end_line >= int(template_type["min_end_line"])
        and bool(str(best_type.get("fields_summary") or "").strip())
        and _identifier_span_ok(
            ctx.corpus_root / str(etl["repo"]),
            str(template_type["file"]),
            str(template_type["name"]),
            start_line,
            end_line,
        )
    )

    template_method = etl["template_method"]
    method_run = ctx.run(
        "cpp: sym template method",
        "sym",
        "-b",
        bundle,
        template_method["query"],
        "--json",
        "--no-sync",
    )
    method_rows = [
        row
        for row in _json_rows(method_run)
        if row.get("name") == template_method["name"]
        and row.get("kind") == template_method["kind"]
        and row.get("file") == template_method["file"]
        and template_method["symbol_id_contains"] in str(row.get("symbol_id") or "")
    ]
    method_ok = method_run["exit"] == 0 and any(
        int(row.get("start_line") or 0) in {int(line) for line in template_method["start_lines"]}
        for row in method_rows
    )
    ctx.check(
        ETL_LABELS[3],
        type_ok and method_ok,
        {
            "repo": str(etl["repo"]),
            "type": {
                "name": best_type.get("name"),
                "file": best_type.get("file"),
                "kind": best_type.get("kind"),
                "type_id": best_type.get("type_id"),
                "start_line": best_type.get("start_line"),
                "end_line": best_type.get("end_line"),
                "fields_summary": best_type.get("fields_summary"),
            },
            "methods": [
                {"symbol_id": row.get("symbol_id"), "start_line": row.get("start_line")}
                for row in method_rows
            ],
            "type_ok": type_ok,
            "method_ok": method_ok,
        },
    )

    out_of_line_ok = True
    out_of_line_detail: list[dict] = []
    for index, spec in enumerate(etl["out_of_line"]):
        run = ctx.run(
            f"cpp: out-of-line query {index}",
            "sym",
            "-b",
            bundle,
            spec["query"],
            "--json",
            "--no-sync",
        )
        rows = [
            row
            for row in _json_rows(run)
            if row.get("kind") == "method"
            and row.get("file") == spec["file"]
            and str(row.get("symbol_id") or "").endswith(spec["symbol_id_suffix"])
        ]
        row_ok = bool(rows) and (
            int(rows[0].get("start_line") or 0) == int(spec["start_line"])
            and int(rows[0].get("end_line") or 0) >= int(spec["start_line"])
            and spec["signature_contains"] in str(rows[0].get("signature") or "")
            and _identifier_span_ok(
                ctx.corpus_root / str(etl["repo"]),
                str(spec["file"]),
                str(rows[0].get("name") or ""),
                int(rows[0].get("start_line") or 0),
                int(rows[0].get("end_line") or 0),
            )
        )
        out_of_line_ok = out_of_line_ok and run["exit"] == 0 and row_ok
        out_of_line_detail.append(
            {
                "query": spec["query"],
                "start_line": rows[0].get("start_line") if rows else None,
                "expected_start_line": spec["start_line"],
                "signature": rows[0].get("signature") if rows else None,
                "ok": row_ok,
            }
        )
    ctx.check(
        ETL_LABELS[4],
        out_of_line_ok,
        {"rows": out_of_line_detail},
    )

    call_graph = etl["call_graph"]
    callees_run = ctx.run(
        "cpp: callees across template class",
        "callees",
        "-b",
        bundle,
        call_graph["callee_query"],
        "--json",
        "--no-sync",
        "--limit",
        100,
    )
    callees_rows = [
        row
        for row in _json_rows(callees_run)
        if row.get("callee_name") == call_graph["callee_name"]
        and row.get("file") == call_graph["file"]
        and int(row.get("line") or 0) == int(call_graph["line"])
        and row.get("tier") != "external_or_macro"
    ]
    callers_run = ctx.run(
        "cpp: callers across template class",
        "callers",
        "-b",
        bundle,
        call_graph["caller_query"],
        "--json",
        "--no-sync",
        "--limit",
        200,
    )
    callers_rows = [
        row
        for row in _json_rows(callers_run)
        if call_graph["caller_id_contains"] in str(row.get("caller_id") or "")
        and row.get("file") == call_graph["file"]
        and int(row.get("line") or 0) == int(call_graph["line"])
    ]
    ctx.check(
        ETL_LABELS[5],
        callees_run["exit"] == 0
        and callers_run["exit"] == 0
        and bool(callees_rows)
        and bool(callers_rows),
        {
            "callees": callees_rows[:3],
            "callers": callers_rows[:3],
            "callee_rows": len(callees_rows),
            "caller_rows": len(callers_rows),
        },
    )

    collapse = etl["template_collapse"]
    before = int(collapse["window_before"])
    after = int(collapse["window_after"])
    raw_min = int(collapse["raw_param_min_len"])
    symbol_rows = ctx.read_tsv(bundle, "symbols")
    source_root = ctx.corpus_root / str(etl["repo"])
    line_cache: dict[str, list[str]] = {}
    collapse_rows = 0
    violations: list[dict] = []
    for row in symbol_rows:
        try:
            start = int(row.get("start_line") or 0)
        except (TypeError, ValueError):
            continue
        file_rel = str(row.get("file") or "")
        if not file_rel:
            continue
        if file_rel not in line_cache:
            line_cache[file_rel] = _source_lines(source_root / file_rel)
        lines = line_cache[file_rel]
        if start < 1 or start > len(lines):
            continue
        window = "\n".join(lines[max(0, start - before):start + after])
        raw_params = _raw_template_params(window)
        if raw_params is None:
            continue
        normalized = " ".join(raw_params.split())
        if len(normalized) <= raw_min:
            continue
        collapse_rows += 1
        signature = str(row.get("signature") or "")
        if (
            not signature.startswith(collapse["signature_prefix"])
            or len(signature) > int(collapse["signature_max_len"])
            or normalized in signature
        ):
            violations.append(
                {
                    "file": file_rel,
                    "name": row.get("name"),
                    "start_line": start,
                    "raw_param_len": len(normalized),
                    "signature": signature[:160],
                }
            )
    ctx.check(
        ETL_LABELS[6],
        collapse_rows >= int(collapse["min_rows"]) and not violations,
        {
            "rows": collapse_rows,
            "min_rows": collapse["min_rows"],
            "violations": violations[:10],
            "violation_count": len(violations),
        },
    )


def _run_stm32(ctx: HarnessContext, stm32: dict) -> None:
    corpus = ctx.corpus_root / str(stm32["repo"])
    run = ctx.run("cpp: STM32 inspect", "inspect", corpus, "--json")
    languages = _language_map(run.get("json"))
    payload = run.get("json") if isinstance(run.get("json"), dict) else {}
    c_entry = languages.get("c", {})
    ctx.check(
        STM32_LABELS[0],
        run["exit"] == 0
        and "panicked" not in str(run.get("stderr") or "").lower()
        and int(payload.get("total_files") or 0) == int(stm32["total_files"])
        and int(c_entry.get("files") or 0) >= int(stm32["c_files_min"]),
        {
            "repo": str(stm32["repo"]),
            "total_files": payload.get("total_files"),
            "c_files": c_entry.get("files"),
            "c_files_min": stm32["c_files_min"],
            "cpp_files": languages.get("cpp", {}).get("files"),
        },
    )


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["cpp", "perf"])
    if oracles is None:
        return
    cpp = oracles["cpp"]
    budgets = {**oracles["perf"]["scale"]["budgets"], **cpp["budgets"]}
    fixture = cpp["fixture"]
    fixture_src = ctx.fixtures_dir / str(fixture["name"])

    if not fixture_src.is_dir():
        ctx.check(
            FIXTURE_LABELS[0],
            False,
            f"missing fixture directory at {fixture_src}",
        )
        return
    bundle = ctx.fixture_bundles_dir / str(fixture["name"])
    _fixture_assertions(ctx, fixture, fixture_src, bundle)

    etl_available = ctx.check_repos_available(
        [str(cpp["etl"]["repo"])], ETL_LABELS, use_corpus_root=True
    )
    stm32_available = ctx.check_repos_available(
        [str(cpp["stm32"]["repo"])], STM32_LABELS, use_corpus_root=True
    )
    if not etl_available and not stm32_available:
        return

    guard = LargeConvertLock(
        default_lock_path(ctx.corpus_root),
        wait_seconds=float(budgets["lock_wait_s"]),
        stale_seconds=float(budgets["lock_stale_s"]),
        owner="qa-cpp",
    )
    acquired, reason = guard.acquire()
    if not acquired:
        if etl_available:
            for label in ETL_LABELS:
                ctx.skip_record(label, reason)
        if stm32_available:
            for label in STM32_LABELS:
                ctx.skip_record(label, reason)
        return

    previous_timeout = ctx.timeout
    ctx.timeout = max(previous_timeout, float(budgets["command_timeout_s"]))
    try:
        if etl_available:
            _run_etl(ctx, cpp["etl"], budgets)
        if stm32_available:
            _run_stm32(ctx, cpp["stm32"])
    finally:
        ctx.timeout = previous_timeout
        guard.release()
