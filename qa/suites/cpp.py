from pathlib import Path
import subprocess

from lib.runner import HarnessContext

QA_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = QA_ROOT.parent

FIXTURE_LABELS = [
    "cpp: fixture sources cover templates, namespace, nested class, alias, operators, ctor, and dtor",
    "cpp: fixture constructs extracted with expected kinds and coordinates",
    "cpp: plain-C header with C++ keywords only in comments and strings stays C",
]

ASSERTION_LABELS = [*FIXTURE_LABELS]


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
    lines = _source_lines(root / file_rel)
    if start < 1 or end < start or end > len(lines):
        return False
    return any(name in line for line in lines[start - 1:end])


def _git_tracked(root: Path, rel_dir: str) -> set[str] | None:
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


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["cpp"])
    if oracles is None:
        return
    cpp = oracles["cpp"]
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
