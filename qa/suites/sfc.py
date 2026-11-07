from pathlib import Path
import re
import shutil
import subprocess

from lib import procs
from lib.runner import HarnessContext

QA_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = QA_ROOT.parent

ASSERTION_LABELS = [
    "sfc: fixtures are tracked standalone JSX, Vue, and Svelte components",
    "sfc: jsx component symbol has valid coordinates",
    "sfc: vue component symbol has valid coordinates",
    "sfc: svelte component symbol has valid coordinates",
    "sfc: jsx rename and one-line prepend propagate through incremental sync",
    "sfc: vue and svelte three-line prepend shifts coordinates by three",
    "sfc: second convert after the shift converges to cache hit",
    "sfc: checked-in fixtures and harness working tree stay unchanged",
]


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


def _git_status(root: Path) -> dict:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"exit": None, "stdout": "", "error": type(exc).__name__}
    return {"exit": proc.returncode, "stdout": proc.stdout.replace("\r\n", "\n")}


def _read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def _write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _count_lines(path: Path) -> int:
    raw = path.read_bytes()
    return raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)


def _file_hashes(fixture_dir: Path, files: list[str]) -> dict[str, str]:
    return {name: procs.file_sha256(fixture_dir / name) for name in files}


def _import_targets(text: str) -> list[str]:
    targets: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("import"):
            continue
        match = re.search(r"from\s+[\"']([^\"']+)[\"']", stripped)
        if match is None:
            match = re.match(r"import\s+[\"']([^\"']+)[\"']", stripped)
        if match is not None:
            targets.append(match.group(1))
    return targets


def _manifest_report(fixture: dict, fixture_dir: Path) -> dict:
    files = [str(name) for name in fixture["files"]]
    missing = [name for name in files if not (fixture_dir / name).is_file()]
    fixture_rel = f"qa/fixtures/{fixture['name']}"
    tracked = _git_tracked(REPO_ROOT, fixture_rel)
    tracking_ok = tracked is None or all(
        f"{fixture_rel}/{name}" in tracked for name in files
    )
    stems = {Path(name).stem for name in files}
    script_missing: list[str] = []
    cross_imports: dict[str, list[str]] = {}
    for name in files:
        if not name.endswith((".vue", ".svelte")):
            continue
        path = fixture_dir / name
        if not path.is_file():
            continue
        text = _read_text(path)
        if "<script" not in text:
            script_missing.append(name)
        own_stem = Path(name).stem
        offenders = [
            target
            for target in _import_targets(text)
            if any(stem != own_stem and stem in target for stem in stems)
        ]
        if offenders:
            cross_imports[name] = offenders
    return {
        "fixture_dir": str(fixture_dir),
        "files": files,
        "missing": missing,
        "git_tracked": sorted(tracked) if tracked is not None else "not verified (no git repository)",
        "tracking_ok": tracking_ok,
        "script_missing": script_missing,
        "cross_imports": cross_imports,
        "valid": not missing and tracking_ok and not script_missing and not cross_imports,
    }


def _component_rows(
    ctx: HarnessContext,
    bundle: Path,
    spec: dict,
) -> list[dict]:
    file_rel = str(spec["file"])
    name = str(spec["name"])
    return [
        row
        for row in ctx.read_tsv(bundle, "symbols")
        if row.get("file") == file_rel and row.get("name") == name
    ]


def _coordinate_check(
    ctx: HarnessContext,
    bundle: Path,
    source_dir: Path,
    spec: dict,
) -> dict:
    rows = _component_rows(ctx, bundle, spec)
    expected_start = int(spec["start_line"])
    expected_end = int(spec["end_line"])
    name = str(spec["name"])
    file_rel = str(spec["file"])
    path = source_dir / file_rel
    line_count = _count_lines(path) if path.is_file() else 0
    lines = _read_text(path).splitlines() if path.is_file() else []
    span = "\n".join(lines[expected_start - 1:expected_end]) if lines else ""
    row = rows[0] if rows else {}
    start = int(row.get("start_line") or 0)
    end = int(row.get("end_line") or 0)
    uppercase = bool(name) and name[0].isupper()
    span_ok = re.search(rf"\b{re.escape(name)}\b", span) is not None
    matches_golden = start == expected_start and end == expected_end
    valid = (
        bool(rows)
        and uppercase
        and start == expected_start
        and end == expected_end
        and 1 <= start <= end <= line_count
        and span_ok
    )
    return {
        "file": file_rel,
        "name": name,
        "rows": len(rows),
        "start_line": start,
        "end_line": end,
        "expected_start_line": expected_start,
        "expected_end_line": expected_end,
        "file_line_count": line_count,
        "uppercase": uppercase,
        "identifier_in_span": span_ok,
        "matches_golden": matches_golden,
        "valid": valid,
    }


def _exact_rows(run: dict, name: str) -> list[dict]:
    payload = run.get("json")
    if not isinstance(payload, list):
        return []
    return [
        row
        for row in payload
        if isinstance(row, dict) and row.get("name") == name
    ]


def _shift_pair(rows: list[dict], spec: dict, delta: int) -> dict:
    name = str(spec["name"])
    file_rel = str(spec["file"])
    expected_start = int(spec["start_line"]) + delta
    expected_end = int(spec["end_line"]) + delta
    matched = [
        row
        for row in rows
        if row.get("file") == file_rel and row.get("name") == name
    ]
    row = matched[0] if matched else {}
    start = int(row.get("start_line") or 0)
    end = int(row.get("end_line") or 0)
    return {
        "file": file_rel,
        "name": name,
        "rows": len(matched),
        "start_line": start,
        "end_line": end,
        "expected_start_line": expected_start,
        "expected_end_line": expected_end,
        "valid": bool(matched) and start == expected_start and end == expected_end,
    }


def _shadow_pair(run: dict, name: str, spec: dict, delta: int) -> dict:
    name_matches = _exact_rows(run, name)
    result = _shift_pair(name_matches, {**spec, "name": name}, delta)
    result.update({"sym_exit": run["exit"], "sym_rows": len(name_matches)})
    return result


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["sfc"])
    if oracles is None:
        return
    fixture = oracles["sfc"]["fixture"]
    fixture_dir = ctx.fixtures_dir / str(fixture["name"])
    if not fixture_dir.is_dir():
        ctx.check(
            ASSERTION_LABELS[0],
            False,
            f"missing fixture directory at {fixture_dir}",
        )
        return

    git_before = _git_status(REPO_ROOT)
    manifest = _manifest_report(fixture, fixture_dir)
    ctx.check(ASSERTION_LABELS[0], manifest["valid"], manifest)
    fixture_hashes_before = _file_hashes(fixture_dir, manifest["files"])

    sandbox = ctx.sandbox_dir / "sfc"
    source_dir = sandbox / "fixtures"
    bundle = sandbox / "bundle"
    sandbox.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fixture_dir, source_dir)

    cold = ctx.run(
        "sfc: cold convert",
        "convert",
        source_dir,
        "-o",
        bundle,
        "--timings",
    )
    cold_ok = (
        cold["exit"] == 0
        and "INDEXED" in str(cold.get("stdout") or "")
        and "panicked" not in str(cold.get("stderr") or "").lower()
    )
    components = fixture["components"]
    for index, key in ((1, "jsx"), (2, "vue"), (3, "svelte")):
        report = _coordinate_check(ctx, bundle, source_dir, components[key])
        report["cold_exit"] = cold["exit"]
        report["cold_ok"] = cold_ok
        ctx.check(ASSERTION_LABELS[index], cold_ok and report["valid"], report)

    jsx_spec = components["jsx"]
    jsx_old = str(jsx_spec["name"])
    jsx_new = jsx_old + str(fixture["jsx_rename_suffix"])
    jsx_path = source_dir / str(jsx_spec["file"])
    jsx_text = _read_text(jsx_path)
    renamed = re.sub(rf"\b{re.escape(jsx_old)}\b", jsx_new, jsx_text)
    _write_text(jsx_path, str(fixture["jsx_prepend_line"]) + "\n" + renamed)
    jsx_convert = ctx.run(
        "sfc: jsx incremental convert",
        "convert",
        source_dir,
        "-o",
        bundle,
        "--timings",
    )
    jsx_rows = ctx.read_tsv(bundle, "symbols")
    jsx_pair = _shift_pair(jsx_rows, {**jsx_spec, "name": jsx_new}, 1)
    jsx_query = ctx.run(
        "sfc: jsx renamed component query",
        "sym",
        "-b",
        bundle,
        jsx_new,
        "--json",
        "--no-sync",
    )
    jsx_sym_pair = _shadow_pair(jsx_query, jsx_new, jsx_spec, 1)
    jsx_ok = (
        jsx_convert["exit"] == 0
        and "INCREMENTAL SYNC" in str(jsx_convert.get("stdout") or "")
        and jsx_pair["valid"]
        and jsx_sym_pair["valid"]
    )
    ctx.check(
        ASSERTION_LABELS[4],
        jsx_ok,
        {
            "old_name": jsx_old,
            "new_name": jsx_new,
            "convert_exit": jsx_convert["exit"],
            "incremental_sync": "INCREMENTAL SYNC" in str(jsx_convert.get("stdout") or ""),
            "symbols_tsv": jsx_pair,
            "sym_query": jsx_sym_pair,
        },
    )

    shift_lines = int(fixture["sfc_prepend_lines"])
    prepend = (str(fixture["sfc_prepend_line"]) + "\n") * shift_lines
    shift_specs = [components["vue"], components["svelte"]]
    for spec in shift_specs:
        path = source_dir / str(spec["file"])
        _write_text(path, prepend + _read_text(path))

    shift_convert = ctx.run(
        "sfc: vue and svelte incremental convert",
        "convert",
        source_dir,
        "-o",
        bundle,
        "--timings",
    )
    hashes_after_shift = procs.bundle_hashes(bundle, include_index_md=False)
    shift_rows = ctx.read_tsv(bundle, "symbols")
    shift_pairs: dict[str, dict] = {}
    for spec in shift_specs:
        key = str(spec["file"])
        pair = _shift_pair(shift_rows, spec, shift_lines)
        query = ctx.run(
            f"sfc: {Path(key).suffix.lstrip('.')} shifted component query",
            "sym",
            "-b",
            bundle,
            str(spec["name"]),
            "--json",
            "--no-sync",
        )
        pair["sym_query"] = _shadow_pair(query, str(spec["name"]), spec, shift_lines)
        shift_pairs[key] = pair
    shift_ok = (
        shift_convert["exit"] == 0
        and "INCREMENTAL SYNC" in str(shift_convert.get("stdout") or "")
        and all(pair["valid"] and pair["sym_query"]["valid"] for pair in shift_pairs.values())
        and bool(hashes_after_shift)
    )
    ctx.check(
        ASSERTION_LABELS[5],
        shift_ok,
        {
            "prepend_lines": shift_lines,
            "convert_exit": shift_convert["exit"],
            "incremental_sync": "INCREMENTAL SYNC" in str(shift_convert.get("stdout") or ""),
            "symbols_tsv": shift_pairs,
        },
    )

    second = ctx.run(
        "sfc: converged convert",
        "convert",
        source_dir,
        "-o",
        bundle,
        "--timings",
    )
    hashes_after_second = procs.bundle_hashes(bundle, include_index_md=False)
    diffs = procs.hash_diffs(hashes_after_shift, hashes_after_second)
    second_ok = (
        second["exit"] == 0
        and "CACHE HIT" in str(second.get("stdout") or "")
        and not diffs
    )
    ctx.check(
        ASSERTION_LABELS[6],
        second_ok,
        {
            "exit": second["exit"],
            "cache_hit": "CACHE HIT" in str(second.get("stdout") or ""),
            "artifact_count": len(hashes_after_shift),
            "hash_diffs": diffs[:10],
            "diff_count": len(diffs),
        },
    )

    fixture_hashes_after = _file_hashes(fixture_dir, manifest["files"])
    git_after = _git_status(REPO_ROOT)
    ctx.check(
        ASSERTION_LABELS[7],
        fixture_hashes_before == fixture_hashes_after and git_before == git_after,
        {
            "fixture_hashes_unchanged": fixture_hashes_before == fixture_hashes_after,
            "fixture_diffs": procs.hash_diffs(fixture_hashes_before, fixture_hashes_after),
            "git_exit": [git_before.get("exit"), git_after.get("exit")],
            "git_status_unchanged": git_before == git_after,
            "git_before": str(git_before.get("stdout") or "")[:500],
            "git_after": str(git_after.get("stdout") or "")[:500],
            "sandbox": str(sandbox),
        },
    )
