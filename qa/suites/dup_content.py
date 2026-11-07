from pathlib import Path
import csv
import json
import shutil

from lib.runner import HarnessContext

ASSERTION_LABELS = [
    "dup-content: both identical copies have distinct cache shards",
    "dup-content: both identical copies indexed in symbols, types, and sections",
    "dup-content: incremental edit of one copy reparses only edited copy",
    "dup-content: incremental refresh keeps sibling section and symbols",
    "dup-content: incremental edit counts and hashes match --force",
    "dup-content: adding duplicate copies incrementally indexes all copies and matches --force",
    "dup-content: deleting a duplicate copy incrementally prunes only deleted copy and matches --force",
]

ALL_LABELS = [
    *ASSERTION_LABELS,
    "dup-content: fixture directory exists",
    "dup-content: fixture bundle ready",
    "dup-content: initial convert",
    "dup-content: incremental edit convert",
    "dup-content: query sibling symbol",
    "dup-content: query renamed symbol",
    "dup-content: force after edit",
    "dup-content: incremental add copies",
    "dup-content: query after add",
    "dup-content: force after add",
    "dup-content: incremental delete copy",
    "dup-content: query after delete",
    "dup-content: force after delete",
]


def _read_tsv(bundle: Path, name: str) -> list[dict]:
    path = bundle / "index" / f"{name}.tsv"
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def _read_manifest(bundle: Path) -> dict:
    manifest_path = bundle / "cache" / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _meta_counts(meta: dict) -> tuple:
    return (
        meta.get("symbol_count"),
        meta.get("type_count"),
        meta.get("section_count"),
        meta.get("total_lines"),
    )


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(["dup-content"])
    if oracles is None:
        return
    if not ctx.any_label_matches(ALL_LABELS):
        return

    oracle = oracles["dup-content"]
    fixture_name = oracle["fixture_name"]
    fixture_src = ctx.fixtures_dir / fixture_name
    if not fixture_src.is_dir():
        ctx.check(
            "dup-content: fixture directory exists",
            False,
            f"missing fixture directory at {fixture_src}",
        )
        return

    if not ctx.ensure_fixture_bundle(fixture_name, fixture_src):
        return

    source = ctx.sandbox_dir / "copies" / fixture_name
    if source.exists():
        shutil.rmtree(source)
    source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fixture_src, source)

    bundle = ctx.sandbox_dir / "dup-bundles" / fixture_name

    alpha_rel = oracle["alpha_file"]
    beta_rel = oracle["beta_file"]
    gamma_rel = oracle["gamma_file"]
    delta_rel = oracle["delta_file"]
    probe_sym = oracle["probe_symbol"]
    renamed_sym = oracle["renamed_symbol"]
    type_name = oracle["type_name"]

    ctx.run("dup-content: initial convert", "convert", source, "-o", bundle, "--timings")

    manifest = _read_manifest(bundle)
    files_map = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
    alpha_entry = files_map.get(alpha_rel) if isinstance(files_map, dict) else None
    beta_entry = files_map.get(beta_rel) if isinstance(files_map, dict) else None

    shards_ok = (
        isinstance(alpha_entry, dict)
        and isinstance(beta_entry, dict)
        and len(files_map) == oracle["expected_initial_files"]
        and alpha_entry.get("blake3_hash") == beta_entry.get("blake3_hash")
        and bool(alpha_entry.get("shard"))
        and bool(beta_entry.get("shard"))
        and alpha_entry.get("shard") != beta_entry.get("shard")
        and (bundle / alpha_entry["shard"]).is_file()
        and (bundle / beta_entry["shard"]).is_file()
    )
    ctx.check(
        "dup-content: both identical copies have distinct cache shards",
        shards_ok,
        {
            "alpha_shard": alpha_entry.get("shard") if isinstance(alpha_entry, dict) else None,
            "beta_shard": beta_entry.get("shard") if isinstance(beta_entry, dict) else None,
        },
    )

    sym_rows = _read_tsv(bundle, "symbols")
    type_rows = _read_tsv(bundle, "types")
    sec_rows = _read_tsv(bundle, "sections")

    probe_files = {r.get("file") for r in sym_rows if r.get("name") == probe_sym}
    type_files = {r.get("file") for r in type_rows if r.get("name") == type_name}
    sec_modules = {r.get("module_path") for r in sec_rows}

    indexed_ok = (
        probe_files == {alpha_rel, beta_rel}
        and type_files == {alpha_rel, beta_rel}
        and set(oracle["initial_modules"]).issubset(sec_modules)
    )
    ctx.check(
        "dup-content: both identical copies indexed in symbols, types, and sections",
        indexed_ok,
        {
            "probe_files": sorted(f for f in probe_files if f),
            "type_files": sorted(f for f in type_files if f),
            "sections": sorted(m for m in sec_modules if m),
        },
    )

    alpha_path = source / alpha_rel
    beta_path = source / beta_rel
    beta_text = beta_path.read_text(encoding="utf-8") if beta_path.is_file() else ""
    if alpha_path.is_file():
        ctx.changed_write(
            alpha_path,
            alpha_path.read_text(encoding="utf-8").replace(probe_sym, renamed_sym),
        )

    r_edit = ctx.run(
        "dup-content: incremental edit convert",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    edit_meta = ctx.read_meta(bundle)
    ctx.check(
        "dup-content: incremental edit of one copy reparses only edited copy",
        "INCREMENTAL SYNC" in r_edit["stdout"]
        and "CACHE HIT" not in r_edit["stdout"]
        and edit_meta.get("incremental_reparsed_files") == oracle["expected_reparsed_on_edit"]
        and edit_meta.get("incremental_reused_files") == oracle["expected_reused_on_edit"],
        {
            "reparsed": edit_meta.get("incremental_reparsed_files"),
            "reused": edit_meta.get("incremental_reused_files"),
        },
    )

    r_sib = ctx.run(
        "dup-content: query sibling symbol",
        "sym",
        bundle,
        probe_sym,
        "--no-sync",
        "--json",
    )
    r_ren = ctx.run(
        "dup-content: query renamed symbol",
        "sym",
        bundle,
        renamed_sym,
        "--no-sync",
        "--json",
    )
    sib_rows = ctx.exact(r_sib["json"], probe_sym)
    ren_rows = ctx.exact(r_ren["json"], renamed_sym)

    sections_dir = bundle / "sections"
    section_texts = (
        [p.read_text(encoding="utf-8") for p in sorted(sections_dir.glob("*.md"))]
        if sections_dir.is_dir()
        else []
    )
    has_beta_section = any(
        beta_rel in body and f"def {probe_sym}(" in body for body in section_texts
    )
    has_alpha_section = any(
        alpha_rel in body and f"def {renamed_sym}(" in body for body in section_texts
    )

    ctx.check(
        "dup-content: incremental refresh keeps sibling section and symbols",
        len(sib_rows) == 1
        and sib_rows[0].get("file") == beta_rel
        and len(ren_rows) == 1
        and ren_rows[0].get("file") == alpha_rel
        and has_beta_section
        and has_alpha_section,
        {
            "sibling_files": [r.get("file") for r in sib_rows],
            "renamed_files": [r.get("file") for r in ren_rows],
            "has_beta_section": has_beta_section,
            "has_alpha_section": has_alpha_section,
        },
    )

    inc_edit_counts = _meta_counts(edit_meta)
    inc_edit_hashes = ctx.hashes(bundle)
    ctx.run(
        "dup-content: force after edit",
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    force_edit_meta = ctx.read_meta(bundle)
    force_edit_counts = _meta_counts(force_edit_meta)
    force_edit_hashes = ctx.hashes(bundle)
    edit_hash_diffs = [
        k for k in set(inc_edit_hashes) | set(force_edit_hashes)
        if inc_edit_hashes.get(k) != force_edit_hashes.get(k)
    ]
    ctx.check(
        "dup-content: incremental edit counts and hashes match --force",
        bool(inc_edit_hashes)
        and inc_edit_counts == force_edit_counts
        and not edit_hash_diffs,
        {
            "inc_counts": inc_edit_counts,
            "force_counts": force_edit_counts,
            "hash_diffs": edit_hash_diffs,
        },
    )

    gamma_path = source / gamma_rel
    delta_path = source / delta_rel
    gamma_path.parent.mkdir(parents=True, exist_ok=True)
    delta_path.parent.mkdir(parents=True, exist_ok=True)
    ctx.changed_write(gamma_path, beta_text)
    ctx.changed_write(delta_path, beta_text)

    r_add = ctx.run(
        "dup-content: incremental add copies",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    add_manifest = _read_manifest(bundle)
    add_files = (
        add_manifest.get("files") if isinstance(add_manifest.get("files"), dict) else {}
    )
    add_shards = {
        entry.get("shard")
        for entry in add_files.values()
        if isinstance(entry, dict) and entry.get("shard")
    }
    all_add_shards_exist = (
        len(add_files) == oracle["expected_added_files"]
        and len(add_shards) == oracle["expected_added_files"]
        and all((bundle / s).is_file() for s in add_shards if isinstance(s, str))
    )

    r_add_sym = ctx.run(
        "dup-content: query after add",
        "sym",
        bundle,
        probe_sym,
        "--no-sync",
        "--json",
    )
    add_sym_files = {
        r.get("file") for r in ctx.exact(r_add_sym["json"], probe_sym)
    }
    add_inc_counts = _meta_counts(ctx.read_meta(bundle))
    add_inc_hashes = ctx.hashes(bundle)

    ctx.run(
        "dup-content: force after add",
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    add_force_counts = _meta_counts(ctx.read_meta(bundle))
    add_force_hashes = ctx.hashes(bundle)
    add_hash_diffs = [
        k for k in set(add_inc_hashes) | set(add_force_hashes)
        if add_inc_hashes.get(k) != add_force_hashes.get(k)
    ]

    ctx.check(
        "dup-content: adding duplicate copies incrementally indexes all copies and matches --force",
        "CACHE HIT" not in r_add["stdout"]
        and all_add_shards_exist
        and add_sym_files == {beta_rel, gamma_rel, delta_rel}
        and bool(add_inc_hashes)
        and add_inc_counts == add_force_counts
        and not add_hash_diffs,
        {
            "manifest_files": len(add_files),
            "unique_shards": len(add_shards),
            "sym_files": sorted(f for f in add_sym_files if f),
            "hash_diffs": add_hash_diffs,
        },
    )

    if gamma_path.is_file():
        gamma_path.unlink()
    if gamma_path.parent.is_dir():
        shutil.rmtree(gamma_path.parent, ignore_errors=True)

    r_del = ctx.run(
        "dup-content: incremental delete copy",
        "convert",
        source,
        "-o",
        bundle,
        "--timings",
    )
    r_del_sym = ctx.run(
        "dup-content: query after delete",
        "sym",
        bundle,
        probe_sym,
        "--no-sync",
        "--json",
    )
    del_sym_files = {
        r.get("file") for r in ctx.exact(r_del_sym["json"], probe_sym)
    }
    del_sec_modules = {r.get("module_path") for r in _read_tsv(bundle, "sections")}
    del_inc_counts = _meta_counts(ctx.read_meta(bundle))
    del_inc_hashes = ctx.hashes(bundle)

    ctx.run(
        "dup-content: force after delete",
        "convert",
        source,
        "-o",
        bundle,
        "--force",
        "--timings",
    )
    del_force_counts = _meta_counts(ctx.read_meta(bundle))
    del_force_hashes = ctx.hashes(bundle)
    del_hash_diffs = [
        k for k in set(del_inc_hashes) | set(del_force_hashes)
        if del_inc_hashes.get(k) != del_force_hashes.get(k)
    ]

    ctx.check(
        "dup-content: deleting a duplicate copy incrementally prunes only deleted copy and matches --force",
        "CACHE HIT" not in r_del["stdout"]
        and del_sym_files == {beta_rel, delta_rel}
        and oracle["deleted_module"] not in del_sec_modules
        and bool(del_inc_hashes)
        and del_inc_counts == del_force_counts
        and not del_hash_diffs,
        {
            "sym_files": sorted(f for f in del_sym_files if f),
            "sections": sorted(m for m in del_sec_modules if m),
            "hash_diffs": del_hash_diffs,
        },
    )
