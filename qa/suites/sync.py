"""Incremental synchronization black-box suite (24 assertions)."""
import difflib

from lib.runner import HarnessContext

REPOS = ["smart_locker", "volt_website"]

ASSERTION_LABELS = [
    "Status reports one changed file",
    "No-sync keeps previous index",
    "Query sees renamed symbol after auto refresh",
    "Query removes previous definition",
    "Only edited file reparsed",
    "Auto refresh leaves fresh bundle",
    "Comment-only edit updates source coordinates",
    "Comment edit preserves correct displayed source",
    "Docstring changes propagate to index",
    "New file discovered automatically",
    "Deleted definitions disappear automatically",
    "File rename updates paths",
    "Same-second edit setup",
    "Same-second edit must be stale",
    "Same-second edit new name is queryable",
    "Forced rebuild recovers missed edit",
    "Incremental indexes match full rebuild",
    "Initial single-file has function",
    "TS incremental rename visible",
    "Single-file output stays synchronized",
    "Malformed source does not crash indexing",
    "Status sync returns fresh after repair",
    "Status sync updates query data",
    "Invalid UTF8 input does not panic",
]


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(REPOS)
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ASSERTION_LABELS):
        return

    locker_sync = oracles["smart_locker"]["sync"]
    locker_type = oracles["smart_locker"]["type_query"]
    web_sync = oracles["volt_website"]["sync"]

    source = ctx.copy_corpus("smart_locker", "locker-sync")
    output = ctx.sandbox_dir / "sync-bundles"
    bundle = output / source.name

    ctx.run("Copy initial ensure", "ensure", source, "--out", output, "--timings")
    ctx.run("Copy warm ensure", "ensure", source, "--out", output, "--timings")

    ident = source / locker_sync["target_file"]
    original = ident.read_text(encoding="utf-8") if ident.is_file() else ""
    ctx.changed_write(
        ident,
        original.replace(locker_sync["old_def"], locker_sync["new_def"]),
    )

    r = ctx.run("Rename is stale", "status", bundle, "--check", "--json", expected=2)
    ctx.check(
        "Status reports one changed file",
        isinstance(r["json"], list)
        and len(r["json"]) == 1
        and r["json"][0].get("changed_files_count")
        == locker_sync["expected_changed_files_count"],
    )

    r = ctx.run(
        "No-sync old symbol",
        "sym",
        bundle,
        locker_sync["old_symbol"],
        "--no-sync",
        "--json",
    )
    ctx.check(
        "No-sync keeps previous index",
        bool(ctx.exact(r["json"], locker_sync["old_symbol"])),
    )

    r = ctx.run(
        "Rename automatic refresh",
        "sym",
        bundle,
        locker_sync["renamed_symbol_1"],
        "--json",
    )
    ctx.check(
        "Query sees renamed symbol after auto refresh",
        bool(ctx.exact(r["json"], locker_sync["renamed_symbol_1"])),
    )

    r = ctx.run(
        "Old symbol removed",
        "sym",
        bundle,
        locker_sync["old_symbol"],
        "--json",
    )
    ctx.check(
        "Query removes previous definition",
        not ctx.exact(r["json"], locker_sync["old_symbol"]),
    )

    meta = ctx.read_meta(bundle)
    ctx.check(
        "Only edited file reparsed",
        meta.get("incremental_reparsed_files")
        == locker_sync["expected_reparsed_files"]
        and meta.get("incremental_reused_files")
        == locker_sync["expected_reused_files"],
        {
            "reparsed": meta.get("incremental_reparsed_files"),
            "reused": meta.get("incremental_reused_files"),
        },
    )

    r = ctx.run("Fresh after rename", "status", bundle, "--check", "--json")
    ctx.check(
        "Auto refresh leaves fresh bundle",
        isinstance(r["json"], list)
        and len(r["json"]) > 0
        and bool(r["json"][0].get("is_fresh")),
    )

    body = ident.read_text(encoding="utf-8") if ident.is_file() else ""
    ctx.changed_write(ident, locker_sync["comment_prefix"] + body)
    r = ctx.run(
        "Comment insertion refresh",
        "sym",
        bundle,
        locker_sync["renamed_symbol_1"],
        "--json",
    )
    rows = ctx.exact(r["json"], locker_sync["renamed_symbol_1"])
    ctx.check(
        "Comment-only edit updates source coordinates",
        len(rows) == 1
        and rows[0].get("start_line") == locker_sync["shifted_start_line"],
        rows[0].get("start_line") if rows else None,
    )

    r = ctx.run(
        "Comment insertion inline source",
        "sym",
        bundle,
        locker_sync["renamed_symbol_1"],
        "--show",
    )
    ctx.check(
        "Comment edit preserves correct displayed source",
        locker_sync["inline_source_contains"] in r["stdout"],
    )

    model = source / locker_sync["model_file"]
    model_body = model.read_text(encoding="utf-8") if model.is_file() else ""
    ctx.changed_write(
        model,
        model_body.replace(
            locker_sync["old_docstring"],
            locker_sync["new_docstring"],
        ),
    )
    r = ctx.run("Docstring refresh", "type", bundle, locker_type, "--json")
    ctx.check(
        "Docstring changes propagate to index",
        any(
            x.get("doc_summary") == locker_sync["new_docstring"]
            for x in ctx.exact(r["json"], locker_type)
        ),
    )

    added = source / locker_sync["added_file"]
    ctx.changed_write(
        added,
        original.replace(locker_sync["old_symbol"], locker_sync["added_symbol"]),
    )
    r = ctx.run(
        "Added file query refresh",
        "sym",
        bundle,
        locker_sync["added_symbol"],
        "--json",
    )
    ctx.check(
        "New file discovered automatically",
        len(ctx.exact(r["json"], locker_sync["added_symbol"])) == 1,
    )

    if added.is_file():
        added.unlink()
    ctx.run("Deleted file freshness", "status", bundle, "--check", "--json", expected=2)
    r = ctx.run(
        "Deleted file query refresh",
        "sym",
        bundle,
        locker_sync["added_symbol"],
        "--json",
    )
    ctx.check("Deleted definitions disappear automatically", r["json"] == [])

    renamed = ident.with_name(locker_sync["renamed_file_name"])
    if ident.is_file():
        ident.rename(renamed)
    r = ctx.run(
        "File rename query refresh",
        "sym",
        bundle,
        locker_sync["renamed_symbol_1"],
        "--json",
    )
    ctx.check(
        "File rename updates paths",
        isinstance(r["json"], list)
        and len(r["json"]) == 1
        and r["json"][0].get("file", "").endswith(locker_sync["renamed_file_name"]),
    )
    ident = renamed

    setup_ok, setup_detail = ctx.mutate_same_second(
        ident,
        locker_sync["renamed_symbol_1"],
        locker_sync["renamed_symbol_2"],
    )
    ctx.check("Same-second edit setup", setup_ok, setup_detail)

    r = ctx.run(
        "Same-second edit freshness",
        "status",
        bundle,
        "--check",
        "--json",
        expected=None,
        paired_assertion="Same-second edit must be stale",
    )
    ctx.check(
        "Same-second edit must be stale",
        r["exit"] == 2
        and isinstance(r["json"], list)
        and len(r["json"]) > 0
        and not r["json"][0].get("is_fresh"),
        r["json"],
    )

    r = ctx.run(
        "Same-second edit automatic refresh",
        "sym",
        bundle,
        locker_sync["renamed_symbol_2"],
        "--json",
    )
    ctx.check(
        "Same-second edit new name is queryable",
        bool(ctx.exact(r["json"], locker_sync["renamed_symbol_2"])),
    )

    ctx.run("Force repairs same-second edit", "ensure", source, "--out", output, "--force")
    r = ctx.run(
        "Forced same-second query",
        "sym",
        bundle,
        locker_sync["renamed_symbol_2"],
        "--json",
    )
    ctx.check(
        "Forced rebuild recovers missed edit",
        bool(ctx.exact(r["json"], locker_sync["renamed_symbol_2"])),
    )

    ctx.changed_write(
        ident,
        ident.read_text(encoding="utf-8").replace(
            locker_sync["renamed_symbol_2"],
            locker_sync["renamed_symbol_3"],
        ),
    )
    ctx.run("Incremental equivalence baseline", "ensure", source, "--out", output)
    before = ctx.hashes(bundle)
    sections_dir = bundle / "sections"
    old_sections = (
        {
            str(p.relative_to(bundle)).replace("\\", "/"): p.read_text(encoding="utf-8")
            for p in sections_dir.glob("*.md")
        }
        if sections_dir.is_dir()
        else {}
    )
    ctx.run("Post-edit forced determinism", "convert", source, "-o", bundle, "--force")
    after_hashes = ctx.hashes(bundle)
    different = [key for key in before if before[key] != after_hashes.get(key)]
    ctx.check(
        "Incremental indexes match full rebuild",
        bool(before) and not different,
        different,
    )
    for key in different:
        if key in old_sections and (bundle / key).is_file():
            diff = "".join(
                difflib.unified_diff(
                    old_sections[key].splitlines(True),
                    (bundle / key).read_text(encoding="utf-8").splitlines(True),
                    fromfile="incremental/" + key,
                    tofile="forced/" + key,
                )
            )
            (ctx.sandbox_dir / "incremental-versus-forced.diff").write_text(
                diff,
                encoding="utf-8",
            )

    website = ctx.copy_corpus("volt_website", "website-sync")
    web_bundle = output / website.name
    ctx.run(
        "Website single-file initial",
        "convert",
        website,
        "-o",
        web_bundle,
        "--single-file",
    )
    merged = web_bundle / f"{website.name}.md"
    if not merged.exists():
        merged_candidates = (
            list(web_bundle.glob("*.md")) if web_bundle.is_dir() else []
        )
        ctx.check(
            "Initial single-file has function",
            False,
            [p.name for p in merged_candidates],
        )
    else:
        ctx.check(
            "Initial single-file has function",
            web_sync["old_symbol"] in merged.read_text(encoding="utf-8"),
        )

    kontakt = website / web_sync["target_file"]
    ctx.changed_write(
        kontakt,
        kontakt.read_text(encoding="utf-8").replace(
            web_sync["old_symbol"],
            web_sync["renamed_symbol_1"],
        ),
    )
    r = ctx.run(
        "Website TS rename automatic refresh",
        "sym",
        web_bundle,
        web_sync["renamed_symbol_1"],
        "--json",
    )
    ctx.check(
        "TS incremental rename visible",
        bool(ctx.exact(r["json"], web_sync["renamed_symbol_1"])),
    )
    ctx.check(
        "Single-file output stays synchronized",
        merged.is_file()
        and web_sync["renamed_symbol_1"] in merged.read_text(encoding="utf-8"),
    )

    ctx.run(
        "Website return to single-file mode",
        "convert",
        website,
        "-o",
        web_bundle,
        "--single-file",
        "--force",
    )
    malformed = website / web_sync["malformed_file"]
    ctx.changed_write(malformed, web_sync["malformed_content"])
    r = ctx.run("Malformed new source", "ensure", website, "--out", output)
    ctx.check(
        "Malformed source does not crash indexing",
        r["exit"] == 0 and "panicked at" not in r["stderr"],
    )

    ctx.changed_write(
        kontakt,
        kontakt.read_text(encoding="utf-8").replace(
            web_sync["renamed_symbol_1"],
            web_sync["renamed_symbol_2"],
        ),
    )
    r = ctx.run("Explicit status sync", "status", web_bundle, "--sync", "--check", "--json")
    ctx.check(
        "Status sync returns fresh after repair",
        isinstance(r["json"], list)
        and bool(r["json"])
        and all(isinstance(x, dict) and x.get("is_fresh") for x in r["json"]),
    )
    r = ctx.run(
        "Post status-sync no-sync query",
        "sym",
        web_bundle,
        web_sync["renamed_symbol_2"],
        "--no-sync",
        "--json",
    )
    ctx.check(
        "Status sync updates query data",
        bool(ctx.exact(r["json"], web_sync["renamed_symbol_2"])),
    )

    invalid_utf8 = website / web_sync["invalid_utf8_file"]
    invalid_utf8.write_bytes(b"export function qa_utf8() { return '\xff'; }\n")
    r = ctx.run(
        "Invalid UTF8 indexing",
        "ensure",
        website,
        "--out",
        output,
        expected=None,
        paired_assertion="Invalid UTF8 input does not panic",
    )
    ctx.check(
        "Invalid UTF8 input does not panic",
        "panicked at" not in r["stderr"],
        {"exit": r["exit"], "stderr": r["stderr"][:350]},
    )
