"""Cache and option boundaries black-box suite (26 assertions)."""
import shutil

from lib.runner import HarnessContext

REPOS = ["smart_locker", "volt_website", "beautiful-embedded-c"]

OPTIONS_LABELS = [
    "No merged file without flag",
    "Warm single-file request produces merged file",
    "Forced single-file output exists",
    "Ensure restores missing required output",
    "Query repairs missing symbols table",
    "Options baseline",
    "Enable single-file on warm cache",
    "Forced single-file recovery",
    "Ensure repairs missing symbols table",
    "Query with missing symbols table",
    "Restore complete options bundle",
]

VENDOR_AND_HEX_LABELS = [
    "Derived C fixture has classified vendor file",
    "Vendor mode change honored on cache hit",
    "Vendor none excludes SDK symbols",
    "Vendor all restores SDK symbols",
    "Hex address notation equivalence",
    "Vendor active initial",
    "Vendor none warm switch",
    "Vendor excluded symbol",
    "Vendor all switch",
    "Vendor all indexed symbol",
    "Address fixture refresh",
    "Hex normalization 0x40000004",
    "Hex normalization 40000004h",
    "Hex normalization 0X40000004",
]

SPACES_LABELS = [
    "Paths containing spaces work",
    "Spaces in paths convert",
    "Spaces in paths query",
]

ASSERTION_LABELS = [
    "No merged file without flag",
    "Warm single-file request produces merged file",
    "Forced single-file output exists",
    "Ensure restores missing required output",
    "Query repairs missing symbols table",
    *[
        label
        for lang in ["python", "typescript", "c"]
        for label in [
            f"{lang}: equal-size different subsecond setup",
            f"{lang}: detects same-second edit",
            f"{lang}: convert avoids false cache hit",
            f"{lang}: syncs same-second symbol",
            f"{lang}: force rebuild fixes miss",
        ]
    ],
    "Derived C fixture has classified vendor file",
    "Vendor mode change honored on cache hit",
    "Vendor none excludes SDK symbols",
    "Vendor all restores SDK symbols",
    "Hex address notation equivalence",
    "Paths containing spaces work",
]


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(REPOS)
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ASSERTION_LABELS):
        return

    locker_o = oracles["smart_locker"]
    web_o = oracles["volt_website"]
    bec_o = oracles["beautiful-embedded-c"]

    if ctx.any_label_matches(OPTIONS_LABELS):
        source = ctx.copy_corpus("volt_website", "website-options")
        bundle = ctx.sandbox_dir / "boundary-bundles" / "website-options"
        ctx.run("Options baseline", "convert", source, "-o", bundle)
        merged = bundle / f"{source.name}.md"
        ctx.check("No merged file without flag", not merged.exists())
        r = ctx.run(
            "Enable single-file on warm cache",
            "convert",
            source,
            "-o",
            bundle,
            "--single-file",
        )
        ctx.check(
            "Warm single-file request produces merged file",
            merged.exists(),
            r["stdout"].splitlines()[1:3],
        )
        ctx.run(
            "Forced single-file recovery",
            "convert",
            source,
            "-o",
            bundle,
            "--single-file",
            "--force",
        )
        ctx.check("Forced single-file output exists", merged.exists())

        missing = bundle / "index" / "symbols.tsv"
        saved = missing.read_bytes() if missing.is_file() else b""
        if missing.is_file():
            missing.unlink()
        r = ctx.run(
            "Ensure repairs missing symbols table",
            "ensure",
            source,
            "--out",
            bundle.parent,
        )
        ctx.check(
            "Ensure restores missing required output",
            missing.exists(),
            r["stdout"].splitlines()[:3],
        )

        # Delete symbols.tsv again so the query repair assertion genuinely tests missing-table self-heal
        if missing.is_file():
            missing.unlink()
        r = ctx.run(
            "Query with missing symbols table",
            "sym",
            bundle,
            web_o["sym_query"],
            "--json",
            expected=None,
            paired_assertion="Query repairs missing symbols table",
        )
        ctx.check(
            "Query repairs missing symbols table",
            r["exit"] == 0
            and missing.exists()
            and bool(ctx.exact(r["json"], web_o["sym_query"])),
        )
        if not missing.exists() and saved:
            missing.parent.mkdir(parents=True, exist_ok=True)
            missing.write_bytes(saved)
        ctx.run("Restore complete options bundle", "convert", source, "-o", bundle, "--force")

    probes = [
        locker_o["same_second_probe"],
        web_o["same_second_probe"],
        bec_o["same_second_probe"],
    ]
    for probe in probes:
        language = probe["language"]
        repo = probe["repo"]
        relative = probe["relative_path"]
        old = probe["old_symbol"]
        new = probe["new_symbol"]
        lang_labels = [
            f"{language}: initial index",
            f"{language}: equal-size different subsecond setup",
            f"{language}: same-second status",
            f"{language}: detects same-second edit",
            f"{language}: same-second warm convert",
            f"{language}: convert avoids false cache hit",
            f"{language}: same-second new symbol",
            f"{language}: syncs same-second symbol",
            f"{language}: force rebuild verifies new source",
            f"{language}: forced new symbol",
            f"{language}: force rebuild fixes miss",
        ]
        if not ctx.any_label_matches(lang_labels):
            continue

        copied = ctx.sandbox_dir / "copies" / f"same-second-{language}"
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ctx.repos_root / repo / relative, target)
        out = ctx.sandbox_dir / "boundary-bundles" / f"same-second-{language}"
        ctx.run(f"{language}: initial index", "convert", copied, "-o", out)

        setup_ok, setup_detail = ctx.mutate_same_second(target, old, new)
        ctx.check(
            f"{language}: equal-size different subsecond setup",
            setup_ok,
            setup_detail,
        )
        r = ctx.run(
            f"{language}: same-second status",
            "status",
            out,
            "--check",
            "--json",
            expected=None,
            paired_assertion=f"{language}: detects same-second edit",
        )
        ctx.check(f"{language}: detects same-second edit", r["exit"] == 2, r["json"])
        r = ctx.run(f"{language}: same-second warm convert", "convert", copied, "-o", out)
        ctx.check(
            f"{language}: convert avoids false cache hit",
            "CACHE HIT" not in r["stdout"],
        )
        r = ctx.run(f"{language}: same-second new symbol", "sym", out, new, "--json")
        ctx.check(
            f"{language}: syncs same-second symbol",
            bool(ctx.exact(r["json"], new)),
        )
        ctx.run(
            f"{language}: force rebuild verifies new source",
            "convert",
            copied,
            "-o",
            out,
            "--force",
        )
        r = ctx.run(f"{language}: forced new symbol", "sym", out, new, "--json")
        ctx.check(
            f"{language}: force rebuild fixes miss",
            bool(ctx.exact(r["json"], new)),
        )

    if ctx.any_label_matches(VENDOR_AND_HEX_LABELS):
        vp = bec_o["vendor_probe"]
        embedded = ctx.sandbox_dir / "copies" / "c-vendor-options"
        first = embedded / "src"
        vendor = embedded / "vendor"
        first.mkdir(parents=True, exist_ok=True)
        vendor.mkdir(parents=True, exist_ok=True)
        real_c = ctx.repos_root / "beautiful-embedded-c" / vp["source_c"]
        real_header = ctx.repos_root / "beautiful-embedded-c" / vp["source_h"]
        shutil.copy2(real_c, first / vp["target_c_name"])
        shutil.copy2(real_header, first / vp["target_h_name"])
        body = real_c.read_text(encoding="utf-8").replace(
            vp["old_prefix"],
            vp["new_prefix"],
        )
        (vendor / vp["vendor_c_name"]).write_text(body, encoding="utf-8")

        output = ctx.sandbox_dir / "boundary-bundles" / "c-vendor-options"
        ctx.run(
            "Vendor active initial",
            "convert",
            embedded,
            "-o",
            output,
            "--vendor-mode",
            "active",
        )
        active_meta = ctx.read_meta(output)
        ctx.check(
            "Derived C fixture has classified vendor file",
            active_meta.get("vendor_files") == vp["expected_active_vendor_files"],
            active_meta.get("vendor_files"),
        )
        ctx.run(
            "Vendor none warm switch",
            "convert",
            embedded,
            "-o",
            output,
            "--vendor-mode",
            "none",
        )
        meta = ctx.read_meta(output)
        ctx.check(
            "Vendor mode change honored on cache hit",
            meta.get("vendor_mode") == "none"
            and meta.get("vendor_files") == vp["expected_none_vendor_files"],
            {"mode": meta.get("vendor_mode"), "vendor_files": meta.get("vendor_files")},
        )
        r = ctx.run(
            "Vendor excluded symbol",
            "sym",
            output,
            vp["vendor_symbol"],
            "--json",
        )
        ctx.check(
            "Vendor none excludes SDK symbols",
            not ctx.exact(r["json"], vp["vendor_symbol"]),
        )
        ctx.run(
            "Vendor all switch",
            "convert",
            embedded,
            "-o",
            output,
            "--vendor-mode",
            "all",
        )
        r = ctx.run(
            "Vendor all indexed symbol",
            "sym",
            output,
            vp["vendor_symbol"],
            "--json",
        )
        ctx.check(
            "Vendor all restores SDK symbols",
            bool(ctx.exact(r["json"], vp["vendor_symbol"])),
        )

        addrs = first / vp["registers_header_name"]
        ctx.changed_write(addrs, vp["registers_header_content"])
        ctx.run(
            "Address fixture refresh",
            "convert",
            embedded,
            "-o",
            output,
            "--vendor-mode",
            "all",
        )
        regs = [
            ctx.run(f"Hex normalization {value}", "reg", output, value, "--json")["json"]
            for value in vp["hex_queries"]
        ]
        ctx.check(
            "Hex address notation equivalence",
            isinstance(regs[0], list)
            and regs[0] == regs[1] == regs[2]
            and bool(regs[0]),
        )

    if ctx.any_label_matches(SPACES_LABELS):
        sp = web_o["spaces_probe"]
        space = ctx.sandbox_dir / "copies" / "website path with spaces"
        space.mkdir(parents=True, exist_ok=True)
        copied = space / sp["copied_name"]
        shutil.copy2(ctx.repos_root / "volt_website" / sp["source_file"], copied)
        out = ctx.sandbox_dir / "boundary-bundles" / "path with spaces"
        ctx.run("Spaces in paths convert", "convert", space, "-o", out)
        r = ctx.run("Spaces in paths query", "sym", out, sp["symbol"], "--json")
        ctx.check(
            "Paths containing spaces work",
            bool(ctx.exact(r["json"], sp["symbol"])),
        )
