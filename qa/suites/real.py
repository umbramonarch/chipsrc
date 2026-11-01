"""Real-repository black-box suite (66 assertions across 4 repositories)."""
from pathlib import Path
import json

from lib.runner import HarnessContext

REPOS = ["chipsrc", "smart_locker", "volt_website", "beautiful-embedded-c"]
REQUIRED_ARTIFACTS = [
    "INDEX.md",
    "meta.json",
    "cache/manifest.json",
    "index/symbols.tsv",
    "index/types.tsv",
    "index/calls.tsv",
    "index/macros.tsv",
    "index/xref.tsv",
    "index/sections.tsv",
]

ASSERTION_LABELS = [
    *[
        label
        for repo in REPOS
        for label in [
            f"{repo}: inspect/index file counts agree",
            f"{repo}: bundle artifacts exist",
            f"{repo}: warm run cache hit",
            f"{repo}: warm run preserves index content",
            f"{repo}: forced rebuild deterministic indexes",
            f"{repo}: all symbol source coordinates valid",
        ]
    ],
    "Rust definition and signature",
    "Rust type fields",
    "Rust library orchestrator calls scanner",
    "Python definition exact coordinates",
    "Python cross-module callers are correctly resolved",
    "Python direct same-file callee",
    "Python ORM class fields",
    "TS exact cross-file call",
    "TS constant retains values",
    "TS path finds direct relationship",
    "TS impact finds direct relationship",
    "C caller and ISR extraction",
    "C ISR recognized by kind",
    "C typedef fields extracted",
    "C register separator equivalence",
    "C xref includes register accesses",
    "smart_locker: inline source contains expected body",
    "volt_website: inline source contains expected body",
    "beautiful-embedded-c: inline source contains expected body",
    "Multi-bundle discovery",
    "All four bundles fresh",
    "sym: respects limit",
    "callers: respects limit",
    "callees: respects limit",
    "type: respects limit",
    "search: respects limit",
    "Search source: machine readable list",
    "Search symbols: machine readable list",
    "Search types: machine readable list",
    "Search calls: machine readable list",
    "Search macros: machine readable list",
    "Search xref: machine readable list",
    "Search sections: machine readable list",
    "Regex finds actual call and definition",
    "Section listing count",
    "Section body contains signatures",
    "Unknown symbol is empty JSON",
    "missing repo: fails without panic",
    "missing bundle: fails without panic",
    "bad vendor mode: fails without panic",
    "negative limit: fails without panic",
    "Unbalanced regex remains usable as literal",
]


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(REPOS)
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ASSERTION_LABELS):
        return

    chipsrc_o = oracles["chipsrc"]
    locker_o = oracles["smart_locker"]
    web_o = oracles["volt_website"]
    bec_o = oracles["beautiful-embedded-c"]

    for repo in REPOS:
        ctx.ensure_repo_bundle(repo)

    for repo in REPOS:
        repo_path = ctx.repos_root / repo
        bundle = ctx.bundles_dir / repo
        report = ctx.run(f"{repo}: inspect", "inspect", repo_path, "--json")
        meta = ctx.read_meta(bundle)
        rep_json = report["json"] if isinstance(report["json"], dict) else {}
        ctx.check(
            f"{repo}: inspect/index file counts agree",
            "total_files" in rep_json
            and "total_files" in meta
            and rep_json.get("total_files") == meta.get("total_files"),
        )
        ctx.check(
            f"{repo}: bundle artifacts exist",
            all((bundle / name).is_file() for name in REQUIRED_ARTIFACTS),
        )
        before = ctx.hashes(bundle)
        warm = ctx.run(
            f"{repo}: warm convert",
            "convert",
            repo_path,
            "-o",
            bundle,
            "--timings",
        )
        ctx.check(
            f"{repo}: warm run cache hit",
            "CACHE HIT" in warm["stdout"],
            warm["wall_ms"],
        )
        ctx.check(
            f"{repo}: warm run preserves index content",
            bool(before) and before == ctx.hashes(bundle),
        )
        ctx.run(
            f"{repo}: forced rebuild",
            "convert",
            repo_path,
            "-o",
            bundle,
            "--force",
            "--single-file",
        )
        after = ctx.hashes(bundle)
        changed = [key for key in before if before[key] != after.get(key)]
        ctx.check(
            f"{repo}: forced rebuild deterministic indexes",
            bool(before) and not changed,
            changed,
        )
        symbols = ctx.read_symbols_tsv(bundle)
        invalid: list[str] = []
        source_root = Path(meta.get("source_root", str(repo_path)))
        for symbol in symbols:
            file_path = source_root / symbol["file"]
            line_key = "start_line" if "start_line" in symbol else "lines"
            start = int(symbol[line_key].split("-")[0])
            if not file_path.is_file() or not (
                1 <= start <= len(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
            ):
                invalid.append(symbol["symbol_id"])
        ctx.check(
            f"{repo}: all symbol source coordinates valid",
            bool(symbols) and not invalid,
            invalid[:10],
        )

    s = ctx.query("Rust symbol", "sym", "chipsrc", chipsrc_o["sym_query"])["json"]
    ctx.check(
        "Rust definition and signature",
        any(
            x.get("file") == chipsrc_o["sym_file"]
            and chipsrc_o["sym_sig_contains"] in x.get("signature", "")
            for x in ctx.exact(s, chipsrc_o["sym_query"])
        ),
    )
    t = ctx.query("Rust type", "type", "chipsrc", chipsrc_o["type_query"])["json"]
    ctx.check(
        "Rust type fields",
        any(
            chipsrc_o["type_field_contains"] in x.get("fields_summary", "")
            for x in ctx.exact(t, chipsrc_o["type_query"])
        ),
    )
    c = ctx.query("Rust callees", "callees", "chipsrc", chipsrc_o["sym_query"])["json"]
    ctx.check(
        "Rust library orchestrator calls scanner",
        any(
            isinstance(x, dict) and x.get("callee_name") == chipsrc_o["expected_callee"]
            for x in (c or [])
        ),
    )

    p = ctx.query("Python symbol", "sym", "smart_locker", locker_o["sym_query"])["json"]
    ctx.check(
        "Python definition exact coordinates",
        any(
            x.get("file") == locker_o["sym_file"]
            and x.get("start_line") == locker_o["sym_start_line"]
            for x in ctx.exact(p, locker_o["sym_query"])
        ),
    )
    c = ctx.query(
        "Python imported callers",
        "callers",
        "smart_locker",
        locker_o["sym_query"],
        limit=locker_o["callers_limit"],
    )["json"]
    required_callers = {
        (item[0], item[1]) for item in locker_o["import_resolved_callers"]
    }
    got_callers = {
        (x.get("file"), x.get("line"))
        for x in (c or [])
        if isinstance(x, dict) and x.get("tier") == locker_o["import_resolved_tier"]
    }
    ctx.check(
        "Python cross-module callers are correctly resolved",
        required_callers <= got_callers,
        sorted(required_callers - got_callers),
    )
    c = ctx.query("Python callees", "callees", "smart_locker", locker_o["sym_query"])[
        "json"
    ]
    ctx.check(
        "Python direct same-file callee",
        any(
            isinstance(x, dict)
            and x.get("callee_name") == locker_o["same_file_callee"]
            and x.get("tier") == locker_o["same_file_tier"]
            for x in (c or [])
        ),
    )
    t = ctx.query("Python class", "type", "smart_locker", locker_o["type_query"])["json"]
    ctx.check(
        "Python ORM class fields",
        any(
            locker_o["type_field_contains"] in x.get("fields_summary", "")
            for x in ctx.exact(t, locker_o["type_query"])
        ),
    )

    c = ctx.query("TS imported caller", "callers", "volt_website", web_o["sym_query"])[
        "json"
    ]
    ctx.check(
        "TS exact cross-file call",
        any(
            isinstance(x, dict)
            and x.get("caller_name") == web_o["caller_name"]
            and x.get("file") == web_o["caller_file"]
            and x.get("line") == web_o["caller_line"]
            and x.get("tier") == web_o["caller_tier"]
            for x in (c or [])
        ),
    )
    m = ctx.query("TS exported constant", "macro", "volt_website", web_o["macro_query"])[
        "json"
    ]
    ctx.check(
        "TS constant retains values",
        any(
            web_o["macro_value_contains"] in x.get("value", "")
            and x.get("line") == web_o["macro_line"]
            for x in ctx.exact(m, web_o["macro_query"])
        ),
    )
    for command in ["path", "impact"]:
        cmd_args = (
            [
                "path",
                ctx.bundles_dir / "volt_website",
                web_o["caller_name"],
                web_o["sym_query"],
                "--json",
            ]
            if command == "path"
            else [
                "impact",
                ctx.bundles_dir / "volt_website",
                web_o["sym_query"],
                "--json",
            ]
        )
        r = ctx.run(f"TS {command}", *cmd_args)["json"]
        ctx.check(
            f"TS {command} finds direct relationship",
            isinstance(r, dict)
            and bool(r.get("found"))
            and web_o["caller_name"] in r.get("summary", "")
            and web_o["sym_query"] in r.get("summary", ""),
        )

    c = ctx.query(
        "C direct callers",
        "callers",
        "beautiful-embedded-c",
        bec_o["sym_query"],
    )["json"]
    ctx.check(
        "C caller and ISR extraction",
        set(bec_o["expected_callers"])
        <= {x.get("caller_name") for x in (c or []) if isinstance(x, dict)},
    )
    s = ctx.query(
        "C ISR filter",
        "sym",
        "beautiful-embedded-c",
        bec_o["isr_symbol"],
        kind=bec_o["isr_kind"],
    )["json"]
    ctx.check(
        "C ISR recognized by kind",
        isinstance(s, list)
        and len(s) == bec_o["isr_count"]
        and all(isinstance(x, dict) and x.get("kind") == bec_o["isr_kind"] for x in s),
    )
    t = ctx.query(
        "C typedef struct",
        "type",
        "beautiful-embedded-c",
        bec_o["type_query"],
    )["json"]
    ctx.check(
        "C typedef fields extracted",
        isinstance(t, list)
        and len(t) == bec_o["type_count"]
        and all(
            isinstance(x, dict)
            and bec_o["type_field_contains"] in x.get("fields_summary", "")
            for x in t
        ),
    )
    macros = []
    for name in bec_o["register_queries"]:
        macros.append(
            ctx.query(
                f"C register normalization {name}",
                "reg",
                "beautiful-embedded-c",
                name,
            )["json"]
        )
    ctx.check(
        "C register separator equivalence",
        isinstance(macros[0], list)
        and macros[0] == macros[1] == macros[2]
        and len(macros[0]) == bec_o["register_hit_count"],
    )
    x = ctx.query(
        "C hardware references",
        "xref",
        "beautiful-embedded-c",
        bec_o["xref_query"],
    )["json"]
    ctx.check(
        "C xref includes register accesses",
        bool(x) and bec_o["xref_query"] in json.dumps(x),
    )

    for repo_name, repo_o in [
        ("smart_locker", locker_o),
        ("volt_website", web_o),
        ("beautiful-embedded-c", bec_o),
    ]:
        r = ctx.run(
            f"{repo_name}: inline source",
            "sym",
            ctx.bundles_dir / repo_name,
            repo_o["inline_source_symbol"],
            "--show",
        )
        ctx.check(
            f"{repo_name}: inline source contains expected body",
            repo_o["inline_source_contains"] in r["stdout"],
        )

    r = ctx.run(
        "Multi-bundle symbol lookup",
        "sym",
        "-b",
        ctx.bundles_dir,
        chipsrc_o["multi_bundle_symbol"],
        "--json",
        "--limit",
        str(chipsrc_o["multi_bundle_limit"]),
    )
    ctx.check(
        "Multi-bundle discovery",
        isinstance(r["json"], list)
        and len({x.get("bundle") for x in r["json"] if isinstance(x, dict)})
        >= chipsrc_o["multi_bundle_min_bundles"],
    )
    r = ctx.run("Multi-bundle freshness", "status", ctx.bundles_dir, "--check", "--json")
    named_entries = (
        [
            x
            for x in r["json"]
            if isinstance(x, dict) and x.get("bundle_name") in REPOS
        ]
        if isinstance(r["json"], list)
        else []
    )
    ctx.check(
        "All four bundles fresh",
        len(named_entries) == chipsrc_o["expected_bundle_count"]
        and {x.get("bundle_name") for x in named_entries} == set(REPOS)
        and all(x.get("is_fresh") for x in named_entries),
    )

    for command, text in locker_o["limit_probe_queries"]:
        r = ctx.query(
            f"{command}: max limit 1",
            command,
            "smart_locker",
            text,
            limit=locker_o["max_limit_probe"],
        )
        ctx.check(
            f"{command}: respects limit",
            isinstance(r["json"], list)
            and len(r["json"]) <= locker_o["max_limit_probe"],
        )

    for kind in web_o["search_kinds"]:
        r = ctx.query(
            f"Search kind {kind}",
            "search",
            "volt_website",
            web_o["search_query"],
            kind=kind,
            ignore_case=True,
            limit=web_o["search_limit"],
        )
        ctx.check(f"Search {kind}: machine readable list", isinstance(r["json"], list))

    r = ctx.query(
        "Regex source search",
        "search",
        "volt_website",
        web_o["regex_pattern"],
        source=True,
    )
    ctx.check(
        "Regex finds actual call and definition",
        isinstance(r["json"], list) and len(r["json"]) >= web_o["regex_min_hits"],
    )
    r = ctx.query("Section listing", "section", "volt_website")
    ctx.check(
        "Section listing count",
        isinstance(r["json"], list)
        and len(r["json"]) == web_o["expected_section_count"],
    )
    r = ctx.run(
        "Section body",
        "section",
        ctx.bundles_dir / "volt_website",
        web_o["section_query"],
        "--show",
    )
    ctx.check("Section body contains signatures", web_o["sym_query"] in r["stdout"])
    r = ctx.query("Unknown symbol", "sym", "chipsrc", chipsrc_o["unknown_symbol"])
    ctx.check("Unknown symbol is empty JSON", r["json"] == [])

    for label, neg_args in [
        ("missing repo", ["inspect", ctx.out_dir / "does-not-exist", "--json"]),
        (
            "missing bundle",
            [
                "sym",
                "-b",
                ctx.out_dir / "does-not-exist",
                chipsrc_o["multi_bundle_symbol"],
                "--json",
            ],
        ),
        (
            "bad vendor mode",
            ["inspect", ctx.repos_root / "chipsrc", "--vendor-mode", "invalid"],
        ),
        (
            "negative limit",
            [
                "sym",
                ctx.bundles_dir / "chipsrc",
                chipsrc_o["multi_bundle_symbol"],
                "--limit",
                chipsrc_o["negative_limit_arg"],
            ],
        ),
    ]:
        paired = f"{label}: fails without panic"
        r = ctx.run(label, *neg_args, expected=None, paired_assertion=paired)
        ctx.check(
            paired,
            r["exit"] != 0 and "panicked at" not in r["stderr"],
            r["exit"],
        )

    r = ctx.run(
        "Unbalanced regex literal fallback",
        "search",
        ctx.bundles_dir / "chipsrc",
        chipsrc_o["literal_fallback_query"],
        "--json",
        "--limit",
        str(chipsrc_o["literal_fallback_limit"]),
    )
    ctx.check(
        "Unbalanced regex remains usable as literal",
        isinstance(r["json"], list),
    )
