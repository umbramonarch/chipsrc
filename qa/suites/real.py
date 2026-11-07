from pathlib import Path
import json

from lib.runner import HarnessContext

REPO = "chipsrc"
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
    "chipsrc: inspect/index file counts agree",
    "chipsrc: bundle artifacts exist",
    "chipsrc: warm run cache hit",
    "chipsrc: warm run preserves index content",
    "chipsrc: forced rebuild deterministic indexes",
    "chipsrc: all symbol source coordinates valid",
    "Rust definition and signature",
    "Rust type fields",
    "Rust library orchestrator calls scanner",
    "Rust cross-module callers resolved",
    "Rust path finds direct relationship",
    "Rust impact finds direct relationship",
    "Rust constant retains value",
    "Rust xref includes type references",
    "chipsrc: inline source contains expected body",
    "Multi-bundle fixture discovery",
    "All fixture bundles fresh",
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
    "Section listing non-empty",
    "Section body contains signatures",
    "Unknown symbol is empty JSON",
    "missing repo: fails without panic",
    "missing bundle: fails without panic",
    "bad vendor mode: fails without panic",
    "negative limit: fails without panic",
    "Unbalanced regex remains usable as literal",
]


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles([REPO])
    if oracles is None:
        return
    if not ctx.check_repos_available([REPO], ASSERTION_LABELS):
        return

    chipsrc_o = oracles[REPO]
    repo_path = ctx.repos_root / REPO
    bundle = ctx.bundles_dir / REPO

    if not ctx.ensure_repo_bundle(REPO, repo_path):
        return

    for fx_name in chipsrc_o["fixture_bundles"]:
        fx_src = ctx.fixtures_dir / fx_name
        if fx_src.is_dir():
            ctx.ensure_fixture_bundle(fx_name, fx_src)

    report = ctx.run(f"{REPO}: inspect", "inspect", repo_path, "--json")
    meta = ctx.read_meta(bundle)
    rep_json = report["json"] if isinstance(report["json"], dict) else {}
    ctx.check(
        f"{REPO}: inspect/index file counts agree",
        "total_files" in rep_json
        and "total_files" in meta
        and rep_json.get("total_files") == meta.get("total_files"),
    )
    ctx.check(
        f"{REPO}: bundle artifacts exist",
        all((bundle / name).is_file() for name in REQUIRED_ARTIFACTS),
    )
    before = ctx.hashes(bundle)
    warm = ctx.run(
        f"{REPO}: warm convert",
        "convert",
        repo_path,
        "-o",
        bundle,
        "--timings",
    )
    ctx.check(
        f"{REPO}: warm run cache hit",
        "CACHE HIT" in warm["stdout"],
        warm["wall_ms"],
    )
    ctx.check(
        f"{REPO}: warm run preserves index content",
        bool(before) and before == ctx.hashes(bundle),
    )
    ctx.run(
        f"{REPO}: forced rebuild",
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
        f"{REPO}: forced rebuild deterministic indexes",
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
        f"{REPO}: all symbol source coordinates valid",
        bool(symbols) and not invalid,
        invalid[:10],
    )

    s = ctx.query("Rust symbol", "sym", REPO, chipsrc_o["sym_query"])["json"]
    ctx.check(
        "Rust definition and signature",
        any(
            x.get("file") == chipsrc_o["sym_file"]
            and chipsrc_o["sym_sig_contains"] in x.get("signature", "")
            for x in ctx.exact(s, chipsrc_o["sym_query"])
        ),
    )
    t = ctx.query("Rust type", "type", REPO, chipsrc_o["type_query"])["json"]
    ctx.check(
        "Rust type fields",
        any(
            chipsrc_o["type_field_contains"] in x.get("fields_summary", "")
            for x in ctx.exact(t, chipsrc_o["type_query"])
        ),
    )
    c = ctx.query("Rust callees", "callees", REPO, chipsrc_o["sym_query"])["json"]
    ctx.check(
        "Rust library orchestrator calls scanner",
        any(
            isinstance(x, dict) and x.get("callee_name") == chipsrc_o["expected_callee"]
            for x in (c or [])
        ),
    )
    callers_res = ctx.query(
        "Rust callers", "callers", REPO, chipsrc_o["expected_callee"]
    )["json"]
    ctx.check(
        "Rust cross-module callers resolved",
        any(
            isinstance(x, dict) and x.get("caller_name") == chipsrc_o["caller_expected"]
            for x in (callers_res or [])
        ),
    )

    r_path = ctx.run(
        "Rust path",
        "path",
        bundle,
        chipsrc_o["sym_query"],
        chipsrc_o["expected_callee"],
        "--json",
    )["json"]
    ctx.check(
        "Rust path finds direct relationship",
        isinstance(r_path, dict)
        and bool(r_path.get("found"))
        and chipsrc_o["sym_query"] in r_path.get("summary", "")
        and chipsrc_o["expected_callee"] in r_path.get("summary", ""),
    )

    r_impact = ctx.run(
        "Rust impact",
        "impact",
        bundle,
        chipsrc_o["expected_callee"],
        "--json",
    )["json"]
    ctx.check(
        "Rust impact finds direct relationship",
        isinstance(r_impact, dict)
        and bool(r_impact.get("found"))
        and chipsrc_o["expected_callee"] in r_impact.get("summary", ""),
    )

    m = ctx.query("Rust constant", "macro", REPO, chipsrc_o["macro_query"])["json"]
    ctx.check(
        "Rust constant retains value",
        any(
            chipsrc_o["macro_value_contains"] in x.get("value", "")
            for x in ctx.exact(m, chipsrc_o["macro_query"])
        ),
    )

    x = ctx.query("Rust xref", "xref", REPO, chipsrc_o["xref_query"])["json"]
    ctx.check(
        "Rust xref includes type references",
        bool(x) and chipsrc_o["xref_query"] in json.dumps(x),
    )

    r_show = ctx.run(
        f"{REPO}: inline source",
        "sym",
        bundle,
        chipsrc_o["inline_source_symbol"],
        "--show",
    )
    ctx.check(
        f"{REPO}: inline source contains expected body",
        chipsrc_o["inline_source_contains"] in r_show["stdout"],
    )

    r_multi = ctx.run(
        "Multi-bundle fixture search",
        "search",
        "-b",
        ctx.fixture_bundles_dir,
        "a",
        "--json",
        "--limit",
        "100",
    )
    ctx.check(
        "Multi-bundle fixture discovery",
        isinstance(r_multi["json"], list)
        and len({x.get("bundle_name") for x in r_multi["json"] if isinstance(x, dict)})
        >= 2,
    )

    r_status = ctx.run(
        "Fixture bundles freshness",
        "status",
        ctx.fixture_bundles_dir,
        "--check",
        "--json",
    )
    expected_fx = set(chipsrc_o["fixture_bundles"])
    named_entries = (
        [
            x
            for x in r_status["json"]
            if isinstance(x, dict) and x.get("bundle_name") in expected_fx
        ]
        if isinstance(r_status["json"], list)
        else []
    )
    ctx.check(
        "All fixture bundles fresh",
        len(named_entries) == len(expected_fx)
        and {x.get("bundle_name") for x in named_entries} == expected_fx
        and all(x.get("is_fresh") for x in named_entries),
    )

    for command, text in chipsrc_o["limit_probe_queries"]:
        r = ctx.query(
            f"{command}: max limit 1",
            command,
            REPO,
            text,
            limit=chipsrc_o["max_limit_probe"],
        )
        ctx.check(
            f"{command}: respects limit",
            isinstance(r["json"], list)
            and len(r["json"]) <= chipsrc_o["max_limit_probe"],
        )

    for kind in chipsrc_o["search_kinds"]:
        r = ctx.query(
            f"Search kind {kind}",
            "search",
            REPO,
            chipsrc_o["search_query"],
            kind=kind,
            ignore_case=True,
            limit=chipsrc_o["search_limit"],
        )
        ctx.check(f"Search {kind}: machine readable list", isinstance(r["json"], list))

    r_regex = ctx.query(
        "Regex source search",
        "search",
        REPO,
        chipsrc_o["regex_pattern"],
        source=True,
    )
    ctx.check(
        "Regex finds actual call and definition",
        isinstance(r_regex["json"], list)
        and len(r_regex["json"]) >= chipsrc_o["regex_min_hits"],
    )
    r_sec = ctx.query("Section listing", "section", REPO)
    ctx.check(
        "Section listing non-empty",
        isinstance(r_sec["json"], list) and len(r_sec["json"]) > 0,
    )
    r_sec_body = ctx.run(
        "Section body",
        "section",
        bundle,
        chipsrc_o["section_query"],
        "--show",
    )
    ctx.check(
        "Section body contains signatures",
        chipsrc_o["section_contains"] in r_sec_body["stdout"],
    )
    r_unk = ctx.query("Unknown symbol", "sym", REPO, chipsrc_o["unknown_symbol"])
    ctx.check("Unknown symbol is empty JSON", r_unk["json"] == [])

    for label, neg_args in [
        ("missing repo", ["inspect", ctx.out_dir / "does-not-exist", "--json"]),
        (
            "missing bundle",
            [
                "sym",
                "-b",
                ctx.out_dir / "does-not-exist",
                chipsrc_o["sym_query"],
                "--json",
            ],
        ),
        (
            "bad vendor mode",
            ["inspect", repo_path, "--vendor-mode", "invalid"],
        ),
        (
            "negative limit",
            [
                "sym",
                bundle,
                chipsrc_o["sym_query"],
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

    r_lit = ctx.run(
        "Unbalanced regex literal fallback",
        "search",
        bundle,
        chipsrc_o["literal_fallback_query"],
        "--json",
        "--limit",
        str(chipsrc_o["literal_fallback_limit"]),
    )
    ctx.check(
        "Unbalanced regex remains usable as literal",
        isinstance(r_lit["json"], list),
    )
