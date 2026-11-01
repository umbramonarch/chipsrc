"""Native Claude Code hooks black-box suite (5 assertions)."""
import json

from lib.runner import HarnessContext

REPOS = ["volt_website"]

ASSERTION_LABELS = [
    "Session-start refreshes changed source",
    "Post-edit refreshes changed source",
    "Post-edit refreshes equal-size same-second edit",
    "session-start malformed input fails open without panic",
    "post-edit malformed input fails open without panic",
]


def run_suite(ctx: HarnessContext) -> None:
    oracles = ctx.require_oracles(REPOS)
    if oracles is None:
        return
    if not ctx.check_repos_available(REPOS, ASSERTION_LABELS):
        return

    hk = oracles["volt_website"]["hooks"]

    source = ctx.copy_corpus("volt_website", "website-hooks")
    bundle = source / "output" / source.name
    ctx.run("Hook bundle creation", "convert", source, "-o", bundle)

    target = source / hk["target_file"]
    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                hk["old_symbol"],
                hk["renamed_symbol_1"],
            ),
        )
    payload = json.dumps(
        {"cwd": str(source), "hook_event_name": "SessionStart", "source": "startup"}
    )
    ctx.run_hook("Native session-start", source, "session-start", payload)
    r = ctx.run(
        "Query after session-start",
        "sym",
        bundle,
        hk["renamed_symbol_1"],
        "--no-sync",
        "--json",
    )
    ctx.check(
        "Session-start refreshes changed source",
        bool(ctx.exact(r["json"], hk["renamed_symbol_1"])),
    )

    if target.is_file():
        ctx.changed_write(
            target,
            target.read_text(encoding="utf-8").replace(
                hk["renamed_symbol_1"],
                hk["renamed_symbol_2"],
            ),
        )
    payload = json.dumps(
        {
            "cwd": str(source),
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(target)},
        }
    )
    ctx.run_hook("Native post-edit", source, "post-edit", payload)
    r = ctx.run(
        "Query after post-edit",
        "sym",
        bundle,
        hk["renamed_symbol_2"],
        "--no-sync",
        "--json",
    )
    ctx.check(
        "Post-edit refreshes changed source",
        bool(ctx.exact(r["json"], hk["renamed_symbol_2"])),
    )

    if target.is_file():
        ctx.mutate_same_second(
            target,
            hk["renamed_symbol_2"],
            hk["renamed_symbol_3"],
        )
    ctx.run_hook("Native post-edit same-second", source, "post-edit", payload)
    r = ctx.run(
        "Query after same-second post-edit",
        "sym",
        bundle,
        hk["renamed_symbol_3"],
        "--no-sync",
        "--json",
    )
    ctx.check(
        "Post-edit refreshes equal-size same-second edit",
        bool(ctx.exact(r["json"], hk["renamed_symbol_3"])),
    )

    for name in ["session-start", "post-edit"]:
        r = ctx.run_hook(
            f"{name} malformed payload",
            source,
            name,
            hk["malformed_payload"],
        )
        ctx.check(
            f"{name} malformed input fails open without panic",
            r["exit"] == 0 and "panicked at" not in r["stderr"],
        )
