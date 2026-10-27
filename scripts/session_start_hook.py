#!/usr/bin/env python3
"""SessionStart hook for the chipsrc Claude Code plugin.

Scans the workspace in <15ms for indexed chipsrc codebase bundles (`output/*/meta.json`)
and source repositories, optionally refreshing existing bundles via `chipsrc ensure`
and injecting a compact orientation summary into the session context so the agent
immediately knows which codebase bundles and 1-turn code intelligence commands are ready.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

IGNORED_DIRS = {
    ".git",
    "target",
    "node_modules",
    "bin",
    "output",
    "dist",
    "build",
    ".claude",
    ".factory",
    ".venv",
    "venv",
}

SOURCE_EXTENSIONS = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".hh",
    ".hxx",
    ".inl",
    ".rs",
    ".py",
    ".pyi",
    ".ts",
    ".mts",
    ".cts",
    ".tsx",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
}


def find_chipsrc_binary(project_dir: Path) -> str | None:
    env_bin = os.environ.get("CHIPSRC_BIN")
    if env_bin and Path(env_bin).is_file():
        return env_bin

    which_bin = shutil.which("chipsrc")
    if which_bin:
        return which_bin

    plugin_root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", project_dir)).resolve()
    exe_names = ["chipsrc.exe", "chipsrc"] if os.name == "nt" else ["chipsrc"]
    for base in (project_dir, plugin_root):
        for profile in ("release", "debug"):
            for exe in exe_names:
                candidate = base / "target" / profile / exe
                if candidate.is_file():
                    return str(candidate)
    return None


def find_bundles(root: Path) -> list[dict]:
    bundles: list[dict] = []
    candidates = [root, root / "output"]
    seen: set[Path] = set()
    for base in candidates:
        if not base.is_dir():
            continue
        try:
            entries = [base] if (base / "meta.json").is_file() else sorted(base.iterdir())
            for child in entries:
                if not child.is_dir() or child in seen:
                    continue
                meta_path = child / "meta.json"
                index_path = child / "INDEX.md"
                if meta_path.is_file() and index_path.is_file():
                    seen.add(child)
                    try:
                        data = json.loads(meta_path.read_text(encoding="utf-8"))
                        meta = data.get("metadata", {})
                        sanity = data.get("sanity", {})
                        if "symbol_count" not in meta and "languages" not in meta:
                            continue
                        rel_path = (
                            child.relative_to(root).as_posix()
                            if child != root
                            else "."
                        )
                        bundles.append(
                            {
                                "name": meta.get("repo_name", child.name),
                                "path": rel_path,
                                "source_root": meta.get("source_root", "."),
                                "vendor_mode": meta.get("vendor_mode", "active"),
                                "files": meta.get("total_files", 0),
                                "symbols": meta.get("symbol_count", 0),
                                "types": meta.get("type_count", 0),
                                "calls": meta.get("call_edge_count", 0),
                                "macros": meta.get("macro_count", 0),
                                "xrefs": meta.get("xref_count", 0),
                                "sections": meta.get("section_count", 0),
                                "score": sanity.get("score", 0),
                            }
                        )
                    except Exception:
                        continue
        except OSError:
            continue
    return bundles


def has_source_files(root: Path, max_depth: int = 3) -> bool:
    def walk(curr: Path, depth: int) -> bool:
        if depth > max_depth:
            return False
        try:
            for entry in curr.iterdir():
                if entry.is_dir():
                    if entry.name.startswith(".") or entry.name in IGNORED_DIRS:
                        continue
                    if walk(entry, depth + 1):
                        return True
                elif entry.suffix.lower() in SOURCE_EXTENSIONS:
                    return True
        except OSError:
            return False
        return False

    return walk(root, 0)


def refresh_existing_bundles(project_dir: Path, bundles: list[dict]) -> None:
    binary = find_chipsrc_binary(project_dir)
    if not binary or not bundles:
        return
    output_root = project_dir / "output"
    for b in bundles:
        source_root = b.get("source_root") or str(project_dir)
        vendor_mode = b.get("vendor_mode") or "active"
        if not Path(source_root).is_dir():
            continue
        try:
            subprocess.run(
                [
                    binary,
                    "ensure",
                    str(source_root),
                    "-o",
                    str(output_root),
                    "--vendor-mode",
                    str(vendor_mode),
                ],
                cwd=str(project_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except Exception:
            continue


def main() -> int:
    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()
    bundles = find_bundles(project_dir)
    if bundles:
        refresh_existing_bundles(project_dir, bundles)
        bundles = find_bundles(project_dir)

    repo_has_sources = has_source_files(project_dir)
    if not bundles and not repo_has_sources:
        return 0

    lines: list[str] = ["[chipsrc] Source Code & Hardware Cross-Reference Intelligence active:"]
    if bundles:
        summary = ", ".join(
            f"`{b['path']}` ({b['files']} files, {b['symbols']} syms, {b['types']} types, "
            f"{b['calls']} calls, {b['macros']} macros/MMIO, sanity {b['score']}/100)"
            for b in bundles
        )
        lines.append(f"- Indexed codebase bundles ready (auto-synced via `cache.json`): {summary}")
    else:
        lines.append(
            "- Unindexed source repository detected (run `chipsrc ensure . -o output` to build the Agent Codebase Bundle)."
        )

    lines.append(
        "- Prefer 1-turn CLI queries over blind Grep/Read loops (all queries auto-refresh changed files): "
        "`chipsrc sym <name> [-s]`, `chipsrc callers <fn>`, `chipsrc callees <fn>`, "
        "`chipsrc type <name> [-s]`, `chipsrc macro|reg|mmio <name|0xHEX>`, "
        "`chipsrc xref <symbol>`, `chipsrc section [query] [-s]`, `chipsrc search <pattern>`."
    )

    payload = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "\n".join(lines),
        }
    }
    sys.stdout.write(json.dumps(payload) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
