#!/usr/bin/env python3
"""PostToolUse hook for the chipsrc Claude Code plugin.

Triggered after `Edit`, `Write`, or `MultiEdit` tool calls. When a tracked source file
(`.c`, `.h`, `.cpp`, `.hpp`, `.rs`, `.py`, `.ts`, `.tsx`, `.js`, `.jsx`) is modified,
runs `chipsrc ensure` incrementally via `cache.json` in <50ms so the Agent Codebase
Bundle (`INDEX.md`, `sections/*.md`, `index/*.tsv`, `meta.json`) stays 100% synchronized
with live code edits.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

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

IGNORED_PATH_PARTS = {".git", "target", "node_modules", "output", ".claude", ".factory"}


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


def find_matching_bundles(project_dir: Path, edited_file: Path) -> list[tuple[Path, str, str]]:
    """Return list of (output_root, source_root, vendor_mode) for bundles covering `edited_file`."""
    matches: list[tuple[Path, str, str]] = []
    output_root = project_dir / "output"
    if not output_root.is_dir():
        return matches

    edited_resolved = edited_file.resolve()
    try:
        for child in sorted(output_root.iterdir()):
            if not child.is_dir():
                continue
            meta_path = child / "meta.json"
            if not meta_path.is_file():
                continue
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                meta = data.get("metadata", {})
                source_root = meta.get("source_root")
                vendor_mode = meta.get("vendor_mode", "active")
                if not source_root:
                    continue
                src_path = Path(source_root).resolve()
                if edited_resolved == src_path or src_path in edited_resolved.parents:
                    matches.append((output_root, str(src_path), str(vendor_mode)))
            except Exception:
                continue
    except OSError:
        return matches

    return matches


def main() -> int:
    if os.environ.get("CHIPSRC_DISABLE_AUTO_SYNC") == "1":
        return 0

    try:
        raw_stdin = sys.stdin.read()
        if not raw_stdin.strip():
            return 0
        event = json.loads(raw_stdin)
    except Exception:
        return 0

    tool_name = event.get("tool_name", "")
    if tool_name not in ("Edit", "Write", "MultiEdit"):
        return 0

    tool_input = event.get("tool_input", {}) or {}
    file_path_str = tool_input.get("file_path") or tool_input.get("path") or ""
    if not isinstance(file_path_str, str) or not file_path_str:
        return 0

    edited_path = Path(file_path_str)
    if edited_path.suffix.lower() not in SOURCE_EXTENSIONS:
        return 0

    if any(part in IGNORED_PATH_PARTS for part in edited_path.parts):
        return 0

    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()
    if not edited_path.is_absolute():
        edited_path = (project_dir / edited_path).resolve()

    matches = find_matching_bundles(project_dir, edited_path)
    if not matches:
        return 0

    binary = find_chipsrc_binary(project_dir)
    if not binary:
        return 0

    synced_bundles: list[str] = []
    for output_root, source_root, vendor_mode in matches:
        try:
            proc = subprocess.run(
                [
                    binary,
                    "ensure",
                    source_root,
                    "-o",
                    str(output_root),
                    "--vendor-mode",
                    vendor_mode,
                ],
                cwd=str(project_dir),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                synced_bundles.append(proc.stdout.strip().splitlines()[0])
        except Exception:
            continue

    if synced_bundles:
        payload = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    f"[chipsrc auto-sync] Incrementally updated bundle after editing "
                    f"`{edited_path.name}`: {'; '.join(synced_bundles)}"
                ),
            }
        }
        sys.stdout.write(json.dumps(payload) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
