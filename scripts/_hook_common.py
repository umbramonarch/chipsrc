#!/usr/bin/env python3
"""Shared constants and path/binary helpers for chipsrc Claude Code hooks."""

from __future__ import annotations

import os
from pathlib import Path
import shutil

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
    ".astro",
    ".vue",
    ".svelte",
}


def norm_path_str(p: str | Path) -> str:
    raw = str(p)
    if raw.startswith("\\\\?\\"):
        raw = raw[4:]
    return os.path.normcase(os.path.normpath(os.path.abspath(raw)))


def is_path_within(child: str | Path, parent: str | Path) -> bool:
    c_norm = norm_path_str(child)
    p_norm = norm_path_str(parent)
    if c_norm == p_norm:
        return True
    prefix = p_norm.rstrip("\\/") + os.sep
    return c_norm.startswith(prefix)


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
