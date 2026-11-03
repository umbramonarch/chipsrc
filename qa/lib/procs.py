"""Timing, bundle, and helper-process utilities shared by the QA suites (stdlib only)."""
from pathlib import Path
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time

TIMING_RE = re.compile(r"(scan|parse|link|graph|shard|emit|total)=(\d+)ms")
REPARSE_RE = re.compile(r"\[(\d+)/(\d+)\s+reparsed/reused\]")
REQUIRED_TSVS = ("sections", "symbols", "types", "calls", "macros", "xref")
REQUIRED_ARTIFACTS = (
    "INDEX.md",
    "meta.json",
    "cache/manifest.json",
    *[f"index/{name}.tsv" for name in REQUIRED_TSVS],
)


def parse_timings(stdout: str) -> dict[str, int]:
    """Parse a `--timings` line such as `scan=3ms ... emit=9ms (total=15ms)`."""
    return {name: int(value) for name, value in TIMING_RE.findall(stdout)}


def parse_reparsed(stdout: str) -> tuple[int, int] | None:
    """Parse the `[N/M reparsed/reused]` counter printed by convert/ensure."""
    match = REPARSE_RE.search(stdout)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_hashes(bundle: Path, include_index_md: bool = True) -> dict[str, str]:
    """SHA-256 map over `index/`, `sections/`, and optionally `INDEX.md`."""
    bundle = Path(bundle)
    result: dict[str, str] = {}
    for folder in ("index", "sections"):
        folder_path = bundle / folder
        if not folder_path.is_dir():
            continue
        for path in sorted(folder_path.rglob("*")):
            if path.is_file():
                rel = str(path.relative_to(bundle)).replace("\\", "/")
                result[rel] = file_sha256(path)
    if include_index_md:
        index_md = bundle / "INDEX.md"
        if index_md.is_file():
            result["INDEX.md"] = file_sha256(index_md)
    return result


def hash_diffs(left: dict[str, str], right: dict[str, str]) -> list[str]:
    """Relative paths whose content differs (or exists on only one side)."""
    return sorted(
        key for key in set(left) | set(right) if left.get(key) != right.get(key)
    )


def first_line(path: Path, limit: int = 4096) -> str:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(limit)
    except OSError:
        return ""
    return raw.split(b"\n", 1)[0].decode("utf-8", "replace")


def index_headers(bundle: Path) -> dict[str, str]:
    return {
        name: first_line(Path(bundle) / "index" / f"{name}.tsv")
        for name in REQUIRED_TSVS
    }


def section_md_files(bundle: Path) -> list[str]:
    sections_tsv = Path(bundle) / "index" / "sections.tsv"
    if not sections_tsv.is_file():
        return []
    try:
        with sections_tsv.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle, delimiter="\t"))
    except OSError:
        return []
    return [row.get("md_file", "") for row in rows if row.get("md_file")]


def _json_object(path: Path) -> dict | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def missing_artifacts(bundle: Path) -> list[str]:
    """Missing, empty, or malformed required bundle artifacts (cheap stat/header reads)."""
    bundle = Path(bundle)
    problems: list[str] = []
    for rel in REQUIRED_ARTIFACTS:
        path = bundle / rel
        if not path.is_file():
            problems.append(rel)
        elif path.stat().st_size == 0:
            problems.append(f"{rel} (empty)")
        elif rel.startswith("index/") and not first_line(path).strip():
            problems.append(f"{rel} (missing header)")
    if (bundle / "meta.json").is_file() and _json_object(bundle / "meta.json") is None:
        problems.append("meta.json (invalid JSON)")
    manifest = (
        _json_object(bundle / "cache" / "manifest.json")
        if (bundle / "cache" / "manifest.json").is_file()
        else None
    )
    if manifest is not None and not isinstance(manifest.get("files"), dict):
        problems.append("cache/manifest.json (missing files map)")
    for md_file in section_md_files(bundle):
        if not (bundle / "sections" / md_file).is_file():
            problems.append(f"sections/{md_file}")
    return problems


def find_leftovers(bundle: Path) -> dict[str, list[str]]:
    """Recursively locate `*.tmp` files and `cache/.lock` files inside a bundle."""
    bundle = Path(bundle)
    tmp_files: list[str] = []
    lock_files: list[str] = []
    if not bundle.is_dir():
        return {"tmp_files": tmp_files, "lock_files": lock_files}
    for path in bundle.rglob("*"):
        if not path.is_file():
            continue
        if path.name.endswith(".tmp"):
            tmp_files.append(str(path.relative_to(bundle)).replace("\\", "/"))
        elif path.name == ".lock":
            lock_files.append(str(path.relative_to(bundle)).replace("\\", "/"))
    return {"tmp_files": sorted(tmp_files), "lock_files": sorted(lock_files)}


LOCK_HOLDER_SCRIPT = "\n".join(
    [
        "import os, sys, time",
        "path = sys.argv[1]",
        "hold = float(sys.argv[2])",
        "payload = ('%d:%d' % (os.getpid(), int(time.time() * 1000))).encode('ascii')",
        "with open(path, 'wb') as handle:",
        "    handle.write(payload)",
        "deadline = time.time() + hold",
        "while time.time() < deadline:",
        "    os.utime(path, None)",
        "    time.sleep(0.25)",
    ]
)


def hold_lock_process(lock_path: Path, hold_seconds: float = 120.0) -> subprocess.Popen:
    """Start a helper process that owns a fresh, continuously refreshed lock file."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            LOCK_HOLDER_SCRIPT,
            str(lock_path),
            str(float(hold_seconds)),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_for_path(path: Path, timeout: float = 10.0, interval: float = 0.05) -> bool:
    path = Path(path)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(interval)
    return path.exists()


def stop_process(proc: subprocess.Popen | None, timeout: float = 5.0) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass


if sys.platform == "win32":  # pragma: no cover - exercised on the mission host
    import ctypes
    import ctypes.wintypes as _wintypes

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", _wintypes.DWORD),
            ("PageFaultCount", _wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    def open_process_handle(pid: int):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, int(pid))
        return handle or None

    def peak_working_set_bytes(handle) -> int | None:
        if not handle:
            return None
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        ok = psapi.GetProcessMemoryInfo(
            ctypes.c_void_p(handle),
            ctypes.byref(counters),
            ctypes.sizeof(counters),
        )
        if not ok:
            return None
        return int(counters.PeakWorkingSetSize)

    def close_process_handle(handle) -> None:
        if handle:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(
                ctypes.c_void_p(handle)
            )

else:

    def open_process_handle(pid: int):
        return None

    def peak_working_set_bytes(handle) -> int | None:
        return None

    def close_process_handle(handle) -> None:
        return None
