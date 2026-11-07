from pathlib import Path
import csv
import hashlib
import json
import re

TIMING_RE = re.compile(r"(scan|parse|link|graph|shard|emit|total)=(\d+)ms")
REPARSE_RE = re.compile(r"\[(\d+)/(\d+)\s+reparsed/reused\]")
REQUIRED_TSVS = ("sections", "symbols", "types", "calls", "macros", "xref")
REQUIRED_ARTIFACTS = (
    "INDEX.md",
    "meta.json",
    "cache/manifest.json",
    *[f"index/{name}.tsv" for name in REQUIRED_TSVS],
)
MANIFEST_SCHEMA_VERSION = "2.1.0"
INVALID_MANIFEST = "invalid cache/manifest.json"


def parse_timings(stdout: str) -> dict[str, int]:
    return {name: int(value) for name, value in TIMING_RE.findall(stdout)}


def parse_reparsed(stdout: str) -> tuple[int, int] | None:
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


def _manifest_shard_problems(bundle: Path) -> list[str]:
    manifest_path = bundle / "cache" / "manifest.json"
    if not manifest_path.is_file() or manifest_path.stat().st_size == 0:
        return []
    manifest = _json_object(manifest_path)
    if manifest is None or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        return [INVALID_MANIFEST]
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return [INVALID_MANIFEST]
    shards: set[str] = set()
    for entry in files.values():
        shard = entry.get("shard") if isinstance(entry, dict) else None
        if not isinstance(shard, str) or not shard.strip():
            return [INVALID_MANIFEST]
        shards.add(shard.replace("\\", "/"))
    return sorted(shard for shard in shards if not (bundle / shard).is_file())


def manifest_file_count(bundle: Path) -> int:
    manifest = _json_object(Path(bundle) / "cache" / "manifest.json")
    files = manifest.get("files") if isinstance(manifest, dict) else None
    return len(files) if isinstance(files, dict) else 0


def missing_artifacts(bundle: Path) -> list[str]:
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
    problems.extend(_manifest_shard_problems(bundle))
    for md_file in section_md_files(bundle):
        if not (bundle / "sections" / md_file).is_file():
            problems.append(f"sections/{md_file}")
    return problems
