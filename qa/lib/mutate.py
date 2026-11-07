from pathlib import Path
import os
import time

NS_PER_SEC = 10**9
SUBSEC_DELTA_NS = 10**8
ADVANCE_SECS_NS = 2 * (10**9)


def changed_write(path: Path, body: str) -> None:
    before = path.stat().st_mtime_ns if path.exists() else time.time_ns()
    path.write_text(body, encoding="utf-8")
    stamp = max(time.time_ns(), before + ADVANCE_SECS_NS)
    os.utime(path, ns=(stamp, stamp))


def mutate_same_second(path: Path, old_text: str, new_text: str) -> tuple[bool, dict]:
    prior = path.stat()
    raw = path.read_bytes()
    updated = raw.replace(old_text.encode("utf-8"), new_text.encode("utf-8"))
    path.write_bytes(updated)

    prior_ns = prior.st_mtime_ns
    subsec = prior_ns % NS_PER_SEC
    if subsec + SUBSEC_DELTA_NS < NS_PER_SEC:
        stamp = prior_ns + SUBSEC_DELTA_NS
    else:
        stamp = prior_ns - SUBSEC_DELTA_NS

    os.utime(path, ns=(stamp, stamp))
    after = path.stat()

    same_size = after.st_size == prior.st_size
    same_sec = (
        int(after.st_mtime) == int(prior.st_mtime)
        and (after.st_mtime_ns // NS_PER_SEC) == (prior.st_mtime_ns // NS_PER_SEC)
    )
    diff_ns = after.st_mtime_ns != prior.st_mtime_ns
    passed = same_size and same_sec and diff_ns
    detail = {
        "st_size": [prior.st_size, after.st_size],
        "mtime_sec": [int(prior.st_mtime), int(after.st_mtime)],
        "st_mtime_ns": [prior.st_mtime_ns, after.st_mtime_ns],
    }
    return passed, detail
