"""Cross-run guard that serializes large-corpus (STM32CubeF4 / ETL) conversions.

The mission's validator guidance reserves the directory
``<corpus-root>/validators/.large-convert.lock`` for exactly one large conversion at
a time (see ``library/user-testing.md``).  The scale suite claims the same directory
before it starts a cold conversion and releases it when finished, so a harness run and
a validator convert never overlap; when the guard is already held the suite records
``skipped`` assertions with the holder path instead of failing.
"""
from pathlib import Path
import json
import os
import shutil
import time

LOCK_DIR_NAME = ".large-convert.lock"


def default_lock_path(corpus_root: Path) -> Path:
    return Path(corpus_root) / "validators" / LOCK_DIR_NAME


class LargeConvertLock:
    """Directory-based advisory guard around large-corpus conversions."""

    def __init__(
        self,
        path: Path,
        wait_seconds: float = 120.0,
        stale_seconds: float = 3600.0,
        poll_seconds: float = 2.0,
        owner: str = "qa-blackbox",
    ) -> None:
        self.path = Path(path)
        self.wait_seconds = float(wait_seconds)
        self.stale_seconds = float(stale_seconds)
        self.poll_seconds = max(float(poll_seconds), 0.05)
        self.owner = owner
        self._held = False

    def held(self) -> bool:
        return self._held

    def _holder_age(self) -> float | None:
        try:
            return time.time() - self.path.stat().st_mtime
        except OSError:
            return None

    def _reclaim_if_stale(self) -> bool:
        age = self._holder_age()
        if age is None or age <= self.stale_seconds:
            return False
        if self.path.is_dir():
            shutil.rmtree(self.path, ignore_errors=True)
        else:
            try:
                self.path.unlink()
            except OSError:
                return False
        return True

    def acquire(self) -> tuple[bool, str]:
        deadline = time.monotonic() + self.wait_seconds
        while True:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.mkdir()
            except FileExistsError:
                pass
            except OSError as exc:
                return False, f"cannot claim large-convert guard {self.path}: {exc}"
            else:
                try:
                    (self.path / "owner.json").write_text(
                        json.dumps(
                            {
                                "pid": os.getpid(),
                                "owner": self.owner,
                                "claimed_ms": int(time.time() * 1000),
                            }
                        ),
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                self._held = True
                return True, f"claimed {self.path}"

            if self._reclaim_if_stale():
                continue
            age = self._holder_age()
            if age is None:
                continue
            if time.monotonic() >= deadline:
                return (
                    False,
                    "another large convert holds "
                    f"{self.path} (held {age:.0f}s); skipping large-corpus budgets",
                )
            time.sleep(self.poll_seconds)

    def release(self) -> None:
        if not self._held:
            return
        shutil.rmtree(self.path, ignore_errors=True)
        self._held = False
