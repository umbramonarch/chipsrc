"""Cross-run guard that serializes large-corpus (STM32CubeF4 / ETL) conversions.

The mission's validator guidance reserves the directory
``<corpus-root>/validators/.large-convert.lock`` for exactly one large conversion at
a time (see ``library/user-testing.md``).  The scale suite claims the same directory
before it starts a cold conversion and releases it when finished, so a harness run and
a validator convert never overlap; when the guard is already held the suite records
``skipped`` assertions with the holder path instead of failing.

Ownership safety
----------------
The claim writes ``owner.json`` (pid, per-process token, claim time) inside the lock
directory and keeps a file handle to ``owner.json`` open for the whole hold.  On
Windows an open handle without delete sharing makes ``os.rename`` of the containing
directory fail with ``PermissionError``, so a stale reclaimer can never displace a
live owner.  ``release()`` closes the handle, re-reads the token, and only removes the
directory when ``owner.json`` still carries this guard's token.

Stale reclamation is itself guarded by a sibling ``<lock>.reclaim`` directory that
acquisition also respects: a reclaimer claims it, re-checks the holder age *after* the
claim, and only then renames the stale directory aside.  A third contender therefore
cannot slip into the canonical path while a fresh replacement claim is being
displaced, and a reclaimer that observed a stale owner before another process
replaced it aborts instead of moving the replacement.
"""
from pathlib import Path
import json
import os
import shutil
import time
import uuid

LOCK_DIR_NAME = ".large-convert.lock"
OWNER_FILE_NAME = "owner.json"
RECLAIM_DIR_SUFFIX = ".reclaim"
#: A reclamation claim is held for milliseconds; anything older than this was abandoned by a
#: crashed reclaimer and may be cleared by the next contender.
RECLAIM_CLAIM_MAX_AGE_S = 60.0


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
        self.token = uuid.uuid4().hex
        self._held = False
        #: Open handle to ``owner.json``; blocks ``os.rename`` of the lock directory on Windows.
        self._owner_fp = None

    # -- teardown -----------------------------------------------------------------

    def __del__(self) -> None:  # pragma: no cover - best-effort interpreter cleanup
        try:
            self._close_owner_fp()
        except Exception:
            pass

    def _close_owner_fp(self) -> None:
        """Closes the live ``owner.json`` handle (idempotent)."""
        fp = getattr(self, "_owner_fp", None)
        if fp is not None:
            try:
                fp.close()
            except OSError:
                pass
            self._owner_fp = None

    # -- state --------------------------------------------------------------------

    def held(self) -> bool:
        return self._held

    def reclaim_dir(self) -> Path:
        """Sibling directory that coordinates concurrent stale reclamation."""
        return self.path.with_name(f"{self.path.name}{RECLAIM_DIR_SUFFIX}")

    @staticmethod
    def _read_owner_from(path: Path) -> dict | None:
        try:
            data = json.loads(
                (Path(path) / OWNER_FILE_NAME).read_text(encoding="utf-8")
            )
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _read_owner(self) -> dict | None:
        return self._read_owner_from(self.path)

    def _write_owner(self) -> bool:
        """Writes this guard's owner payload and keeps the file handle open."""
        owner_path = self.path / OWNER_FILE_NAME
        try:
            fp = open(owner_path, "w", encoding="utf-8")
        except OSError:
            return False
        try:
            fp.write(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "token": self.token,
                        "owner": self.owner,
                        "created_ms": int(time.time() * 1000),
                    }
                )
            )
            fp.flush()
        except OSError:
            _safe_close(fp)
            try:
                owner_path.unlink()
            except OSError:
                pass
            return False
        self._owner_fp = fp
        return True

    @staticmethod
    def _path_age(path: Path) -> float | None:
        """Age in seconds from ``owner.json.created_ms``, falling back to directory mtime."""
        owner = LargeConvertLock._read_owner_from(path)
        created_ms = owner.get("created_ms") if owner is not None else None
        if isinstance(created_ms, (int, float)) and not isinstance(created_ms, bool):
            return max(0.0, time.time() - float(created_ms) / 1000.0)
        try:
            return time.time() - Path(path).stat().st_mtime
        except OSError:
            return None

    def _holder_age(self) -> float | None:
        return self._path_age(self.path)

    def _reclaim_claim_active(self) -> bool:
        """True when another contender holds a fresh ``<lock>.reclaim`` claim."""
        reclaim_dir = self.reclaim_dir()
        age = self._path_age(reclaim_dir)
        return age is not None and age <= RECLAIM_CLAIM_MAX_AGE_S

    def _claim_reclaim_dir(self) -> bool:
        """Takes the reclamation claim; clears an abandoned one first."""
        reclaim_dir = self.reclaim_dir()
        try:
            reclaim_dir.mkdir()
            return True
        except FileExistsError:
            age = self._path_age(reclaim_dir)
            if age is None or age <= RECLAIM_CLAIM_MAX_AGE_S:
                return False
            # A crashed reclaimer left the claim behind; clear it and take over once.
            shutil.rmtree(reclaim_dir, ignore_errors=True)
            try:
                reclaim_dir.mkdir()
                return True
            except OSError:
                return False
        except OSError:
            return False

    def _reclaim_if_stale(self) -> bool:
        age = self._holder_age()
        if age is None or age <= self.stale_seconds:
            return False
        if not self._claim_reclaim_dir():
            return False
        reclaim_dir = self.reclaim_dir()
        try:
            # Re-check after claiming the reclaim directory: the owner may have been replaced by a
            # fresh claim between our first observation and the claim. The live owner's open
            # `owner.json` handle also makes the rename below fail on Windows.
            age = self._holder_age()
            if age is None or age <= self.stale_seconds:
                return False
            if not self.path.is_dir():
                try:
                    self.path.unlink()
                except OSError:
                    return False
                return True
            stale_path = self.path.with_name(f"{self.path.name}.stale.{uuid.uuid4().hex}")
            try:
                os.rename(self.path, stale_path)
            except OSError:
                return False
            stale_age = self._path_age(stale_path)
            if stale_age is not None and stale_age <= self.stale_seconds:
                # A replacement lock claimed the path between our age check and the rename;
                # restore it untouched instead of deleting a live lock.
                try:
                    os.rename(stale_path, self.path)
                except OSError:
                    pass
                return False
            shutil.rmtree(stale_path, ignore_errors=True)
            return True
        finally:
            shutil.rmtree(reclaim_dir, ignore_errors=True)

    def acquire(self) -> tuple[bool, str]:
        deadline = time.monotonic() + self.wait_seconds
        while True:
            claimed = False
            if not self._reclaim_claim_active():
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    self.path.mkdir()
                    claimed = True
                except FileExistsError:
                    pass
                except OSError as exc:
                    return False, f"cannot claim large-convert guard {self.path}: {exc}"
            if claimed:
                if not self._write_owner():
                    self._close_owner_fp()
                    shutil.rmtree(self.path, ignore_errors=True)
                    return (
                        False,
                        f"cannot write {OWNER_FILE_NAME} inside {self.path}; "
                        "refusing to hold the large-convert guard",
                    )
                self._held = True
                return True, f"claimed {self.path}"

            if self._reclaim_if_stale():
                continue
            age = self._holder_age()
            if age is None:
                # The guard vanished or is unreadable mid-poll: retry, but never spin
                # past the wait deadline.
                if time.monotonic() >= deadline:
                    return (
                        False,
                        f"cannot inspect large-convert guard {self.path}; "
                        "skipping large-corpus budgets",
                    )
                time.sleep(self.poll_seconds)
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
            self._close_owner_fp()
            return
        owner = self._read_owner()
        owns_token = owner is not None and owner.get("token") == self.token
        # Close the live handle *before* removal: on Windows the open `owner.json` handle
        # prevents the directory from being renamed or deleted.
        self._close_owner_fp()
        if owns_token:
            shutil.rmtree(self.path, ignore_errors=True)
        self._held = False


def _safe_close(fp) -> None:
    try:
        fp.close()
    except OSError:
        pass
