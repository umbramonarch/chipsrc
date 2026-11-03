"""Unit tests for the large-convert guard (`qa/lib/lockguard.py`).

Run with ``python -m unittest discover -s qa/tests -p "test_*.py"`` from the repository root.

The interesting cases are the injected-schedule stale-reclamation races: while one contender is
deciding whether an owner is stale, a second contender can replace the guard.  The guard must keep
the fresh replacement and refuse every other contender instead of leaving two live owners.
"""
from pathlib import Path
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

QA_ROOT = Path(__file__).resolve().parent.parent
if str(QA_ROOT) not in sys.path:
    sys.path.insert(0, str(QA_ROOT))

from lib.lockguard import (  # noqa: E402
    LOCK_DIR_NAME,
    OWNER_FILE_NAME,
    RECLAIM_DIR_SUFFIX,
    LargeConvertLock,
)

STALE_SECONDS = 1800.0


class ScheduledLock(LargeConvertLock):
    """Guard that runs an injected step immediately after its first holder-age observation."""

    def __init__(self, *args, after_first_age=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._after_first_age = after_first_age
        self._age_calls = 0

    def _holder_age(self):
        age = super()._holder_age()
        self._age_calls += 1
        if self._age_calls == 1 and self._after_first_age is not None:
            hook, self._after_first_age = self._after_first_age, None
            hook()
        return age


def _write_owner(lock_path: Path, token: str, age_s: float, owner: str = "crashed") -> None:
    (lock_path / OWNER_FILE_NAME).write_text(
        json.dumps(
            {
                "pid": 999_999,
                "token": token,
                "owner": owner,
                "created_ms": int((time.time() - age_s) * 1000),
            }
        ),
        encoding="utf-8",
    )


class LargeConvertLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="chipsrc_lockguard_"))
        self.lock_path = self.tmp / LOCK_DIR_NAME
        self.created: list[LargeConvertLock] = []

    def tearDown(self) -> None:
        for guard in self.created:
            try:
                guard.release()
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _guard(self, **kwargs) -> LargeConvertLock:
        options = {
            "wait_seconds": 0.4,
            "stale_seconds": STALE_SECONDS,
            "poll_seconds": 0.05,
        }
        options.update(kwargs)
        guard = LargeConvertLock(self.lock_path, **options)
        self.created.append(guard)
        return guard

    # -- basic ownership ---------------------------------------------------------

    def test_acquire_and_release_keep_owner_token(self) -> None:
        guard = self._guard(owner="A")
        acquired, reason = guard.acquire()
        self.assertTrue(acquired, reason)
        self.assertTrue(guard.held())
        self.assertTrue(self.lock_path.is_dir())
        owner = json.loads((self.lock_path / OWNER_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(owner["token"], guard.token)
        self.assertIsNotNone(guard._owner_fp, "the live owner handle must stay open")

        guard.release()
        self.assertFalse(guard.held())
        self.assertFalse(self.lock_path.exists())
        self.assertIsNone(guard._owner_fp)
        self.assertFalse(list(self.tmp.glob(f"{LOCK_DIR_NAME}.stale.*")))

    def test_live_owner_blocks_a_second_contender(self) -> None:
        owner = self._guard(owner="A")
        self.assertTrue(owner.acquire()[0])
        contender = self._guard(owner="B")
        acquired, reason = contender.acquire()
        self.assertFalse(acquired, reason)
        self.assertFalse(contender.held())
        self.assertTrue(owner.held())
        self.assertEqual(
            json.loads((self.lock_path / OWNER_FILE_NAME).read_text(encoding="utf-8"))[
                "token"
            ],
            owner.token,
        )

    def test_abandoned_stale_lock_is_reclaimed(self) -> None:
        self.lock_path.mkdir()
        _write_owner(self.lock_path, "crashed-token", STALE_SECONDS * 2)
        guard = self._guard(owner="A")
        acquired, reason = guard.acquire()
        self.assertTrue(acquired, reason)
        self.assertTrue(guard.held())
        owner = json.loads((self.lock_path / OWNER_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(owner["token"], guard.token)
        self.assertFalse(list(self.tmp.glob(f"{LOCK_DIR_NAME}.stale.*")))
        self.assertFalse((self.tmp / f"{LOCK_DIR_NAME}{RECLAIM_DIR_SUFFIX}").exists())

    def test_release_never_removes_a_replacement_owner(self) -> None:
        guard = self._guard(owner="A")
        self.assertTrue(guard.acquire()[0], "A must acquire")
        (self.lock_path / OWNER_FILE_NAME).write_text(
            json.dumps({"pid": 1, "token": "replacement", "created_ms": int(time.time() * 1000)}),
            encoding="utf-8",
        )
        guard.release()
        self.assertTrue(
            self.lock_path.is_dir(), "a replacement lock must survive the original release()"
        )

    # -- stale-reclamation races -------------------------------------------------

    def test_three_contender_stale_reclamation_preserves_owner_a(self) -> None:
        """B observes the stale lock, A replaces it, then C arrives: only A may hold."""
        self.lock_path.mkdir()
        _write_owner(self.lock_path, "crashed-token", STALE_SECONDS * 2)

        owner_a = self._guard(owner="A", wait_seconds=1.0)

        def a_replaces_the_stale_lock() -> None:
            acquired, reason = owner_a.acquire()
            self.assertTrue(acquired, f"owner A must win the stale reclamation: {reason}")

        b = ScheduledLock(
            self.lock_path,
            wait_seconds=0.4,
            stale_seconds=STALE_SECONDS,
            poll_seconds=0.05,
            owner="B",
            after_first_age=a_replaces_the_stale_lock,
        )
        self.created.append(b)
        b_acquired, b_reason = b.acquire()

        c = self._guard(owner="C")
        c_acquired, c_reason = c.acquire()

        a_held = owner_a.held()
        two_live_owners = sum(1 for guard in (owner_a, b, c) if guard.held()) > 1

        self.assertTrue(a_held, "owner A must still hold the guard")
        self.assertFalse(b_acquired, f"B must be refused, got: {b_reason}")
        self.assertFalse(c_acquired, f"C must be refused, got: {c_reason}")
        self.assertFalse(two_live_owners, "two guards must never hold the same lock")
        owner = json.loads((self.lock_path / OWNER_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(owner["token"], owner_a.token, "the canonical owner must be A")
        self.assertFalse(list(self.tmp.glob(f"{LOCK_DIR_NAME}.stale.*")))
        self.assertFalse((self.tmp / f"{LOCK_DIR_NAME}{RECLAIM_DIR_SUFFIX}").exists())

        owner_a.release()
        self.assertFalse(self.lock_path.exists(), "A's release must clear the guard")

    @unittest.skipUnless(os.name == "nt", "Windows NTFS handle-locking semantics")
    def test_live_owner_handle_blocks_stale_displacement(self) -> None:
        """A reclaimer that believes A is stale must still fail while A's handle is open."""
        owner_a = self._guard(owner="A")
        self.assertTrue(owner_a.acquire()[0], "A must acquire")
        # Backdate the persisted claim so every contender considers A stale; the open
        # `owner.json` handle is what protects the live directory on Windows.
        (self.lock_path / OWNER_FILE_NAME).write_text(
            json.dumps(
                {
                    "pid": 999_999,
                    "token": "looks-stale",
                    "owner": "A",
                    "created_ms": int((time.time() - STALE_SECONDS * 2) * 1000),
                }
            ),
            encoding="utf-8",
        )

        contender = self._guard(owner="B", wait_seconds=0.3)
        b_acquired, b_reason = contender.acquire()

        self.assertFalse(b_acquired, f"a live owner must never be displaced: {b_reason}")
        self.assertTrue(owner_a.held(), "A must still be the live owner")
        self.assertTrue(self.lock_path.is_dir(), "the canonical directory must remain")
        self.assertFalse(
            list(self.tmp.glob(f"{LOCK_DIR_NAME}.stale.*")),
            "a rejected reclamation must not leave a displaced directory behind",
        )
        owner = json.loads((self.lock_path / OWNER_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(owner["token"], "looks-stale")

    def test_third_contender_cannot_enter_during_displacement_window(self) -> None:
        """C acquires *inside* B's rename window, the exact schedule from the round-2 finding."""
        self.lock_path.mkdir()
        _write_owner(self.lock_path, "crashed-token", STALE_SECONDS * 2)

        owner_a = self._guard(owner="A", wait_seconds=1.0)

        def a_replaces_the_stale_lock() -> None:
            acquired, reason = owner_a.acquire()
            self.assertTrue(acquired, f"owner A must win the stale reclamation: {reason}")

        b = ScheduledLock(
            self.lock_path,
            wait_seconds=0.4,
            stale_seconds=STALE_SECONDS,
            poll_seconds=0.05,
            owner="B",
            after_first_age=a_replaces_the_stale_lock,
        )
        self.created.append(b)

        # Patch `os.rename` only for this test so C contends exactly while B tries to displace the
        # directory it still believes is stale (B's first attempt captures A's fresh lock).
        import lib.lockguard as lockguard

        real_rename = lockguard.os.rename
        injected: list[bool] = []

        def hooked_rename(src, dst):
            result = real_rename(src, dst)
            if not injected and Path(src) == self.lock_path:
                injected.append(True)
                # The live owner's open handle must make this fail on Windows; where rename is
                # permitted the reclaim-dir claim still keeps C out of the canonical path.
                c = self._guard(owner="C", wait_seconds=0.2)
                c_acquired, _ = c.acquire()
                self.assertFalse(
                    c_acquired, "no contender may acquire while a live owner holds the guard"
                )
            return result

        lockguard.os.rename = hooked_rename
        try:
            b_acquired, b_reason = b.acquire()
        finally:
            lockguard.os.rename = real_rename

        self.assertTrue(injected, "the injected rename window must have been reached")
        self.assertFalse(b_acquired, f"B must be refused, got: {b_reason}")
        self.assertTrue(owner_a.held(), "owner A must remain the live owner")
        self.assertEqual(
            sum(1 for guard in self.created if guard.held()),
            1,
            "exactly one guard may hold the lock",
        )
        owner = json.loads((self.lock_path / OWNER_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(owner["token"], owner_a.token)
        self.assertFalse(list(self.tmp.glob(f"{LOCK_DIR_NAME}.stale.*")))
        self.assertFalse((self.tmp / f"{LOCK_DIR_NAME}{RECLAIM_DIR_SUFFIX}").exists())

    def test_abandoned_reclaim_claim_is_cleared(self) -> None:
        """A crashed reclaimer's abandoned claim must not wedge the guard forever."""
        self.lock_path.mkdir()
        _write_owner(self.lock_path, "crashed-token", STALE_SECONDS * 2)
        reclaim_dir = self.tmp / f"{LOCK_DIR_NAME}{RECLAIM_DIR_SUFFIX}"
        reclaim_dir.mkdir()
        stat = reclaim_dir.stat()
        import os

        os.utime(reclaim_dir, (stat.st_atime, time.time() - 120.0))

        guard = self._guard(owner="A")
        acquired, reason = guard.acquire()
        self.assertTrue(acquired, reason)
        self.assertFalse(reclaim_dir.exists(), "the abandoned claim must be removed")


if __name__ == "__main__":
    unittest.main()
