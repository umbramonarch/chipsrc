"""Regression tests for the per-binary bundle marker in `qa/lib/runner.py`.

A cached baseline/fixture bundle produced by an older `chipsrc.exe` can hold tables built by
code paths that no longer exist (the historical stale `index/calls.tsv` failure), so a binary
change must force a clean rebuild rather than an incremental sync over stale artifacts.
"""
from pathlib import Path
import sys
import tempfile
import unittest

QA_ROOT = Path(__file__).resolve().parents[1]
if str(QA_ROOT) not in sys.path:
    sys.path.insert(0, str(QA_ROOT))

from lib import procs  # noqa: E402
from lib.runner import BINARY_MARKER, HarnessContext  # noqa: E402

TABLE_NAMES = ("symbols", "types", "calls", "macros", "xref", "sections")


class _FakeBuildContext(HarnessContext):
    """Context whose `convert` never runs a real binary but writes a plausible bundle."""

    def __init__(self, *args, **kwargs) -> None:
        self.build_calls = 0
        self.fresh = False
        super().__init__(*args, **kwargs)

    def _bundle_is_ready_and_fresh(self, repo_path: Path, bundle_dir: Path) -> bool:
        return self.fresh

    def _exec_Raw(self, cmd_args, cwd, stdin_text=None, env=None):
        self.build_calls += 1
        bundle_dir = Path(cmd_args[-1])
        (bundle_dir / "index").mkdir(parents=True, exist_ok=True)
        for name in TABLE_NAMES:
            (bundle_dir / "index" / f"{name}.tsv").write_text("header\n", encoding="utf-8")
        (bundle_dir / "INDEX.md").write_text("# bundle\n", encoding="utf-8")
        (bundle_dir / "meta.json").write_text("{}\n", encoding="utf-8")
        (bundle_dir / "cache").mkdir(parents=True, exist_ok=True)
        (bundle_dir / "cache" / "manifest.json").write_text("{}\n", encoding="utf-8")
        self.fresh = True
        return 0, 1.0, "", "", None


class BinaryMarkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "chipsrc.exe").write_bytes(b"fake-binary-v1")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _context(self, mode: str = "build") -> _FakeBuildContext:
        return _FakeBuildContext(
            suite_name="marker-test",
            bin_path=self.root / "chipsrc.exe",
            repos_root=self.root / "repos",
            corpus_root=self.root / "corpus",
            out_dir=self.root / "out",
            oracles_dir=self.root / "oracles",
            fixtures_dir=self.root / "fixtures",
            timeout=5.0,
            fixtures_mode=mode,
        )

    def _bundle(self, relative: str, marker: str | None) -> Path:
        bundle = self.root / "out" / relative
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "stale-artifact.txt").write_text("old binary output\n", encoding="utf-8")
        if marker is not None:
            (bundle / BINARY_MARKER).write_text(marker + "\n", encoding="utf-8")
        return bundle

    def test_binary_change_forces_clean_rebuild(self) -> None:
        ctx = self._context()
        bundle = self._bundle("bundles/repo", "0" * 64)
        self.assertTrue(ctx.ensure_repo_bundle("repo", self.root / "repos" / "repo"))
        digest = procs.file_sha256(self.root / "chipsrc.exe")
        self.assertEqual(ctx.build_calls, 1)
        self.assertFalse((bundle / "stale-artifact.txt").exists())
        self.assertEqual(ctx.read_binary_marker(bundle), digest)

    def test_matching_marker_reuses_bundle(self) -> None:
        ctx = self._context()
        digest = procs.file_sha256(self.root / "chipsrc.exe")
        bundle = self._bundle("bundles/repo", digest)
        ctx.fresh = True
        self.assertTrue(ctx.ensure_repo_bundle("repo", self.root / "repos" / "repo"))
        self.assertEqual(ctx.build_calls, 0)
        self.assertTrue((bundle / "stale-artifact.txt").exists())
        self.assertEqual(ctx.read_binary_marker(bundle), digest)

    def test_missing_marker_rebuilds_cached_bundle(self) -> None:
        ctx = self._context()
        bundle = self._bundle("bundles/repo", None)
        self.assertTrue(ctx.ensure_repo_bundle("repo", self.root / "repos" / "repo"))
        self.assertEqual(ctx.build_calls, 1)
        self.assertFalse((bundle / "stale-artifact.txt").exists())
        self.assertIsNotNone(ctx.read_binary_marker(bundle))

    def test_require_mode_ignores_marker_and_keeps_bundle(self) -> None:
        ctx = self._context(mode="require")
        bundle = self._bundle("bundles/repo", "f" * 64)
        ctx.fresh = True
        self.assertTrue(ctx.ensure_repo_bundle("repo", self.root / "repos" / "repo"))
        self.assertEqual(ctx.build_calls, 0)
        self.assertTrue((bundle / "stale-artifact.txt").exists())
        self.assertEqual(ctx.read_binary_marker(bundle), "f" * 64)

    def test_fixture_bundle_records_marker_under_fixture_bundles(self) -> None:
        ctx = self._context()
        fixture = self.root / "fixtures" / "cpp"
        fixture.mkdir(parents=True, exist_ok=True)
        (fixture / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        bundle = self._bundle("fixture-bundles/cpp", "0" * 64)
        self.assertTrue(ctx.ensure_fixture_bundle("cpp", fixture))
        digest = procs.file_sha256(self.root / "chipsrc.exe")
        self.assertEqual(ctx.build_calls, 1)
        self.assertFalse((bundle / "stale-artifact.txt").exists())
        self.assertEqual(ctx.read_binary_marker(bundle), digest)


if __name__ == "__main__":
    unittest.main()
