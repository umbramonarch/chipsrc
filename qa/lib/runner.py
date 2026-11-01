"""Execution context, subprocess runner, oracle loader, and result recorder."""
from pathlib import Path
import csv
import hashlib
import json
import os
import shutil
import subprocess
import time

EXPECTED_CACHE_SCHEMA = "2.1.0"
REQUIRED_TSVS = ["symbols", "types", "calls", "macros", "xref", "sections"]
FALLBACK_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "target",
    "output",
    "out",
    "dist",
    ".astro",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "results",
}


class OracleError(Exception):
    """Raised when a required oracle JSON file is missing or invalid."""


class HarnessContext:
    """Per-suite black-box execution context."""

    def __init__(
        self,
        suite_name: str,
        bin_path: Path,
        repos_root: Path,
        corpus_root: Path,
        out_dir: Path,
        oracles_dir: Path,
        fixtures_dir: Path,
        only_patterns: list[str] | None = None,
        skip_patterns: list[str] | None = None,
        timeout: float = 120.0,
        fixtures_mode: str = "build",
    ) -> None:
        self.suite_name = suite_name
        self.bin_path = bin_path
        self.repos_root = repos_root
        self.corpus_root = corpus_root
        self.out_dir = out_dir
        self.oracles_dir = oracles_dir
        self.fixtures_dir = fixtures_dir
        self.only_patterns = [p for p in (only_patterns or []) if p]
        self.skip_patterns = [p for p in (skip_patterns or []) if p]
        self.timeout = timeout
        self.fixtures_mode = fixtures_mode

        self.bundles_dir = self.out_dir / "bundles"
        self.fixture_bundles_dir = self.out_dir / "fixture-bundles"
        self.sandboxes_dir = self.out_dir / "sandboxes"
        self.sandbox_dir = self.sandboxes_dir / f"{suite_name}-{time.time_ns()}"
        self.log_path = self.out_dir / f"{suite_name}-results.json"

        self.results: list[dict] = []
        self.surfaced_probes: list[dict] = []
        self._oracle_cache: dict[str, dict] = {}

        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.sandboxes_dir.mkdir(parents=True, exist_ok=True)
        self._migrate_stray_fixture_bundles()

    def _migrate_stray_fixture_bundles(self) -> None:
        if not (self.fixtures_dir.is_dir() and self.bundles_dir.is_dir()):
            return
        for fx in self.fixtures_dir.iterdir():
            if not fx.is_dir():
                continue
            stray = self.bundles_dir / fx.name
            if stray.exists():
                dest = self.fixture_bundles_dir / fx.name
                if not dest.exists():
                    self.fixture_bundles_dir.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(stray), str(dest))
                else:
                    shutil.rmtree(stray, ignore_errors=True)

    def cleanup_sandbox(self) -> None:
        if self.sandbox_dir.exists():
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
        if self.sandboxes_dir.is_dir():
            prefix = f"{self.suite_name}-"
            for entry in self.sandboxes_dir.iterdir():
                if entry.is_dir() and entry.name.startswith(prefix):
                    shutil.rmtree(entry, ignore_errors=True)

    def matches_filter(self, label: str) -> bool:
        lower = label.lower()
        if self.skip_patterns and any(p.lower() in lower for p in self.skip_patterns):
            return False
        if self.only_patterns and not any(p.lower() in lower for p in self.only_patterns):
            return False
        return True

    def any_label_matches(self, labels: list[str]) -> bool:
        return any(self.matches_filter(label) for label in labels)

    def save(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(
            json.dumps(self.results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def load_oracle(self, name: str) -> dict:
        if name in self._oracle_cache:
            return self._oracle_cache[name]
        oracle_path = self.oracles_dir / f"{name}.json"
        if not oracle_path.is_file():
            raise OracleError(f"missing oracle file: {oracle_path}")
        try:
            data = json.loads(oracle_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise OracleError(f"invalid oracle JSON at {oracle_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise OracleError(f"oracle at {oracle_path} must be a JSON object")
        self._oracle_cache[name] = data
        return data

    def require_oracles(self, names: list[str]) -> dict[str, dict] | None:
        loaded: dict[str, dict] = {}
        for name in names:
            try:
                loaded[name] = self.load_oracle(name)
            except OracleError as exc:
                self.check(
                    f"{name}: oracle loaded",
                    False,
                    str(exc),
                )
                return None
        return loaded

    def check_repos_available(
        self,
        repos: list[str],
        assertion_labels: list[str],
        use_corpus_root: bool = False,
    ) -> bool:
        root = self.corpus_root if use_corpus_root else self.repos_root
        root_flag = "--corpus-root" if use_corpus_root else "--repos-root"
        missing: list[tuple[str, Path]] = []
        for repo in repos:
            repo_path = root / repo
            if not repo_path.is_dir():
                missing.append((repo, repo_path))
        if not missing:
            return True

        missing_desc = ", ".join(f"{r} ({p})" for r, p in missing)
        reason = f"repo not found under {root_flag}={root}: {missing_desc}"
        print(f"SKIP [{self.suite_name}] {reason}")
        for label in assertion_labels:
            self.skip_record(label, reason)
        self.save()
        return False

    def skip_record(self, label: str, reason: str) -> None:
        if not self.matches_filter(label):
            return
        record = {
            "label": label,
            "kind": "assertion",
            "status": "skipped",
            "passed": None,
            "skipped": True,
            "detail": reason,
            "args": None,
            "exit": None,
            "wall_ms": None,
        }
        self.results.append(record)
        self.save()

    def check(
        self,
        label: str,
        passed: bool,
        detail: object = None,
        *,
        args: list[str] | None = None,
        exit_code: int | None = None,
        wall_ms: float | None = None,
    ) -> bool:
        ok = bool(passed)
        if not self.matches_filter(label):
            return ok
        status = "passed" if ok else "failed"
        record = {
            "label": label,
            "kind": "assertion",
            "status": status,
            "passed": ok,
            "skipped": False,
            "detail": detail,
            "args": list(args) if args is not None else None,
            "exit": exit_code,
            "wall_ms": wall_ms,
        }
        self.results.append(record)
        suffix = f": {detail}" if detail is not None else ""
        print(f"{'PASS' if ok else 'FAIL'} {label}{suffix}")
        self.save()
        return ok

    def record_observational(self, label: str, payload: dict) -> None:
        if not self.matches_filter(label):
            return
        record = {
            "label": label,
            "kind": "observational",
            "status": "passed",
            "passed": True,
            "skipped": False,
            "detail": payload,
            "args": None,
            "exit": None,
            "wall_ms": None,
        }
        record.update(payload)
        self.results.append(record)
        self.save()
        print(json.dumps(record, indent=2))

    def _snapshot_claudeignore(self) -> tuple[Path | None, bytes | None]:
        ci_path = self.repos_root / "chipsrc" / ".claudeignore"
        if ci_path.is_file():
            try:
                return ci_path, ci_path.read_bytes()
            except OSError:
                return None, None
        return None, None

    def _restore_claudeignore(self, snapshot: tuple[Path | None, bytes | None]) -> None:
        ci_path, raw = snapshot
        if ci_path is not None and raw is not None:
            try:
                if not ci_path.is_file() or ci_path.read_bytes() != raw:
                    ci_path.write_bytes(raw)
            except OSError:
                pass

    def _exec_Raw(
        self,
        cmd_args: list[str],
        cwd: Path,
        stdin_text: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, float, str, str, str | None]:
        snapshot = self._snapshot_claudeignore()
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                [str(self.bin_path), *cmd_args],
                input=stdin_text,
                cwd=cwd,
                env=env,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
            wall_ms = round((time.perf_counter() - started) * 1000, 2)
            return proc.returncode, wall_ms, proc.stdout, proc.stderr, None
        except subprocess.TimeoutExpired as exc:
            wall_ms = round((time.perf_counter() - started) * 1000, 2)
            out = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            err = (
                exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            msg = f"Timed out after {self.timeout}s"
            return -1, wall_ms, out, f"{err}\n{msg}".strip(), msg
        except OSError as exc:
            wall_ms = round((time.perf_counter() - started) * 1000, 2)
            msg = f"Executable error ({self.bin_path}): {exc}"
            return -1, wall_ms, "", msg, msg
        finally:
            self._restore_claudeignore(snapshot)

    def run(
        self,
        label: str,
        *args: object,
        expected: int | None = 0,
        paired_assertion: str | None = None,
    ) -> dict:
        str_args = [str(a) for a in args]
        exit_code, wall_ms, stdout, stderr, err_reason = self._exec_Raw(
            str_args,
            cwd=self.out_dir,
        )
        try:
            parsed_json = json.loads(stdout)
        except ValueError:
            parsed_json = None

        if expected is None:
            passed = err_reason is None
            status = "passed" if passed else "failed"
            detail: object = (
                err_reason
                if err_reason is not None
                else f"probe exit={exit_code} (expected=None, surfaced)"
            )
            kind = "probe"
        else:
            passed = err_reason is None and exit_code == expected
            status = "passed" if passed else "failed"
            detail = (
                None
                if passed
                else (err_reason or f"exit={exit_code}, expected={expected}")
            )
            kind = "invocation"

        record: dict = {
            "label": label,
            "kind": kind,
            "status": status,
            "passed": passed,
            "skipped": False,
            "detail": detail,
            "args": str_args,
            "exit": exit_code,
            "wall_ms": wall_ms,
            "stdout": stdout,
            "stderr": stderr,
            "json": parsed_json,
        }
        if expected is None:
            record["probe"] = True
            record["expected_exit"] = None
            record["expected_failure"] = exit_code != 0
            record["surfaced"] = True
            if paired_assertion:
                record["paired_assertion"] = paired_assertion

        should_emit = self.matches_filter(label) or (
            paired_assertion is not None and self.matches_filter(paired_assertion)
        )
        if should_emit:
            self.results.append(record)
            if expected is None:
                self.surfaced_probes.append(
                    {
                        "suite": self.suite_name,
                        "label": label,
                        "args": str_args,
                        "exit": exit_code,
                        "expected_exit": None,
                        "expected_failure": exit_code != 0,
                        "paired_assertion": paired_assertion,
                    }
                )
            if not passed:
                print(f"FAIL {label}: {detail}")
            self.save()
        return record

    def run_hook(
        self,
        label: str,
        source: Path,
        name: str,
        payload: str,
        expected: int = 0,
    ) -> dict:
        env = os.environ.copy()
        env["CLAUDE_PROJECT_DIR"] = str(source)
        str_args = ["hook", name]
        exit_code, wall_ms, stdout, stderr, err_reason = self._exec_Raw(
            str_args,
            cwd=source,
            stdin_text=payload,
            env=env,
        )
        passed = err_reason is None and exit_code == expected
        status = "passed" if passed else "failed"
        detail = (
            None
            if passed
            else (err_reason or f"exit={exit_code}, expected={expected}")
        )
        record = {
            "label": label,
            "kind": "invocation",
            "status": status,
            "passed": passed,
            "skipped": False,
            "detail": detail,
            "args": str_args,
            "cwd": str(source),
            "stdin": payload,
            "exit": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "wall_ms": wall_ms,
        }
        if self.matches_filter(label):
            self.results.append(record)
            if not passed:
                print(f"FAIL {label}: {detail}")
            self.save()
        return record

    def query(
        self,
        label: str,
        command: str,
        repo: str,
        text: str = "",
        **options: object,
    ) -> dict:
        args: list[object] = [command, "-b", str(self.bundles_dir / repo)]
        if text:
            args.append(text)
        args.append("--json")
        for key, value in options.items():
            args.append("--" + key.replace("_", "-"))
            if value is not True:
                args.append(str(value))
        return self.run(label, *args)

    @staticmethod
    def exact(rows: object, name: str) -> list[dict]:
        if not isinstance(rows, list):
            return []
        return [
            row
            for row in rows
            if isinstance(row, dict) and row.get("name") == name
        ]

    @staticmethod
    def hashes(bundle: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for folder in ["index", "sections"]:
            folder_path = bundle / folder
            if not folder_path.is_dir():
                continue
            for path in sorted(folder_path.rglob("*")):
                if path.is_file():
                    rel = str(path.relative_to(bundle)).replace("\\", "/")
                    result[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    @staticmethod
    def read_meta(bundle: Path) -> dict:
        meta_path = bundle / "meta.json"
        if not meta_path.is_file():
            return {}
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("metadata"), dict):
                return data["metadata"]
        except Exception:
            pass
        return {}

    def _bundle_is_ready_and_fresh(self, repo_path: Path, bundle_dir: Path) -> bool:
        required = [
            "INDEX.md",
            "meta.json",
            "cache/manifest.json",
            *[f"index/{name}.tsv" for name in REQUIRED_TSVS],
        ]
        if not all((bundle_dir / rel).is_file() for rel in required):
            return False
        try:
            meta = json.loads((bundle_dir / "meta.json").read_text(encoding="utf-8"))[
                "metadata"
            ]
            manifest = json.loads(
                (bundle_dir / "cache" / "manifest.json").read_text(encoding="utf-8")
            )
        except Exception:
            return False

        if manifest.get("schema_version") != EXPECTED_CACHE_SCHEMA:
            return False

        stamps = meta.get("file_stamps") or []
        if not all(isinstance(s, dict) and "mtime_nanos" in s for s in stamps):
            return False

        code, _, out, _, err = self._exec_Raw(
            ["inspect", str(repo_path), "--json"],
            cwd=self.out_dir,
        )
        if err is not None or code != 0:
            return False
        try:
            inspect_report = json.loads(out)
        except ValueError:
            return False
        if inspect_report.get("fingerprint") != meta.get("fingerprint"):
            return False

        s_code, _, s_out, _, s_err = self._exec_Raw(
            ["status", str(bundle_dir), "--check", "--json"],
            cwd=self.out_dir,
        )
        if s_err is not None or s_code != 0:
            return False
        try:
            s_json = json.loads(s_out)
            if not (
                isinstance(s_json, list)
                and len(s_json) == 1
                and s_json[0].get("is_fresh") is True
            ):
                return False
        except ValueError:
            return False
        return True

    def _ensure_bundle(
        self,
        repo: str,
        target_repo: Path,
        bundle_dir: Path,
    ) -> bool:
        if self._bundle_is_ready_and_fresh(target_repo, bundle_dir):
            return True

        if self.fixtures_mode == "require":
            self.check(
                f"{repo}: fixture bundle ready",
                False,
                f"fixture bundle missing or stale at {bundle_dir} (--fixtures-mode require)",
            )
            return False

        bundle_dir.parent.mkdir(parents=True, exist_ok=True)
        cmd_args = ["convert", str(target_repo), "-o", str(bundle_dir)]
        code, wall_ms, _, stderr, err = self._exec_Raw(
            cmd_args,
            cwd=self.out_dir,
        )
        if (
            err is not None
            or code != 0
            or not self._bundle_is_ready_and_fresh(target_repo, bundle_dir)
        ):
            reason = (
                err
                or stderr.strip()
                or f"fixture bundle build failed with exit={code} at {bundle_dir}"
            )
            self.check(
                f"{repo}: fixture bundle ready",
                False,
                reason,
                args=cmd_args,
                exit_code=code,
                wall_ms=wall_ms,
            )
            return False
        return True

    def ensure_repo_bundle(self, repo: str, repo_path: Path | None = None) -> bool:
        target_repo = repo_path if repo_path is not None else (self.repos_root / repo)
        bundle_dir = self.bundles_dir / repo
        return self._ensure_bundle(repo, target_repo, bundle_dir)

    def ensure_fixture_bundle(self, repo: str, repo_path: Path | None = None) -> bool:
        target_repo = repo_path if repo_path is not None else (self.fixtures_dir / repo)
        bundle_dir = self.fixture_bundles_dir / repo
        stray_bundle = self.bundles_dir / repo
        if stray_bundle.exists():
            shutil.rmtree(stray_bundle, ignore_errors=True)
        return self._ensure_bundle(repo, target_repo, bundle_dir)

    def copy_corpus(self, repo: str, name: str) -> Path:
        source = self.sandbox_dir / "copies" / name
        source.mkdir(parents=True, exist_ok=True)
        repo_root = self.repos_root / repo

        self.ensure_repo_bundle(repo, repo_root)
        meta = self.read_meta(self.bundles_dir / repo)
        stamps = meta.get("file_stamps")
        if isinstance(stamps, list) and stamps:
            origin_root = Path(meta.get("source_root", str(repo_root)))
            if not origin_root.is_dir():
                origin_root = repo_root
            for stamp in stamps:
                rel_path = stamp["rel_path"]
                original = origin_root / rel_path
                target = source / rel_path
                if original.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(original, target)
            return source

        # Fallback copy when bundle metadata could not be built (e.g. broken --bin probe)
        if repo_root.is_dir():
            for root_dir, dirs, files in os.walk(repo_root):
                dirs[:] = [d for d in dirs if d not in FALLBACK_IGNORE_DIRS]
                root_p = Path(root_dir)
                for fname in files:
                    orig = root_p / fname
                    rel = orig.relative_to(repo_root)
                    dest = source / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(orig, dest)
        return source

    @staticmethod
    def read_symbols_tsv(bundle: Path) -> list[dict]:
        tsv_path = bundle / "index" / "symbols.tsv"
        if not tsv_path.is_file():
            return []
        with tsv_path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter="\t"))
