"""Sandboxed reproduction-test runner.

Reproduction tests for ``reproducible_impact`` claims run ONLY through
:func:`run_repro_test` in this module. Never execute code from a report
directly and never touch real systems.

Pipeline per call:

1. Allowlist gate — the repo (path or URL) must be listed in
   ``sandbox_allowlist.txt`` (current working directory), otherwise nothing
   runs and the result carries ``blocked_reason="repo not allowlisted"``.
2. Static screen — the test source is parsed and rejected when it imports
   or calls banned modules/functions or touches filesystem paths outside
   the temp dir.
3. Staged run — the repo checkout is copied into a fresh temp directory,
   the test is written as ``test_proofgate_repro.py``, and
   ``python -m pytest -q`` runs in a subprocess with a minimal environment
   (no API keys, tokens, or cloud credentials) and a wall-clock timeout.
4. Cleanup — the temp directory is removed afterwards.

This is defense in depth for a demo, not a hardened sandbox. See
DESIGN.md ("Sandbox limits") for the known gaps before trusting it.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

#: Allowlist file name (resolved against the current working directory).
ALLOWLIST_FILENAME = "sandbox_allowlist.txt"

#: Entries used when no allowlist file exists.
DEFAULT_ALLOWLIST = ("demo/target_app",)

#: File name the generated test is written as inside the temp dir.
TEST_FILENAME = "test_proofgate_repro.py"

#: Exact reason returned when the repo is not allowlisted.
NOT_ALLOWLISTED_REASON = "repo not allowlisted"

#: Environment variables propagated into the sandbox subprocess. Everything
#: else (MODEL_API_KEY, *_TOKEN_*, cloud credentials, PYTHON*, HOME, ...)
#: is dropped.
ENV_KEEP = ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP")

#: Modules that test code may neither import nor call into.
_BANNED_TOP_LEVELS = frozenset(
    {"socket", "requests", "urllib", "subprocess", "ctypes", "http"}
)

#: Dotted calls that are banned even though the parent module is allowed.
_BANNED_CALLS = frozenset({"os.system", "os.popen", "shutil.rmtree"})

#: Star imports from these modules would silently bind banned callables.
_BANNED_STAR_MODULES = frozenset({"os", "shutil"})

#: Filesystem-touching calls whose literal string arguments are screened
#: for absolute paths and ``..`` escapes. (Deliberately narrow: a web-app
#: test legitimately passes URL paths like ``"/health"`` to a test client,
#: so only real filesystem sinks are inspected.)
_PATH_SINKS = frozenset(
    {
        "open",
        "io.open",
        "os.open",
        "codecs.open",
        "Path",
        "pathlib.Path",
        "pathlib.PosixPath",
        "pathlib.WindowsPath",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.mkdir",
        "os.makedirs",
        "os.removedirs",
        "os.rename",
        "os.replace",
        "os.symlink",
        "os.link",
        "os.stat",
        "os.lstat",
        "os.listdir",
        "os.scandir",
        "os.chdir",
        "os.chmod",
        "os.truncate",
        "os.mkfifo",
        "os.readlink",
        "os.path.join",
        "os.path.abspath",
        "os.path.realpath",
        "os.path.normpath",
        "os.path.expanduser",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copytree",
        "shutil.move",
        "shutil.unpack_archive",
        "shutil.make_archive",
        "tempfile.mkdtemp",
        "tempfile.mkstemp",
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryDirectory",
    }
)

_WINDOWS_ABS_PATH = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass
class TestResult:
    """Outcome of one sandboxed reproduction-test run."""

    passed: bool
    stdout: str
    stderr: str
    duration: float
    blocked_reason: str | None = None
    error: str | None = None
    timed_out: bool = False


# -- allowlist -------------------------------------------------------


def _load_allowlist() -> list[str]:
    """Read allowlist entries (one repo path or URL per line)."""
    path = Path.cwd() / ALLOWLIST_FILENAME
    if not path.is_file():
        return list(DEFAULT_ALLOWLIST)
    entries: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def _path_key(value: str) -> str:
    """Normalize a path for comparison (absolute, case-normalized)."""
    try:
        return os.path.normcase(os.path.abspath(value))
    except (OSError, ValueError):
        return os.path.normcase(value)


def _candidate_strings(repo) -> list[str]:
    """Repo identities checked against the allowlist."""
    if isinstance(repo, (str, os.PathLike)):
        return [str(repo)]
    candidates: list[str] = []
    for attr in ("source", "root"):
        value = getattr(repo, attr, None)
        if value:
            candidates.append(str(value))
    return candidates


def is_allowlisted(repo) -> bool:
    """Return True when the repo path or URL is in the allowlist file."""
    candidates = _candidate_strings(repo)
    if not candidates:
        return False
    strings = set(candidates) | {c.rstrip("/") for c in candidates}
    keys = {_path_key(c) for c in candidates}
    for entry in _load_allowlist():
        if entry in strings or entry.rstrip("/") in strings:
            return True
        if _path_key(entry) in keys:
            return True
    return False


def _repo_root(repo) -> Path | None:
    """Resolve the checked-out repo directory, or None when unusable."""
    if isinstance(repo, (str, os.PathLike)):
        candidate = Path(repo)
        return candidate if candidate.is_dir() else None
    root = getattr(repo, "root", None)
    if root is None:
        return None
    candidate = Path(root)
    return candidate if candidate.is_dir() else None


# -- static screen ---------------------------------------------------


def _dotted_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    """Resolve a call target to a dotted name (aliases expanded)."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value, aliases)
        if base:
            return f"{base}.{node.attr}"
        return None
    return None


def _outside_path(value: str) -> str | None:
    """Return ``value`` when it is a filesystem path outside the temp dir."""
    text = value.strip()
    if not text:
        return None
    if (
        text.startswith("/")
        or text.startswith("\\\\")
        or text.startswith("~")
        or _WINDOWS_ABS_PATH.match(text)
    ):
        return value
    if ".." in re.split(r"[\\/]", text):
        return value
    return None


def _static_block_reason(test_code: str) -> str | None:
    """Screen test source; return a blocked reason or None when clean."""
    try:
        tree = ast.parse(test_code)
    except SyntaxError as exc:
        return f"could not parse test code: {exc}"

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _BANNED_TOP_LEVELS:
                    return f"blocked import: {alias.name}"
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            top = module.split(".")[0]
            if top in _BANNED_TOP_LEVELS:
                return f"blocked import: {module or node.names[0].name}"
            if any(a.name == "*" for a in node.names):
                if top in _BANNED_STAR_MODULES:
                    return f"blocked star import: {module}"
                continue
            for alias in node.names:
                full = f"{module}.{alias.name}" if module else alias.name
                key = alias.asname or alias.name
                aliases[key] = full
                if full in _BANNED_CALLS:
                    return f"blocked import: {full}"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func, aliases)
        if dotted is None:
            continue
        top = dotted.split(".")[0]
        if top in _BANNED_TOP_LEVELS or dotted in _BANNED_CALLS:
            return f"blocked call: {dotted}"
        if dotted in ("__import__", "importlib.import_module") and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.split(".")[0] in _BANNED_TOP_LEVELS:
                    return f"blocked dynamic import: {first.value}"
        if dotted in _PATH_SINKS:
            args: list[ast.AST] = list(node.args) + [
                kw.value for kw in node.keywords
            ]
            for arg in args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and _outside_path(arg.value) is not None
                ):
                    return (
                        "blocked path outside temp dir: "
                        f"{arg.value!r} in {dotted}()"
                    )
    return None


# -- subprocess ------------------------------------------------------


def _sandbox_env() -> dict[str, str]:
    """Build the child environment from scratch (no secrets)."""
    return {
        key: value
        for key, value in os.environ.items()
        if key in ENV_KEEP
    }


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill a timed-out process and its children (best effort)."""
    try:
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        else:
            finished = subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
            )
            if finished.returncode == 0:
                return
    except Exception:
        pass
    try:
        proc.kill()
    except OSError:
        pass


def run_repro_test(repo, test_code: str, timeout_s: float = 60) -> TestResult:
    """Run ``test_code`` against ``repo`` in the sandbox.

    Args:
        repo: Pinned :class:`Repo` (or a plain path/URL string). The repo
            must be listed in ``sandbox_allowlist.txt`` or nothing runs.
        test_code: Pytest source, written as ``test_proofgate_repro.py``.
        timeout_s: Wall-clock budget; the process tree is killed on expiry.

    Returns:
        :class:`TestResult` with ``passed``, captured output, duration,
        and ``blocked_reason`` when the run was refused or timed out.
    """
    started = time.monotonic()

    def done(
        passed: bool,
        stdout: str = "",
        stderr: str = "",
        blocked_reason: str | None = None,
        error: str | None = None,
        timed_out: bool = False,
    ) -> TestResult:
        return TestResult(
            passed=passed,
            stdout=stdout,
            stderr=stderr,
            duration=time.monotonic() - started,
            blocked_reason=blocked_reason,
            error=error,
            timed_out=timed_out,
        )

    if not is_allowlisted(repo):
        return done(False, blocked_reason=NOT_ALLOWLISTED_REASON)

    blocked = _static_block_reason(test_code)
    if blocked is not None:
        return done(False, blocked_reason=blocked)

    src_root = _repo_root(repo)
    if src_root is None:
        return done(False, error=f"repo checkout not found: {repo!r}")

    tmpdir = Path(tempfile.mkdtemp(prefix="proofgate-repro-"))
    try:
        try:
            shutil.copytree(src_root, tmpdir, dirs_exist_ok=True)
        except OSError as exc:
            return done(False, error=f"could not stage repo copy: {exc}")
        (tmpdir / TEST_FILENAME).write_text(test_code, encoding="utf-8")

        popen_kwargs: dict = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        else:
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "pytest", "-q", TEST_FILENAME],
                cwd=tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=_sandbox_env(),
                **popen_kwargs,
            )
        except OSError as exc:
            return done(False, error=f"could not start pytest: {exc}")

        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=float(timeout_s))
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except Exception:
                stdout, stderr = "", ""
            timed_out = True

        stdout = stdout or ""
        stderr = stderr or ""
        if timed_out:
            return done(
                False,
                stdout,
                stderr,
                blocked_reason=f"timed out after {timeout_s}s",
                timed_out=True,
            )
        returncode = proc.returncode
        if returncode == 0:
            return done(True, stdout, stderr)
        if returncode == 1:
            return done(False, stdout, stderr)
        return done(
            False,
            stdout,
            stderr,
            error=f"pytest exited with code {returncode} (no usable result)",
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
