"""Repository access at a pinned version.

``open_repo`` accepts a local path or a git URL, copies/clones it into a
fresh temp folder under ``.proofgate_cache/`` (never modifying the original),
and checks out the given tag or commit. The returned :class:`Repo` exposes
the read-only inspection tools used by the agentic checker.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

CACHE_DIR_NAME = ".proofgate_cache"

#: Max lines returned by a single :meth:`Repo.read_file` call.
MAX_READ_LINES = 120

#: Directories never searched or scanned for symbols.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".sl",
        ".eden",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".hypothesis",
        "node_modules",
        "dist",
        "build",
        ".proofgate_cache",
    }
)

#: Files larger than this are skipped by code search (1 MiB).
MAX_SEARCH_FILE_BYTES = 1024 * 1024


def _run_git(args: list[str], cwd: Path) -> str:
    """Run a git command in ``cwd``; raise RuntimeError on failure."""
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {cwd}: "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout


def _is_git_url(source: str) -> bool:
    lowered = source.lower()
    return lowered.startswith(
        ("http://", "https://", "git://", "ssh://", "git@")
    ) or lowered.endswith(".git")


def _cache_dir(cache_dir: str | Path | None) -> Path:
    path = Path(cache_dir) if cache_dir else Path.cwd() / CACHE_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def open_repo(
    source: str, version: str, cache_dir: str | Path | None = None
) -> "Repo":
    """Open ``source`` pinned at ``version`` in a scratch copy.

    Args:
        source: Local directory path or git URL. The original is never
            modified: git sources are cloned, plain directories are copied.
        version: Tag or commit hash to check out (git sources, or local
            paths that are themselves git repos).
        cache_dir: Parent folder for the scratch copy. Defaults to
            ``.proofgate_cache/`` under the current working directory.

    Returns:
        A :class:`Repo` rooted at the scratch copy.
    """
    cache = _cache_dir(cache_dir)
    digest = hashlib.sha1(f"{source}\x00{version}".encode()).hexdigest()[:12]
    dest = Path(tempfile.mkdtemp(dir=cache, prefix=f"repo-{digest}-"))

    local = Path(source)
    if local.exists() and local.is_dir() and not _is_git_url(source):
        if (local / ".git").exists():
            # Clone from the local repo: the original stays untouched and we
            # get full history (tags + commits) for checkout.
            _run_git(["clone", "--quiet", str(local), str(dest)], cwd=cache)
            dest_empty = False
        else:
            # Plain directory: copy the tree instead.
            shutil.copytree(
                local,
                dest,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git", ".proofgate_cache"),
            )
            dest_empty = False
        repo = Repo(root=dest, source=source, version=version)
        if (dest / ".git").exists() and version:
            _run_git(["checkout", "--quiet", version], cwd=dest)
        return repo

    # Remote git URL: clone, then pin at the requested ref.
    try:
        _run_git(["clone", "--quiet", source, str(dest)], cwd=cache)
    except RuntimeError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(f"could not clone {source!r}: {exc}") from exc
    repo = Repo(root=dest, source=source, version=version)
    if version:
        try:
            _run_git(["checkout", "--quiet", version], cwd=dest)
        except RuntimeError as exc:
            raise RuntimeError(
                f"could not check out version {version!r} from {source!r}: "
                f"{exc}"
            ) from exc
    return repo


@dataclass
class Repo:
    """A scratch copy of a repo pinned at one version (read-only use)."""

    root: Path
    source: str = ""
    version: str = ""
    _symbols_cache: list[dict] | None = field(
        default=None, init=False, repr=False
    )

    def _resolve(self, path: str | Path) -> Path:
        """Resolve ``path`` (repo-relative) staying inside the repo root."""
        candidate = (self.root / str(path)).resolve()
        try:
            candidate.relative_to(self.root.resolve())
        except ValueError:
            raise ValueError(f"path escapes the repo root: {path!r}")
        return candidate

    def _is_git_repo(self) -> bool:
        return (self.root / ".git").exists()

    # -- versions ------------------------------------------------------
    def list_versions(self) -> dict:
        """Return known tags and recent commits of the scratch copy."""
        tags: list[str] = []
        recent: list[dict] = []
        if not self._is_git_repo():
            return {"tags": tags, "recent_commits": recent}
        try:
            out = _run_git(["tag", "--list"], cwd=self.root)
            tags = [t for t in out.splitlines() if t.strip()]
        except RuntimeError:
            tags = []
        try:
            out = _run_git(
                ["log", "--oneline", "-20", "--format=%H %s"], cwd=self.root
            )
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                sha, _, subject = line.partition(" ")
                recent.append({"hash": sha, "subject": subject})
        except RuntimeError:
            recent = []
        return {"tags": tags, "recent_commits": recent}

    # -- file helpers --------------------------------------------------
    def file_exists(self, path: str) -> bool:
        """Return True when ``path`` (repo-relative) is a file."""
        try:
            return self._resolve(path).is_file()
        except ValueError:
            return False

    def read_file(
        self, path: str, start: int = 1, end: int | None = None
    ) -> dict:
        """Return numbered lines ``start..end`` (1-based, inclusive).

        At most 120 lines per call. Raises FileNotFoundError when the file
        does not exist and ValueError on bad ranges.
        """
        resolved = self._resolve(path)
        if not resolved.is_file():
            raise FileNotFoundError(f"no such file in repo: {path!r}")
        if start < 1:
            raise ValueError("'start' must be >= 1")
        text = resolved.read_text(encoding="utf-8", errors="replace")
        all_lines = text.splitlines()
        total = len(all_lines)
        last = total if end is None else end
        if end is not None and end < start:
            raise ValueError("'end' must be >= 'start'")
        if last - start + 1 > MAX_READ_LINES:
            raise ValueError(
                f"at most {MAX_READ_LINES} lines per call; "
                f"requested {last - start + 1} (use start/end windows)"
            )
        last = min(last, total)
        lines = [
            {"line": n, "text": all_lines[n - 1]}
            for n in range(start, last + 1)
        ]
        return {
            "file": str(path).replace("\\", "/"),
            "start": start,
            "end": last,
            "total_lines": total,
            "lines": lines,
        }

    # -- search --------------------------------------------------------
    def _iter_files(self):
        root = self.root.resolve()
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root)
            except ValueError:
                continue
            if any(part in SKIP_DIRS for part in rel.parts):
                continue
            yield path, rel.as_posix()

    @staticmethod
    def _looks_binary(path: Path) -> bool:
        try:
            with open(path, "rb") as fh:
                return b"\x00" in fh.read(8192)
        except OSError:
            return True

    def search_code(
        self, pattern: str, regex: bool = False, max_results: int = 20
    ) -> list[dict]:
        """Search repo text for ``pattern`` (pure Python, no ripgrep).

        Args:
            pattern: Substring (default) or regex (when ``regex=True``).
            regex: Interpret ``pattern`` as a regular expression.
            max_results: Cap on returned matches.

        Returns:
            List of ``{"file", "line", "text"}`` dicts; ``line`` is
            1-based and ``text`` is the matching line.
        """
        if not pattern:
            raise ValueError("pattern must be a non-empty string")
        compiled = re.compile(pattern) if regex else None
        hits: list[dict] = []
        for path, rel in self._iter_files():
            try:
                if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
            except OSError:
                continue
            if self._looks_binary(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                matched = (
                    compiled.search(line) is not None
                    if compiled
                    else pattern in line
                )
                if matched:
                    hits.append(
                        {"file": rel, "line": lineno, "text": line.strip()}
                    )
                    if len(hits) >= max_results:
                        return hits
        return hits

    # -- symbols -------------------------------------------------------
    def _collect_symbols(self) -> list[dict]:
        if self._symbols_cache is not None:
            return self._symbols_cache
        found: list[dict] = []
        for path, rel in self._iter_files():
            if not rel.endswith(".py"):
                continue
            try:
                tree = ast.parse(
                    path.read_text(encoding="utf-8", errors="replace"),
                    filename=rel,
                )
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    kind = (
                        "class"
                        if isinstance(node, ast.ClassDef)
                        else "function"
                    )
                    found.append(
                        {
                            "name": node.name,
                            "file": rel,
                            "line": node.lineno,
                            "kind": kind,
                        }
                    )
        self._symbols_cache = found
        return found

    def find_symbol(self, name: str) -> dict:
        """Find ``def``/``class`` definitions named ``name``.

        Returns ``{"matches", "close_matches"}``: exact hits plus, when no
        exact hit exists, difflib close matches (possible renames or
        misspellings) with their locations.
        """
        if not name:
            raise ValueError("name must be a non-empty string")
        symbols = self._collect_symbols()
        matches = [s for s in symbols if s["name"] == name]
        close_matches: list[dict] = []
        if not matches:
            names = sorted({s["name"] for s in symbols})
            for candidate in difflib.get_close_matches(
                name, names, n=5, cutoff=0.6
            ):
                close_matches.extend(
                    s for s in symbols if s["name"] == candidate
                )
        return {"matches": matches, "close_matches": close_matches}
