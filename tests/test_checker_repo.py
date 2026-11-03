"""Tests for repo.py and checker.py (mocked LLM; no network)."""

from __future__ import annotations

import json
import subprocess

import pytest

from proofgate.checker import check_claims, validate_evidence
from proofgate.models import Claim, Evidence
from proofgate.repo import open_repo

AUTH_PY = '''"""Auth helpers."""

import hmac


def verify_oauth_signature(state, session_value):
    """Check the OAuth callback state."""
    if not state:
        return False
    return hmac.compare_digest(state, session_value)


class SessionStore:
    pass
'''

OTHER_PY = 'HELLO = "verify_oauth_signature"\n'


def _make_plain_repo(root) -> object:
    root.mkdir(parents=True, exist_ok=True)
    src = root / "src"
    src.mkdir()
    (src / "auth.py").write_text(AUTH_PY, encoding="utf-8")
    (src / "other.py").write_text(OTHER_PY, encoding="utf-8")
    return root


def _git(*args, cwd) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _make_git_repo(root) -> object:
    root.mkdir(parents=True, exist_ok=True)
    _git("init", cwd=root)
    _git("config", "user.email", "test@example.com", cwd=root)
    _git("config", "user.name", "Test", cwd=root)
    (root / "app.py").write_text('VERSION = 1\n', encoding="utf-8")
    _git("add", ".", cwd=root)
    _git("commit", "-m", "v1", cwd=root)
    _git("tag", "v1.0", cwd=root)
    (root / "app.py").write_text('VERSION = 2\n', encoding="utf-8")
    _git("add", ".", cwd=root)
    _git("commit", "-m", "v2", cwd=root)
    return root


class ScriptedClient:
    """Mocked LLM: replays one JSON reply per turn, records requests."""

    def __init__(self, replies: list[str], max_tool_turns: int = 8):
        self.replies = list(replies)
        self.calls: list[dict] = []
        self.max_tool_turns = max_tool_turns

    def generate(self, prompt: str, **kwargs):
        self.calls.append({"prompt": prompt, **kwargs})
        if len(self.replies) == 1:
            return self.replies[0]
        return self.replies.pop(0)


def _claim(**overrides) -> Claim:
    base = {
        "id": "c1",
        "kind": "symbol_exists",
        "statement": "Function verify_oauth_signature exists in src/auth.py.",
        "target": {"file": "src/auth.py", "symbol": "verify_oauth_signature"},
        "check_method": "static",
    }
    base.update(overrides)
    return Claim(**base)


# -- search_code ------------------------------------------------------

def test_search_code_substring_regex_and_cap(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    hits = repo.search_code("verify_oauth_signature")
    assert hits, "expected at least one hit"
    assert all(set(h) == {"file", "line", "text"} for h in hits)
    first = hits[0]
    assert first["file"] == "src/auth.py"
    assert isinstance(first["line"], int) and first["line"] >= 1
    assert "verify_oauth_signature" in first["text"]

    regex_hits = repo.search_code(r"def verify_oauth_\w+", regex=True)
    assert any(h["file"] == "src/auth.py" for h in regex_hits)

    capped = repo.search_code("e", max_results=2)
    assert len(capped) == 2


def test_search_code_rejects_empty_pattern(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    with pytest.raises(ValueError):
        repo.search_code("")


# -- open_repo isolation ----------------------------------------------

def test_open_repo_checks_out_version_without_touching_original(tmp_path):
    orig = _make_git_repo(tmp_path / "orig")
    repo = open_repo(str(orig), "v1.0")
    assert repo.root != orig
    # Scratch copy is pinned at v1.0 ...
    assert (repo.root / "app.py").read_text() == 'VERSION = 1\n'
    # ... while the original still holds v2.
    assert (orig / "app.py").read_text() == 'VERSION = 2\n'
    versions = repo.list_versions()
    assert "v1.0" in versions["tags"]
    assert versions["recent_commits"]


def test_open_repo_plain_directory_is_copied(tmp_path):
    orig = _make_plain_repo(tmp_path / "orig")
    repo = open_repo(str(orig), "")
    assert repo.root != orig
    assert (repo.root / "src" / "auth.py").read_text() == AUTH_PY
    assert repo.list_versions() == {"tags": [], "recent_commits": []}


# -- read_file / file_exists ------------------------------------------

def test_read_file_numbered_lines_and_cap(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    page = repo.read_file("src/auth.py", 1, 5)
    assert [ln["line"] for ln in page["lines"]] == [1, 2, 3, 4, 5]
    assert page["total_lines"] == len(AUTH_PY.splitlines())
    with pytest.raises(ValueError, match="at most 120 lines"):
        repo.read_file("src/auth.py", 1, 121)
    with pytest.raises(FileNotFoundError):
        repo.read_file("src/missing.py", 1, 5)
    assert repo.file_exists("src/auth.py") is True
    assert repo.file_exists("src/missing.py") is False


# -- find_symbol close matches -----------------------------------------

def test_find_symbol_exact_match(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    result = repo.find_symbol("verify_oauth_signature")
    assert result["close_matches"] == []
    assert len(result["matches"]) == 1
    match = result["matches"][0]
    assert match["file"] == "src/auth.py"
    assert match["kind"] == "function"
    assert isinstance(match["line"], int)


def test_find_symbol_close_match_for_misspelling(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    result = repo.find_symbol("verify_oauth_signatre")  # missing 'u'
    assert result["matches"] == []
    names = [m["name"] for m in result["close_matches"]]
    assert "verify_oauth_signature" in names
    loc = next(
        m for m in result["close_matches"] if m["name"] == "verify_oauth_signature"
    )
    assert loc["file"] == "src/auth.py"


def test_find_symbol_no_match_no_close(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    result = repo.find_symbol("zzz_no_such_symbol_qqq")
    assert result == {"matches": [], "close_matches": []}


# -- checker: citation rule --------------------------------------------

def test_evidence_without_file_line_cannot_be_supported(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    reply = json.dumps(
        {"status": "supported", "summary": "Trust me, it exists."}
    )
    evidences = check_claims([_claim()], repo, client=ScriptedClient([reply]))
    assert evidences[0].status == "unverifiable"


def test_evidence_without_file_line_cannot_be_refuted(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    reply = json.dumps(
        {
            "status": "refuted",
            "summary": "No such symbol.",
            "file": "src/auth.py",
            # line_start omitted: never actually read -> cannot refute.
        }
    )
    evidences = check_claims([_claim()], repo, client=ScriptedClient([reply]))
    assert evidences[0].status == "unverifiable"


def test_validate_evidence_downgrades_unread_citation():
    ev = Evidence(
        claim_id="c1",
        status="supported",
        summary="Exists.",
        file="src/auth.py",
        line_start=1,
        line_end=5,
    )
    assert validate_evidence(ev, []).status == "unverifiable"
    ev2 = Evidence(
        claim_id="c1",
        status="supported",
        summary="Exists.",
        file="src/auth.py",
        line_start=2,
        line_end=4,
    )
    assert (
        validate_evidence(ev2, [("src/auth.py", 1, 10)]).status == "supported"
    )


def test_checker_supports_only_after_real_read_and_logs_tools(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    replies = [
        json.dumps(
            {"tool": "find_symbol", "arguments": {"name": "verify_oauth_signature"}}
        ),
        json.dumps(
            {
                "tool": "read_file",
                "arguments": {"path": "src/auth.py", "start": 1, "end": 12},
            }
        ),
        json.dumps(
            {
                "status": "supported",
                "summary": "def verify_oauth_signature is defined in src/auth.py.",
                "file": "src/auth.py",
                "line_start": 6,
                "line_end": 6,
                "snippet": "def verify_oauth_signature(state, session_value):",
            }
        ),
    ]
    tool_log: list = []
    client = ScriptedClient(replies)
    evidences = check_claims([_claim()], repo, client=client, tool_log=tool_log)
    assert evidences[0].status == "supported"
    assert evidences[0].file == "src/auth.py"
    assert evidences[0].line_start == 6
    # Each tool call is logged with name + arguments (never the API key).
    assert [e["tool"] for e in tool_log] == ["find_symbol", "read_file"]
    assert tool_log[0]["arguments"] == {"name": "verify_oauth_signature"}
    assert tool_log[0]["claim_id"] == "c1"
    assert "MODEL_API_KEY" not in json.dumps(tool_log)
    assert "MODEL_API_KEY" not in json.dumps(client.calls)


def test_uncited_evidence_keeps_looping_until_cap_then_unverifiable(tmp_path):
    # A supported verdict that cites nothing actually read must not stop the
    # loop early: the checker keeps gathering until the turn cap, then the
    # cap means unverifiable.
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    reply = json.dumps(
        {
            "status": "supported",
            "summary": "Trust me, it exists.",
            "file": "src/auth.py",
            "line_start": 6,
            "line_end": 6,
        }
    )
    client = ScriptedClient([reply])  # same uncited reply every turn
    evidences = check_claims([_claim()], repo, client=client)
    assert evidences[0].status == "unverifiable"
    assert len(client.calls) == client.max_tool_turns


def test_parallel_checks_keep_claim_order_and_grouped_tool_log(tmp_path):
    import re
    import threading

    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")

    class KeyedClient:
        """Thread-safe fake serving canned replies per claim id."""

        def __init__(self, by_claim: dict):
            self.by_claim = {k: list(v) for k, v in by_claim.items()}
            self.max_tool_turns = 8
            self._lock = threading.Lock()

        def generate(self, prompt: str, **kwargs):
            cid = re.search(r"Claim (\S+) \(", prompt).group(1)
            with self._lock:
                replies = self.by_claim[cid]
                return replies.pop(0) if len(replies) > 1 else replies[0]

    def tool(path, start, end):
        return json.dumps({"tool": "read_file",
                           "arguments": {"path": path, "start": start, "end": end}})

    def supported(summary, path, line):
        return json.dumps({"status": "supported", "summary": summary,
                           "file": path, "line_start": line, "line_end": line})

    client = KeyedClient({
        "c1": [tool("src/auth.py", 1, 12),
               supported("def visible in src/auth.py.", "src/auth.py", 6)],
        "c2": [tool("src/other.py", 1, 5),
               supported("line present in src/other.py.", "src/other.py", 1)],
    })
    claims = [_claim(id="c1"),
              _claim(id="c2", statement="Marker present in src/other.py.",
                     target={"file": "src/other.py", "symbol": "HELLO"})]
    tool_log: list = []
    evidences = check_claims(claims, repo, client=client, tool_log=tool_log)
    assert [e.claim_id for e in evidences] == ["c1", "c2"]
    assert all(e.status == "supported" for e in evidences)
    # tool_log stays ordered per claim even though checks ran in parallel.
    ids = [e["claim_id"] for e in tool_log]
    assert ids == sorted(ids)


def test_repro_claims_share_the_worker_pool(tmp_path, monkeypatch):
    """Repro/test claims must be checked inside the worker pool.

    Regression guard: when claim checks ran sequentially, per-claim times
    added up to the wall-clock total. Every claim -- static or sandbox
    repro -- must overlap in time. Each claim's first model call rendezvous
    on a barrier sized to the claim count, so sequential checking would
    stall until the barrier times out and fail this test.
    """
    import re
    import threading
    import types

    import proofgate.checker as checker_mod

    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    barrier = threading.Barrier(4, timeout=15)
    state_lock = threading.Lock()
    first_seen: set[str] = set()
    calls_per_claim: dict[str, int] = {}

    class ConcurrentClient:
        max_tool_turns = 8

        def generate(self, prompt: str, **kwargs):
            cid = re.search(r"Claim (\S+)", prompt).group(1)
            with state_lock:
                calls_per_claim[cid] = calls_per_claim.get(cid, 0) + 1
                first = cid not in first_seen
                first_seen.add(cid)
            if first:
                barrier.wait(timeout=15)
            if "MINIMAL pytest" in prompt:
                return "def test_repro():\n    assert True\n"
            if calls_per_claim[cid] == 1:
                return json.dumps(
                    {
                        "tool": "read_file",
                        "arguments": {
                            "path": "src/auth.py",
                            "start": 1,
                            "end": 12,
                        },
                    }
                )
            return json.dumps(
                {
                    "status": "supported",
                    "summary": "def visible in src/auth.py.",
                    "file": "src/auth.py",
                    "line_start": 6,
                    "line_end": 6,
                }
            )

    sandbox_calls: list[str] = []

    def fake_repro_test(repo, test_code, timeout_s=60):
        sandbox_calls.append(test_code)
        return types.SimpleNamespace(
            passed=True,
            stdout=".",
            stderr="",
            duration=0.1,
            blocked_reason=None,
            error=None,
            timed_out=False,
        )

    monkeypatch.setattr(checker_mod, "is_allowlisted", lambda repo: True)
    monkeypatch.setattr(checker_mod, "run_repro_test", fake_repro_test)

    claims = [
        _claim(id="c1"),
        _claim(id="c2", statement="Marker present in src/other.py.",
               target={"file": "src/other.py", "symbol": "HELLO"}),
        _claim(id="c3", kind="reproducible_impact", check_method="test",
               statement="Exploit X reproduces.",
               target={"file": "src/auth.py"}),
        _claim(id="c4", kind="reproducible_impact", check_method="test",
               statement="Exploit Y reproduces.",
               target={"file": "src/auth.py"}),
    ]
    evidences = check_claims(claims, repo, client=ConcurrentClient())
    assert [e.claim_id for e in evidences] == ["c1", "c2", "c3", "c4"]
    assert all(e.status == "supported" for e in evidences)
    # Both repro claims really went through the sandbox path.
    assert len(sandbox_calls) == 2
    assert all("test_repro" in code for code in sandbox_calls)


def test_repro_test_prompt_uses_medium_reasoning(monkeypatch):
    import types

    import proofgate.checker as checker_mod

    seen: dict = {}

    class FakeLLM:
        max_tool_turns = 8

        def generate(self, prompt: str, **kwargs):
            seen.update(kwargs)
            return "def test_repro(): assert True"

    monkeypatch.setattr(checker_mod, "is_allowlisted", lambda repo: True)
    monkeypatch.setattr(
        checker_mod,
        "run_repro_test",
        lambda repo, code, timeout_s=60: types.SimpleNamespace(
            passed=False,
            stdout="",
            stderr="",
            duration=0.1,
            blocked_reason="blocked",
            error=None,
            timed_out=False,
        ),
    )
    claim = _claim(kind="reproducible_impact", check_method="test")
    evidence = checker_mod._check_test_claim(claim, object(), FakeLLM())
    assert seen.get("reasoning") == {"effort": "medium"}
    assert evidence.status == "unverifiable"


def test_claim_checks_pass_no_reasoning_effort(tmp_path):
    # Low effort is extraction-only: the check loop uses API defaults.
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    replies = [
        json.dumps(
            {"tool": "read_file",
             "arguments": {"path": "src/auth.py", "start": 1, "end": 12}}
        ),
        json.dumps(
            {
                "status": "supported",
                "summary": "def verify_oauth_signature is defined in src/auth.py.",
                "file": "src/auth.py",
                "line_start": 6,
                "line_end": 6,
            }
        ),
    ]
    client = ScriptedClient(replies)
    check_claims([_claim()], repo, client=client)
    assert client.calls and all("reasoning" not in c for c in client.calls)


def test_checker_leaves_reproducible_impact_unverifiable_without_llm(tmp_path):
    repo = open_repo(str(_make_plain_repo(tmp_path / "orig")), "v1")
    client = ScriptedClient(
        [json.dumps({"status": "supported", "summary": "x"})]
    )
    claim = _claim(kind="reproducible_impact", check_method="test")
    evidences = check_claims([claim], repo, client=client)
    assert evidences[0].status == "unverifiable"
    assert client.calls == []
