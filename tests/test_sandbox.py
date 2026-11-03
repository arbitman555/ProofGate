"""Tests for sandbox.py and the checker.py sandbox wiring.

No network and no real model calls: the checker tests use a scripted fake
LLM, and every sandbox run executes against a tiny local stand-in repo.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from proofgate import sandbox
from proofgate.checker import MAX_TEST_LOG_LINES, check_claims
from proofgate.models import Claim
from proofgate.sandbox import is_allowlisted, run_repro_test

CALC_PY = '''"""Tiny calculator used as a stand-in target app."""


def add(a, b):
    """Add two numbers."""
    return a + b
'''


def _make_target(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "calc.py").write_text(CALC_PY, encoding="utf-8")
    return root


@pytest.fixture()
def allowlisted_target(tmp_path, monkeypatch):
    """A target repo allowlisted via a cwd-local sandbox_allowlist.txt."""
    orig = _make_target(tmp_path / "orig")
    work = tmp_path / "work"
    work.mkdir()
    (work / sandbox.ALLOWLIST_FILENAME).write_text(
        str(orig) + "\n", encoding="utf-8"
    )
    monkeypatch.chdir(work)
    return orig


def _impact_claim(**overrides) -> Claim:
    base = {
        "id": "c9",
        "kind": "reproducible_impact",
        "statement": "add() mishandles negatives: add(-1, -2) does not return -3.",
        "target": {"file": "calc.py", "symbol": "add"},
        "check_method": "test",
    }
    base.update(overrides)
    return Claim(**base)


class _TestWriter:
    """Fake LLM: replays one reply as the generated pytest file."""

    def __init__(self, reply: str):
        self.reply = reply
        self.calls: list[str] = []

    max_tool_turns = 8

    def generate(self, prompt: str, **kwargs):
        self.calls.append(prompt)
        return self.reply


# -- basic run ---------------------------------------------------------

def test_pass_and_fail(allowlisted_target):
    ok = run_repro_test(
        str(allowlisted_target),
        "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
    )
    assert ok.passed is True
    assert ok.blocked_reason is None
    assert ok.error is None
    assert isinstance(ok.duration, float) and ok.duration >= 0

    bad = run_repro_test(
        str(allowlisted_target),
        "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 4\n",
    )
    assert bad.passed is False
    assert bad.blocked_reason is None
    assert bad.error is None
    assert bad.stdout.strip() != ""


def test_run_accepts_repo_object(allowlisted_target):
    from proofgate.repo import open_repo

    repo = open_repo(str(allowlisted_target), "")
    assert is_allowlisted(repo) is True
    result = run_repro_test(repo, "def test_ok():\n    assert True\n")
    assert result.passed is True


def test_temp_dir_is_removed(allowlisted_target, monkeypatch):
    seen: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def spy(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        seen.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", spy)
    result = run_repro_test(
        str(allowlisted_target), "def test_ok():\n    assert True\n"
    )
    assert result.passed is True
    assert seen, "expected the sandbox to create a temp dir"
    assert not Path(seen[0]).exists()


# -- static blocklist --------------------------------------------------

IMPORT_CASES = [
    ("import socket", "socket"),
    ("import requests", "requests"),
    ("import urllib.parse", "urllib"),
    ("import http.client", "http.client"),
    ("import subprocess", "subprocess"),
    ("import ctypes", "ctypes"),
    ("from socket import create_connection", "socket"),
    ("from subprocess import run", "subprocess"),
    ("from os import system", "os.system"),
    ("from os import popen", "os.popen"),
    ("from shutil import rmtree", "shutil.rmtree"),
    ("import socket as s", "socket"),
    ("from os import system as sys_call", "os.system"),
]

CALL_CASES = [
    ("import os\n\ndef test_x():\n    os.system('echo hi')\n", "os.system"),
    ("import os\n\ndef test_x():\n    os.popen('echo hi')\n", "os.popen"),
    ("import shutil\n\ndef test_x():\n    shutil.rmtree('x')\n", "shutil.rmtree"),
    ("import socket\n\ndef test_x():\n    socket.create_connection(('h', 80))\n", "socket"),
    ("__import__('socket')\n\ndef test_x():\n    assert True\n", "socket"),
]

PATH_CASES = [
    ("def test_x():\n    open('/etc/passwd').read()\n", "/etc/passwd"),
    ("def test_x():\n    open('../secret').read()\n", ".."),
    (
        "from pathlib import Path\n\ndef test_x():\n    Path('C:/Windows/x').exists()\n",
        "C:/Windows/x",
    ),
]


@pytest.mark.parametrize("stmt,expected", IMPORT_CASES)
def test_blocked_imports(allowlisted_target, stmt, expected):
    result = run_repro_test(
        str(allowlisted_target), f"{stmt}\n\ndef test_x():\n    assert True\n"
    )
    assert result.passed is False
    assert result.blocked_reason is not None
    assert expected in result.blocked_reason


@pytest.mark.parametrize("code,expected", CALL_CASES)
def test_blocked_calls(allowlisted_target, code, expected):
    result = run_repro_test(str(allowlisted_target), code)
    assert result.passed is False
    assert result.blocked_reason is not None
    assert expected in result.blocked_reason


@pytest.mark.parametrize("code,expected", PATH_CASES)
def test_blocked_paths_outside_temp_dir(allowlisted_target, code, expected):
    result = run_repro_test(str(allowlisted_target), code)
    assert result.passed is False
    assert result.blocked_reason is not None
    assert expected in result.blocked_reason


def test_blocked_code_never_runs(allowlisted_target):
    marker = Path.cwd() / "pwned_by_sandbox.txt"
    result = run_repro_test(
        str(allowlisted_target),
        "import socket\n\ndef test_x():\n"
        "    open('pwned_by_sandbox.txt', 'w').write('x')\n",
    )
    assert result.passed is False
    assert result.blocked_reason is not None
    assert "socket" in result.blocked_reason
    assert not marker.exists()


def test_url_path_strings_are_allowed(allowlisted_target):
    # A web-app test client legitimately passes paths like "/health": only
    # real filesystem sinks are screened, so this must run and pass.
    result = run_repro_test(
        str(allowlisted_target),
        'def test_url_path_string_is_fine():\n    assert "/health".startswith("/")\n',
    )
    assert result.passed is True, result.stdout + result.stderr


# -- allowlist refusal -------------------------------------------------

def test_allowlist_refusal_runs_nothing(tmp_path, monkeypatch):
    orig = _make_target(tmp_path / "orig")
    work = tmp_path / "work"
    work.mkdir()
    (work / sandbox.ALLOWLIST_FILENAME).write_text(
        "demo/target_app\n", encoding="utf-8"
    )
    monkeypatch.chdir(work)
    result = run_repro_test(
        str(orig),
        "def test_x():\n    open('should_not_run.txt', 'w').write('x')\n",
    )
    assert result.passed is False
    assert result.blocked_reason == "repo not allowlisted"
    assert not (work / "should_not_run.txt").exists()


# -- stripped environment ----------------------------------------------

def test_subprocess_environment_is_stripped(allowlisted_target, monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", "super-secret-key")
    monkeypatch.setenv("FAKE_CLOUD_TOKEN", "cloud-secret")
    code = (
        "import os\n\n"
        "def test_env():\n"
        "    keys = set(os.environ)\n"
        "    assert 'MODEL_API_KEY' not in keys\n"
        "    assert 'FAKE_CLOUD_TOKEN' not in keys\n"
        "    assert 'PATH' in keys\n"
        "    allowed = {'PATH', 'SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP'}\n"
        "    # PYTEST_* vars are injected by the pytest runner itself, not\n"
        "    # inherited from the parent process, so they are not leaks.\n"
        "    leaked = sorted(k for k in keys - allowed if not k.startswith('PYTEST_'))\n"
        "    assert leaked == [], f'leaked env vars: {leaked}'\n"
    )
    result = run_repro_test(str(allowlisted_target), code)
    assert result.passed is True, result.stdout + result.stderr


# -- timeout -----------------------------------------------------------

def test_timeout_kills_and_reports(allowlisted_target):
    result = run_repro_test(
        str(allowlisted_target),
        "import time\n\ndef test_sleeps():\n    time.sleep(30)\n",
        timeout_s=3,
    )
    assert result.passed is False
    assert result.timed_out is True
    assert result.blocked_reason is not None
    assert "timed out" in result.blocked_reason
    assert result.duration < 30


# -- checker wiring ----------------------------------------------------

def test_checker_supported_on_pass(allowlisted_target):
    writer = _TestWriter(
        "```python\n"
        "from calc import add\n\n"
        "def test_neg():\n"
        "    assert add(-1, -2) == -3\n"
        "```\n"
    )
    evidences = check_claims([_impact_claim()], str(allowlisted_target), client=writer)
    assert evidences[0].status == "supported"
    assert writer.calls, "expected the model to be asked for a test"
    assert evidences[0].test_log is not None
    assert "from calc import add" in evidences[0].test_log
    assert "evidence level 3" in evidences[0].summary


def test_checker_refuted_on_fail(allowlisted_target):
    writer = _TestWriter(
        "from calc import add\n\ndef test_wrong():\n    assert add(1, 1) == 3\n"
    )
    evidences = check_claims([_impact_claim()], str(allowlisted_target), client=writer)
    assert evidences[0].status == "refuted"
    assert evidences[0].test_log is not None


def test_checker_unverifiable_on_blocked(allowlisted_target):
    writer = _TestWriter("import socket\n\ndef test_x():\n    assert True\n")
    evidences = check_claims([_impact_claim()], str(allowlisted_target), client=writer)
    assert evidences[0].status == "unverifiable"
    assert "socket" in (evidences[0].test_log or "")
    assert "socket" in evidences[0].summary


def test_checker_unverifiable_when_llm_fails(allowlisted_target):
    class _Boom:
        max_tool_turns = 8

        def generate(self, prompt, **kwargs):
            raise RuntimeError("model is down")

    evidences = check_claims([_impact_claim()], str(allowlisted_target), client=_Boom())
    assert evidences[0].status == "unverifiable"
    assert "model" in evidences[0].summary.lower()


def test_checker_test_log_trims_output(allowlisted_target):
    writer = _TestWriter(
        "def test_noisy():\n"
        "    for i in range(200):\n"
        "        print(f'line {i}')\n"
        "    assert False\n"
    )
    evidences = check_claims([_impact_claim()], str(allowlisted_target), client=writer)
    assert evidences[0].status == "refuted"
    log = evidences[0].test_log or ""
    assert "print(f'line {i}')" in log  # the stored test code is kept whole
    marker = "# --- pytest output"
    assert marker in log
    output_section = log.split(marker, 1)[1].splitlines()[1:]
    assert len(output_section) <= MAX_TEST_LOG_LINES
    assert any("line 199" in line for line in output_section)
