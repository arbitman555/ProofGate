Read this file before every task.

# ProofGate Design

## Purpose

ProofGate is an AI gatekeeper for security reports. It breaks a vulnerability
report into atomic factual claims, verifies each claim against the real source
code at the stated version, optionally runs a reproduction test in a sandbox,
and returns a verdict with evidence. It never applies fixes and never touches
real systems.

## Pipeline

1. **Report** — intake a vulnerability report (path to a file).
2. **Claims** (`claims.py`) — split the report into atomic factual claims.
3. **Checks** (`checker.py` + `repo.py`) — verify each claim statically
   against the target repo pinned at the stated version (tag or commit).
4. **Optional test** (`sandbox.py`) — for claims marked `check_method=test`,
   run a reproduction test inside the sandbox only.
5. **Verdict** (`verdict.py`) — aggregate per-claim evidence into a label,
   an evidence level, a rationale, and a minutes-saved estimate.

LLM access goes through `llm.py` (Meta Model API via the OpenAI SDK), and the
CLI entry point is `cli.py` (`audit --report <path> --repo <git url or local
path> --version <tag or commit>`).

## Data models (`models.py`)

- **Claim**: `id`, `kind` (one of `symbol_exists`, `location`,
  `version_affected`, `code_property`, `data_flow`, `reproducible_impact`),
  `statement` (plain English), `target` (dict: `file`, `symbol`, `version`,
  line hints), `check_method` (`static` | `test`).
- **Evidence**: `claim_id`, `status` (`supported` | `refuted` |
  `unverifiable`), `summary`, `file`, `line_start`, `line_end`, `snippet`
  (max 15 lines), `test_log` (optional).
- **Verdict**: `label` (`fabricated` | `claim_false` | `partially_true` |
  `confirmed` | `inconclusive`), `evidence_level` (0-5, see below),
  `rationale`, `per_claim` list, `minutes_saved_estimate`.

## Evidence ladder

- **0** — nothing verified.
- **1** — code exists as described.
- **2** — behavior observed in code.
- **3** — reproduced by test.
- **4** — security boundary crossed.
- **5** — independently reproducible.

## Sandbox (`sandbox.py`)

Reproduction tests for `reproducible_impact` claims run only via
`run_repro_test(repo, test_code, timeout_s=60)`, gated by
`sandbox_allowlist.txt` (default entry: `demo/target_app`):

- The repo path or URL must be listed in the allowlist, otherwise nothing
  runs (`blocked_reason="repo not allowlisted"`).
- The repo checkout is copied into a fresh temp directory, the test is
  written as `test_proofgate_repro.py`, and `python -m pytest -q` runs in a
  subprocess with that temp dir as cwd.
- The subprocess environment is rebuilt from scratch: only `PATH`,
  `SYSTEMROOT` (Windows), and `TEMP`/`TMP` are inherited. No `MODEL_API_KEY`,
  no tokens, no cloud credentials. (The pytest runner itself adds
  `PYTEST_CURRENT_TEST`/`PYTEST_VERSION` at runtime; those come from the
  runner, not the parent process.)
- Before running, the test source is statically rejected when it imports or
  calls `socket`, `requests`, `urllib`, `http.client`, `subprocess`,
  `os.system`, `os.popen`, `shutil.rmtree`, `ctypes`, uses dynamic imports
  of those modules, or passes absolute/`..` paths to filesystem calls.
- A wall-clock timeout kills the process tree (`taskkill /T /F` on Windows,
  process-group kill on POSIX). The temp dir is removed afterwards.
- `checker.py` maps the outcome: passed = supported (evidence level 3),
  failed = refuted, blocked or error = unverifiable. The generated test code
  plus the last 60 output lines are stored in `Evidence.test_log`.

### Sandbox limits (read before trusting it)

This is defense in depth for a demo, not a hardened sandbox. Known gaps:

- The static screen is a denylist over literal source. Simple import
  aliases are resolved, but `getattr`/`eval`, computed strings, `importlib`
  with non-literal names, re-exported modules, or paths built at runtime
  (for example `open(os.path.join(a, b))`) can evade it. Only literal banned
  imports/calls and literal absolute/`..` path arguments to filesystem sinks
  are caught.
- No OS-level isolation: no container, seccomp profile, or network
  namespace. Tests run with the user's privileges; loopback and the local
  network stay reachable except through the blocked imports.
- No CPU or memory caps, only a wall-clock timeout, enforced best-effort.
- Secret hygiene is environment-only: the repo copy itself could contain
  secrets, and model-written tests are untrusted input. Never point the
  sandbox at a repo you would not already execute.
- The allowlist is a plain text file; anyone who can edit it can authorize
  code execution. Keep entries exact (full paths or URLs) and review
  generated tests in `Evidence.test_log`.
- Temp-dir cleanup and the timeout kill are best-effort. A deliberately
  hostile test is out of scope for this demo sandbox.

## Guardrails

- API keys only from environment variables (`MODEL_API_KEY`); never print,
  log, or write the key anywhere.
- Reproduction tests run only inside the sandbox module.
- Never execute code from a report directly.
- Never modify the target repo.
- All verdicts are advisory.
