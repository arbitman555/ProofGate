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

## Guardrails

- API keys only from environment variables (`MODEL_API_KEY`); never print,
  log, or write the key anywhere.
- Reproduction tests run only inside the sandbox module.
- Never execute code from a report directly.
- Never modify the target repo.
- All verdicts are advisory.
