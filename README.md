# ProofGate

AI made vulnerability claims cheap. ProofGate makes checking them cheap too.

AI gatekeeper for security reports: breaks a vulnerability report into atomic
factual claims, verifies each claim against the real source code at the stated
version, optionally runs a reproduction test in a sandbox, and returns a
verdict with evidence. It never applies fixes and never touches real systems.

## Demo

Video: https://1drv.ms/v/c/7a6789abbb9d333c/IQCPA0AA43E6TYAwdqqwAijWAUOLwA0IPhVuxBIoet5Ul2M



## The problem

AI-generated reports flooded triage queues: HackerOne reported report volume up
more than 100% after stronger AI models arrived (May 2026). curl's valid-report
rate fell from over 15% to under 5% in 2025, and curl ended its bug bounty on
Jan 31, 2026. Writing a plausible report takes minutes, while disproving a
complex one can take an expert about an hour.

Source: https://www.penligent.ai/hackinglabs/?p=6650

## How it works

Pipeline: report -> atomic claims -> code checks -> sandboxed repro test -> verdict.

- `fabricated`: the report describes code that is not there.
- `claim_false`: the code exists, but the claimed property or behavior is wrong.
- `partially_true`: some claims held while others were refuted.
- `confirmed`: the key claims are supported by evidence.
- `inconclusive`: the evidence does not settle the matter.

Evidence ladder:

| Level | Meaning |
| --- | --- |
| 0 | Nothing verified |
| 1 | Code exists as described |
| 2 | Behavior observed in code |
| 3 | Reproduced by test |
| 4 | Security boundary crossed |
| 5 | Independently reproducible |

Every supported or refuted claim must cite a file and line range the checker
agent actually read with the `read_file` tool; anything else is downgraded to
unverifiable in code. See [DESIGN.md](DESIGN.md) for the full design.

## Use of Meta AI

| Model | Role |
| --- | --- |
| Muse Spark 1.3 | Claim extraction + tool-using checker agent (find_symbol, search_code, read_file, writes repro tests) |
| Muse Wonder 1.0 | Evidence judge for the final verdict (falls back to Spark) |
| Muse Code | Used to build this project |

## Results

Scorecard from `runs/demo/scorecard.json` (demo app at `demo-v1`):

| report | expected | got | level | seconds |
| --- | --- | --- | --- | --- |
| 01_fabricated_jwt.md | fabricated | inconclusive | 0 | 293.7 |
| 02_plausible_avatar_traversal.md | claim_false | claim_false | 2 | 92.4 |
| 03_real_download_traversal.md | confirmed | confirmed | 4 | 311.6 |
| 04_fabricated_cookie_helper.md | fabricated | fabricated | 0 | 168.5 |
| 05_plausible_search_emails.md | claim_false | claim_false | 3 | 148.5 |
| 06_real_search_sqli.md | confirmed | confirmed | 3 | 125.7 |
| 07_fabricated_backup_export.md | fabricated | fabricated | 0 | 269.4 |
| 08_plausible_download_safe.md | claim_false | claim_false | 2 | 86.8 |
| 09_real_admin_export.md | confirmed | confirmed | 4 | 150.9 |
| 10_fabricated_sanitize_helper.md | fabricated | fabricated | 0 | 270.8 |
| 11_plausible_avatar_wildcard.md | claim_false | claim_false | 2 | 123.4 |
| 12_real_download_config.md | confirmed | confirmed | 4 | 126.6 |

- Accuracy: 11/12 (91.7%). The one miss (01) came back inconclusive instead of
  fabricated. No fake report was confirmed and no real report was rejected.
- Typical audit: ~1.5-5 minutes and ~$0.55-1.30 per report.
- Speed work: audits went from ~15-20 min to ~1.5-5 min via parallel claim
  checks (4 workers), a per-claim tool-turn cap of 8 with early stop, and
  retries on 503/429.

## Quick start

Install (Python 3.11+):

```powershell
pip install -r requirements.txt
pip install -e .
```

```bash
pip install -r requirements.txt
pip install -e .
```

Set the API key as an environment variable only (never in a file):

```powershell
$env:MODEL_API_KEY = "your-key-here"
```

```bash
export MODEL_API_KEY="your-key-here"
```

Audit one report:

```powershell
proofgate audit --report demo/reports/03_real_download_traversal.md --repo demo/target_app --version demo-v1
```

```bash
proofgate audit --report demo/reports/03_real_download_traversal.md --repo demo/target_app --version demo-v1
```

Score all demo reports:

```powershell
proofgate score --reports demo/reports --repo demo/target_app --version demo-v1
```

```bash
proofgate score --reports demo/reports --repo demo/target_app --version demo-v1
```

Web UI:

```powershell
streamlit run src/proofgate/app.py
```

```bash
streamlit run src/proofgate/app.py
```

"Replay cached run" toggle: replays saved real runs from `runs/demo/` with no
API key or cost.

## GitHub Action

Labeling an issue `security-report` runs an audit and posts a verdict comment.
The key is stored as the `MODEL_API_KEY` Actions secret. Verdicts are advisory;
a human makes the final call. See [docs/github-action.md](docs/github-action.md).

## Safety design

- Report text is treated as untrusted input (delimited; embedded instructions
  are ignored).
- Repro tests run only for allowlisted repos (`sandbox_allowlist.txt`), in a
  throwaway copy, with a stripped environment (no keys), a Flask test client
  only, and a timeout.
- Propose-only: never modifies the target repo or applies fixes. Verdicts are
  advisory; a human makes the final call.
- API key is read only from the environment and never logged.

## Demo corpus

- `demo/target_app/` is a tiny Flask app written from scratch for this
  project (MIT, our own code) with three planted bugs and one correctly
  validated endpoint. It is tagged `demo-v1` (vulnerable); the
  `demo-v1-fixed` branch fixes all three bugs.
- `demo/reports/` holds 12 labeled demo reports targeting the app
  (`labels.json` maps each file to its true verdict): 4 fabricated, 4
  plausible but wrong, and 4 real.
- Why two versions: demo-v1 is the vulnerable app; the demo-v1-fixed branch
  has the three bugs patched. Auditing the same report against both shows
  ProofGate checks the actual code: a real report is confirmed on demo-v1 and
  refuted on demo-v1-fixed.

## Limitations

- Python targets only; single-file and simple multi-file bugs, no multi-step
  exploit chains.
- Small labeled test set (12 reports); results can vary between runs (the same
  report can land one evidence level apart).
- A claim can hit the per-claim tool budget and come back unverifiable; the
  verdict still uses the remaining evidence.
- The evidence level reflects what was verified, including tests that disprove
  a claim; the label doesn't yet distinguish "reproduced" from "disproved by
  test".
- The sandbox's static screen is a denylist and can be sidestepped (e.g.
  building strings with `chr()`); real containment is the throwaway copy,
  stripped environment, test client only, and timeout. Defense in depth for a
  demo, not a hardened sandbox.
- The checker agent sometimes repeats the same tool call; the turn cap bounds
  the cost.

## Third-party content

- `demo/live/04_six_live.md` is a demo report targeting the real public
  six library (https://github.com/benjaminp/six), which is MIT-licensed. It
  is used to test ProofGate against a real public repo; short code excerpts
  from six appear in saved runs only as cited evidence.
- `runs/demo/six_1.17.0.json` is a saved live run against six; it contains
  short MIT-licensed excerpts used only as cited evidence.

## Built during the Meta Global AI Developer Hackathon 2026

All code in this repository was written during the hackathon (Oct 26 - Nov 4,
2026). The demo target app is original, intentionally vulnerable code for
testing. Do not deploy it.

## License

MIT (see LICENSE).
