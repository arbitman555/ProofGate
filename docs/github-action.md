# ProofGate GitHub Action

Audits any issue labeled `security-report` and posts the verdict as an
issue comment. The issue body is the (untrusted) report; the code under
audit is this repo at its default branch.

## Setup

1. Copy `.github/workflows/proofgate.yml` into your repo (it is already
   in place here).
2. Add the secret: repo **Settings → Secrets and variables → Actions →
   New repository secret**, name `MODEL_API_KEY`, value your Meta Model
   API key. The workflow reads it from `secrets.MODEL_API_KEY` into the
   environment; it is never printed or written anywhere.
3. Create the label: **Issues → Labels → New label**, name
   `security-report` (any color and description, e.g. "triage with
   ProofGate").

No login page, database, or extra service is involved.

## Try it on a test issue

1. Open a new issue and paste a report into the body — for example the
   contents of `demo/reports/03_real_download_traversal.md`.
2. Add the `security-report` label (or create the issue with the label).
3. Wait for the `proofgate` workflow run to finish (a few minutes), then
   read the posted comment: verdict label, evidence level, per-claim
   table with file:line links, rationale, and the advisory line.

To re-run on the same issue, remove the label and add it again.

## Notes

- The verdict comment always ends with "Advisory only. A human makes the
  final call." Treat every verdict as a triage hint, not a decision.
- Sandbox reproduction tests run against the checked-out repo copy only,
  gated by the same static screens and timeouts as local audits (see
  DESIGN.md). Repos outside the allowlist leave repro claims
  unverifiable.
- Action versions are pinned (`actions/checkout@v4`,
  `actions/setup-python@v5`).
