# ProofGate

AI gatekeeper for security reports: breaks a vulnerability report into atomic
factual claims, verifies each claim against the real source code at the stated
version, optionally runs a reproduction test in a sandbox, and returns a
verdict with evidence. It never applies fixes and never touches real systems.

Placeholder skeleton for a hackathon (Python 3.11+). Features are not
implemented yet. See [DESIGN.md](DESIGN.md) for the design.

## Third-party content

- `runs/demo/six_1.17.0.json` contains short code excerpts from the six
  library (https://github.com/benjaminp/six), which is MIT-licensed. It is
  a saved live run used to test ProofGate against a real public repo; the
  excerpts are included only as cited evidence.
- `demo/reports/04_six_live.md` is a test report written for this project
  that targets six.
