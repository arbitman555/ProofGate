# ProofGate

AI gatekeeper for security reports: breaks a vulnerability report into atomic
factual claims, verifies each claim against the real source code at the stated
version, optionally runs a reproduction test in a sandbox, and returns a
verdict with evidence. It never applies fixes and never touches real systems.

Placeholder skeleton for a hackathon (Python 3.11+). Features are not
implemented yet. See [DESIGN.md](DESIGN.md) for the design.

## Demo corpus

- `demo/target_app/` is a tiny Flask app written from scratch for this
  project (MIT, our own code) with three planted bugs and one correctly
  validated endpoint. It is tagged `demo-v1` (vulnerable); the
  `demo-v1-fixed` branch fixes all three bugs.
- `demo/reports/` holds 12 labeled demo reports targeting the app
  (`labels.json` maps each file to its true verdict): 4 fabricated, 4
  plausible but wrong, and 4 real.

## Third-party content

- `demo/live/04_six_live.md` is a demo report targeting the real public
  six library (https://github.com/benjaminp/six), which is MIT-licensed. It
  is used to test ProofGate against a real public repo; short code excerpts
  from six appear in saved runs only as cited evidence.
