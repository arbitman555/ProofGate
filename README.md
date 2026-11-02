# ProofGate

AI gatekeeper for security reports: breaks a vulnerability report into atomic
factual claims, verifies each claim against the real source code at the stated
version, optionally runs a reproduction test in a sandbox, and returns a
verdict with evidence. It never applies fixes and never touches real systems.

Placeholder skeleton for a hackathon (Python 3.11+). Features are not
implemented yet. See [DESIGN.md](DESIGN.md) for the design.
