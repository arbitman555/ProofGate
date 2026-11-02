"""Command line entry point for ProofGate (skeleton)."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofgate", description="ProofGate CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Audit a vulnerability report")
    audit.add_argument("--report", required=True, help="Path to the report file")
    audit.add_argument("--repo", required=True, help="Git URL or local path")
    audit.add_argument("--version", required=True, help="Tag or commit")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        print("not implemented")


if __name__ == "__main__":
    main()
