"""Command line entry point for ProofGate (skeleton)."""

from __future__ import annotations

import argparse
import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofgate", description="ProofGate CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Audit a vulnerability report")
    audit.add_argument("--report", required=True, help="Path to the report file")
    audit.add_argument("--repo", required=True, help="Git URL or local path")
    audit.add_argument("--version", required=True, help="Tag or commit")

    extract = sub.add_parser("extract", help="Extract atomic claims from a report")
    extract.add_argument("--report", required=True, help="Path to the report file")
    extract.add_argument(
        "--json", action="store_true", help="Print raw JSON instead of a table"
    )
    return parser


def _format_table(claims) -> str:
    widths = {
        "id": max([2] + [len(c.id) for c in claims]),
        "kind": max([4] + [len(c.kind) for c in claims]),
        "method": max([6] + [len(c.check_method) for c in claims]),
    }
    header = (
        f"{'ID':<{widths['id']}}  {'KIND':<{widths['kind']}}  "
        f"{'METHOD':<{widths['method']}}  STATEMENT / TARGET"
    )
    lines = [header, "-" * max(len(header), 40)]
    for claim in claims:
        target = ", ".join(f"{k}={v}" for k, v in claim.target.items()) or "-"
        lines.append(
            f"{claim.id:<{widths['id']}}  {claim.kind:<{widths['kind']}}  "
            f"{claim.check_method:<{widths['method']}}  {claim.statement}"
        )
        lines.append(
            f"{'':<{widths['id']}}  {'':<{widths['kind']}}  "
            f"{'':<{widths['method']}}  target: {target}"
        )
    return "\n".join(lines)


def _run_extract(args: argparse.Namespace) -> None:
    from .claims import extract_claims

    report_text = Path(args.report).read_text(encoding="utf-8")
    claims = extract_claims(report_text)
    if args.json:
        print(
            json.dumps([dataclasses.asdict(c) for c in claims], indent=2)
        )
    else:
        if not claims:
            print("No factual claims found.")
        else:
            print(_format_table(claims))


def _run_audit(args: argparse.Namespace) -> None:
    from .checker import check_claims
    from .claims import extract_claims
    from .llm import LLMClient
    from .repo import open_repo

    report_text = Path(args.report).read_text(encoding="utf-8")
    client: LLMClient | None = None
    try:
        client = LLMClient()
    except RuntimeError as exc:
        print(f"error: {exc}")
        raise SystemExit(2)
    claims = extract_claims(report_text, client=client)
    repo = open_repo(args.repo, args.version)
    tool_log: list = []
    evidences = check_claims(claims, repo, client=client, tool_log=tool_log)

    for claim, evidence in zip(claims, evidences):
        where = (
            f"{evidence.file}:{evidence.line_start}-{evidence.line_end}"
            if evidence.file and evidence.line_start is not None
            else "no location cited"
        )
        print(f"[{evidence.status}] {claim.id} ({claim.kind}) {where}")
        print(f"  claim:   {claim.statement}")
        print(f"  summary: {evidence.summary}")

    runs_dir = Path.cwd() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_path = runs_dir / f"{stamp}.json"
    run_path.write_text(
        json.dumps(
            {
                "timestamp": stamp,
                "report": args.report,
                "repo": args.repo,
                "version": args.version,
                "claims": [dataclasses.asdict(c) for c in claims],
                "evidence": [dataclasses.asdict(e) for e in evidences],
                "tool_log": tool_log,
                "usage": dataclasses.asdict(client.usage),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nFull run saved to {run_path}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        _run_audit(args)
    elif args.command == "extract":
        _run_extract(args)


if __name__ == "__main__":
    main()
