"""Command line entry point for ProofGate (skeleton)."""

from __future__ import annotations

import argparse
import dataclasses
import json
import time
from datetime import datetime, timezone
from pathlib import Path


#: Placeholder per-token USD rates for the scorecard "cost" column only.
#: These are rough estimates, not billed prices; the column is labeled
#: "(est)" wherever it is printed.
USD_PER_M_INPUT_TOKENS = 3.0
USD_PER_M_OUTPUT_TOKENS = 15.0


def estimate_cost_usd(prompt_tokens: int, completion_tokens: int) -> float:
    """Rough cost estimate for one audit from its token usage."""
    return (
        prompt_tokens / 1_000_000 * USD_PER_M_INPUT_TOKENS
        + completion_tokens / 1_000_000 * USD_PER_M_OUTPUT_TOKENS
    )


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

    score = sub.add_parser("score", help="Score all labeled demo reports")
    score.add_argument("--reports", required=True, help="Directory of reports")
    score.add_argument("--repo", required=True, help="Git URL or local path")
    score.add_argument("--version", required=True, help="Tag or commit")
    score.add_argument(
        "--output",
        default=str(Path("runs") / "demo" / "scorecard.json"),
        help="Where to write the scorecard JSON",
    )
    return parser


def run_audit(
    report: str | Path,
    repo_source: str,
    version: str,
    client=None,
    tool_log: list | None = None,
) -> dict:
    """Run the full audit pipeline for one report.

    Extract claims, check them against ``repo_source`` pinned at ``version``,
    then judge a verdict. Returns a JSON-serializable run record with
    claims, evidence, verdict, per-report token usage, elapsed seconds, and
    a cost estimate. Raises on failure (extraction errors, missing repo).
    """
    from .checker import check_claims
    from .claims import extract_claims
    from .llm import LLMClient
    from .repo import open_repo
    from .verdict import decide_verdict

    started = time.monotonic()
    if client is None:
        client = LLMClient()
    usage_before = (
        client.usage.prompt_tokens,
        client.usage.completion_tokens,
        client.usage.requests,
    )

    report_text = Path(report).read_text(encoding="utf-8")
    claims = extract_claims(report_text, client=client)
    repo = open_repo(repo_source, version)
    log: list = tool_log if tool_log is not None else []
    evidences = check_claims(claims, repo, client=client, tool_log=log)
    verdict = decide_verdict(claims, evidences, client=client)

    prompt_delta = client.usage.prompt_tokens - usage_before[0]
    completion_delta = client.usage.completion_tokens - usage_before[1]
    request_delta = client.usage.requests - usage_before[2]
    seconds = time.monotonic() - started
    return {
        "report": str(report),
        "repo": repo_source,
        "version": version,
        "claims": [dataclasses.asdict(c) for c in claims],
        "evidence": [dataclasses.asdict(e) for e in evidences],
        "verdict": dataclasses.asdict(verdict),
        "tool_log": log,
        "usage": {
            "prompt_tokens": prompt_delta,
            "completion_tokens": completion_delta,
            "total_tokens": prompt_delta + completion_delta,
            "requests": request_delta,
        },
        "seconds": seconds,
        "cost_usd_estimate": estimate_cost_usd(prompt_delta, completion_delta),
    }


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
    from .llm import LLMClient

    try:
        client: LLMClient | None = LLMClient()
    except RuntimeError as exc:
        print(f"error: {exc}")
        raise SystemExit(2)
    run = run_audit(args.report, args.repo, args.version, client=client)

    for item in run["evidence"]:
        where = (
            f"{item['file']}:{item['line_start']}-{item['line_end']}"
            if item["file"] and item["line_start"] is not None
            else "no location cited"
        )
        print(f"[{item['status']}] {item['claim_id']} {where}")
        print(f"  summary: {item['summary']}")

    verdict = run["verdict"]
    print(f"\nverdict: {verdict['label']} (evidence level {verdict['evidence_level']})")
    print(f"rationale: {verdict['rationale']}")
    print(
        f"minutes saved: {verdict['minutes_saved_estimate']:.0f} (estimate) | "
        f"took {run['seconds']:.1f}s | "
        f"cost ${run['cost_usd_estimate']:.4f} (est)"
    )

    runs_dir = Path.cwd() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_path = runs_dir / f"{stamp}.json"
    run_path.write_text(
        json.dumps({"timestamp": stamp, **run}, indent=2),
        encoding="utf-8",
    )
    print(f"\nFull run saved to {run_path}")


def _run_score(args: argparse.Namespace) -> None:
    from .llm import LLMClient

    reports_dir = Path(args.reports)
    labels_path = reports_dir / "labels.json"
    try:
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot load {labels_path}: {exc}")
        raise SystemExit(2)
    try:
        client: LLMClient | None = LLMClient()
    except RuntimeError as exc:
        print(f"error: {exc}")
        raise SystemExit(2)

    runs_dir = Path.cwd() / "runs" / "demo"
    runs_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    for name in sorted(labels):
        expected = labels[name]
        started = time.monotonic()
        try:
            run = run_audit(
                reports_dir / name, args.repo, args.version, client=client
            )
            got = run["verdict"]["label"]
            level = run["verdict"]["evidence_level"]
            error: str | None = None
        except Exception as exc:  # one bad report must not stop the sweep
            run = {
                "report": str(reports_dir / name),
                "repo": args.repo,
                "version": args.version,
                "error": f"{type(exc).__name__}: {exc}",
            }
            got = "error"
            level = "-"
            error = run["error"]
        seconds = time.monotonic() - started
        cost = run.get("cost_usd_estimate", 0.0)

        cache_path = runs_dir / f"{Path(name).stem}.json"
        cache_path.write_text(
            json.dumps(
                {
                    "timestamp": datetime.now(timezone.utc).strftime(
                        "%Y%m%dT%H%M%SZ"
                    ),
                    "expected": expected,
                    "got": got,
                    "match": got == expected,
                    "error": error,
                    **run,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        rows.append(
            {
                "report": name,
                "expected": expected,
                "got": got,
                "level": level,
                "seconds": seconds,
                "cost": cost,
            }
        )

    width = max([len("report")] + [len(r["report"]) for r in rows])
    print(
        f"{'report':<{width}}  {'expected':<14}  {'got':<14}  "
        f"{'level':<5}  {'seconds':>7}  {'cost (est)':>10}"
    )
    print("-" * (width + 14 + 14 + 5 + 7 + 10 + 12))
    for row in rows:
        print(
            f"{row['report']:<{width}}  {row['expected']:<14}  {row['got']:<14}  "
            f"{str(row['level']):<5}  {row['seconds']:>7.1f}  ${row['cost']:>9.4f}"
        )
    correct = sum(1 for r in rows if r["expected"] == r["got"])
    accuracy = correct / len(rows) if rows else 0.0
    print(f"\nAccuracy: {correct}/{len(rows)} ({accuracy:.1%})")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                "reports_dir": str(reports_dir),
                "repo": args.repo,
                "version": args.version,
                "results": rows,
                "accuracy": accuracy,
                "correct": correct,
                "total": len(rows),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Scorecard saved to {output}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        _run_audit(args)
    elif args.command == "extract":
        _run_extract(args)
    elif args.command == "score":
        _run_score(args)


if __name__ == "__main__":
    main()
