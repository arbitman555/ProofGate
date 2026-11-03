"""Markdown rendering for ProofGate results posted outside the UI.

Used by the GitHub Action (`.github/workflows/proofgate.yml`) to turn an
audit run record into an issue comment. Kept here (instead of inline in the
workflow) so it is importable and unit-tested.
"""

from __future__ import annotations


def _escape_cell(text: str) -> str:
    """Make free text safe for one GitHub markdown table cell."""
    return " ".join(str(text).split()).replace("|", "\\|")


def _short(text: str | None, limit: int = 140) -> str:
    text = _escape_cell(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def file_link(blob_base: str | None, file: str | None, line: int | None) -> str:
    """Render a `file:line` repo link, or plain text when uncited."""
    if not file:
        return "no location cited"
    label = file if line is None else f"{file}:{line}"
    if not blob_base:
        return label
    anchor = "" if line is None else f"#L{line}"
    return f"[{label}]({blob_base.rstrip('/')}/{file}{anchor})"


def audit_issue_report(
    *,
    report_path: str,
    repo_source: str,
    version: str,
    blob_base: str | None,
    comment_path: str,
    allowlist_extra: str | None = None,
    allowlist_path: str = "sandbox_allowlist.txt",
) -> str:
    """Audit one report file and write the issue-comment markdown to disk.

    Used by the GitHub Action: ``report_path`` holds the issue body,
    ``repo_source`` is the checked-out repo, and ``version`` is the branch
    to audit. ``allowlist_extra`` (usually the checkout path) is appended
    to the sandbox allowlist so repro tests may run against that copy;
    without it, repro claims are left unverifiable. Failures still produce
    a comment (naming the error) instead of raising, so the issue always
    gets a reply. Returns the comment text.
    """
    from proofgate.cli import run_audit

    if allowlist_extra:
        with open(allowlist_path, "a", encoding="utf-8") as fh:
            fh.write(allowlist_extra + "\n")
    try:
        run = run_audit(report_path, repo_source, version)
        comment = render_issue_comment(run, blob_base)
    except Exception as exc:
        comment = (
            "## ProofGate verdict\n\n"
            f"Audit failed: `{type(exc).__name__}: {exc}`\n\n"
            "Advisory only. A human makes the final call."
        )
    with open(comment_path, "w", encoding="utf-8") as fh:
        fh.write(comment)
    return comment


def render_issue_comment(run: dict, blob_base: str | None = None) -> str:
    """Render an audit ``run`` record as a GitHub issue comment (markdown).

    Args:
        run: Record as returned by :func:`proofgate.cli.run_audit`.
        blob_base: Optional ``https://host/owner/repo/blob/<branch>``
            prefix used to link cited files.

    Returns:
        Markdown with the verdict card: label, evidence level, per-claim
        table with file:line links, rationale, and the advisory line.
    """
    verdict = run.get("verdict", {}) or {}
    label = verdict.get("label", "inconclusive")
    level = verdict.get("evidence_level", 0)
    rationale = verdict.get("rationale", "")
    evidence = run.get("evidence", []) or []

    lines = [
        "## ProofGate verdict",
        "",
        f"**{label}** (evidence level {level}/5)",
        "",
        "| Claim | Result | Location | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for item in evidence:
        location = file_link(
            blob_base, item.get("file"), item.get("line_start")
        )
        lines.append(
            f"| {_escape_cell(item.get('claim_id', '?'))} "
            f"| {_escape_cell(item.get('status', '?'))} "
            f"| {location} "
            f"| {_short(item.get('summary'))} |"
        )
    lines += [
        "",
        f"Rationale: {_escape_cell(rationale) or '—'}",
        "",
        "Advisory only. A human makes the final call.",
    ]
    return "\n".join(lines)
