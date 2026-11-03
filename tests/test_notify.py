"""Tests for proofgate.notify (issue-comment markdown rendering)."""

from proofgate.notify import audit_issue_report, file_link, render_issue_comment


def _run() -> dict:
    return {
        "verdict": {
            "label": "confirmed",
            "evidence_level": 4,
            "rationale": "Traversal reproduced via ../.",
            "per_claim": [],
            "minutes_saved_estimate": 20.0,
        },
        "evidence": [
            {
                "claim_id": "c1",
                "status": "supported",
                "summary": "download() joins input with os.path.join.",
                "file": "app.py",
                "line_start": 116,
                "line_end": 129,
                "snippet": None,
                "test_log": None,
            },
            {
                "claim_id": "c2",
                "status": "unverifiable",
                "summary": "No evidence either way.",
                "file": None,
                "line_start": None,
                "line_end": None,
                "snippet": None,
                "test_log": None,
            },
        ],
    }


def test_comment_has_verdict_card_sections():
    body = render_issue_comment(_run(), "https://github.com/o/r/blob/main")
    assert "## ProofGate verdict" in body
    assert "**confirmed** (evidence level 4/5)" in body
    assert "Rationale: Traversal reproduced via ../." in body
    assert "Advisory only. A human makes the final call." in body


def test_comment_table_links_cited_files():
    body = render_issue_comment(_run(), "https://github.com/o/r/blob/main")
    assert "[app.py:116](https://github.com/o/r/blob/main/app.py#L116)" in body
    assert "no location cited" in body


def test_comment_without_blob_base_uses_plain_paths():
    body = render_issue_comment(_run())
    assert "app.py:116" in body
    assert "](" not in body


def test_file_link_shapes():
    assert file_link(None, None, None) == "no location cited"
    assert file_link(None, "app.py", None) == "app.py"
    assert (
        file_link("https://github.com/o/r/blob/main", "app.py", 3)
        == "[app.py:3](https://github.com/o/r/blob/main/app.py#L3)"
    )


def test_table_cells_escape_pipes():
    run = _run()
    run["evidence"][0]["summary"] = "a | b"
    body = render_issue_comment(run)
    assert "| a \\| b |" in body


def test_audit_issue_report_writes_comment_file(tmp_path, monkeypatch):
    import proofgate.cli as cli_mod

    report = tmp_path / "report.md"
    report.write_text("# report", encoding="utf-8")
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("demo/target_app\n", encoding="utf-8")
    comment_path = tmp_path / "comment.md"
    monkeypatch.setattr(cli_mod, "run_audit", lambda *a, **k: _run())

    body = audit_issue_report(
        report_path=str(report),
        repo_source="demo/target_app",
        version="demo-v1",
        blob_base="https://github.com/o/r/blob/main",
        comment_path=str(comment_path),
        allowlist_extra="some/checkout",
        allowlist_path=str(allowlist),
    )
    assert "**confirmed** (evidence level 4/5)" in body
    assert "Advisory only. A human makes the final call." in body
    assert comment_path.read_text(encoding="utf-8") == body
    assert "some/checkout" in allowlist.read_text(encoding="utf-8")


def test_audit_issue_report_failure_still_comments(tmp_path, monkeypatch):
    import proofgate.cli as cli_mod

    def boom(*args, **kwargs):
        raise RuntimeError("no key")

    monkeypatch.setattr(cli_mod, "run_audit", boom)
    comment_path = tmp_path / "comment.md"

    body = audit_issue_report(
        report_path=str(tmp_path / "missing.md"),
        repo_source="demo/target_app",
        version="demo-v1",
        blob_base=None,
        comment_path=str(comment_path),
    )
    assert "Audit failed:" in body
    assert "RuntimeError: no key" in body
    assert "Advisory only. A human makes the final call." in body
    assert comment_path.read_text(encoding="utf-8") == body
