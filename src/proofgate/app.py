"""ProofGate web UI.

Run from the repository root::

    streamlit run src/proofgate/app.py

The Audit tab runs the same pipeline as the CLI (extract claims, check
each claim with the model agent loop, judge a verdict) and streams
progress: claims appear as a checklist, then each flips to its final
status as its worker finishes. The Scorecard tab renders
``runs/demo/scorecard.json``.

The API key comes from the ``MODEL_API_KEY`` environment variable only;
there is deliberately no input field for it.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from proofgate.checker import MAX_CHECK_WORKERS, _check_one_claim
from proofgate.claims import extract_claims
from proofgate.cli import estimate_cost_usd
from proofgate.llm import DEFAULT_MAX_TOOL_TURNS, LLMClient
from proofgate.models import Evidence
from proofgate.repo import open_repo
from proofgate.verdict import decide_verdict

ROOT = Path.cwd()
RUNS_DEMO = ROOT / "runs" / "demo"
REPORTS_DIR = ROOT / "demo" / "reports"

STATUS_ICON = {
    "pending": "…",
    "supported": "✔",
    "refuted": "✘",
    "unverifiable": "?",
}

VERDICT_STYLE = {
    # label -> (streamlit call, one-line meaning)
    "confirmed": ("success", "the key claims held up against the code"),
    "partially_true": ("warning", "some claims held while others did not"),
    "claim_false": ("warning", "the code exists but the claims did not hold"),
    "fabricated": ("error", "the report describes code that is not there"),
    "inconclusive": ("info", "the evidence does not settle the matter"),
}

LADDER_MEANING = {
    0: "nothing verified",
    1: "code exists as described",
    2: "behavior observed in code",
    3: "reproduced by test",
    4: "security boundary crossed",
    5: "independently reproducible",
}


def _short_args(arguments: dict, limit: int = 110) -> str:
    text = json.dumps(arguments, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _checklist_markdown(claims, statuses) -> str:
    lines = []
    for claim in claims:
        status = statuses.get(claim.id, "pending")
        icon = STATUS_ICON.get(status, "…")
        lines.append(
            f"{icon} **{claim.id}** `{claim.kind}` — {status}  \n"
            f"{claim.statement}"
        )
    return "\n\n".join(lines) if lines else "No claims."


def _steps_markdown(tool_log, limit: int = 15) -> str:
    if not tool_log:
        return "No tool calls yet."
    lines = []
    for entry in tool_log[-limit:]:
        lines.append(
            f"`{entry.get('claim_id', '?')}` "
            f"**{entry.get('tool', '?')}** "
            f"{_short_args(entry.get('arguments', {}))}"
        )
    return "\n\n".join(lines)


def _evidence_location(evidence) -> str:
    file = evidence.get("file") if isinstance(evidence, dict) else evidence.file
    start = (
        evidence.get("line_start")
        if isinstance(evidence, dict)
        else evidence.line_start
    )
    end = (
        evidence.get("line_end") if isinstance(evidence, dict) else evidence.line_end
    )
    if not file or start is None:
        return "no location cited"
    return f"{file}:{start}" if end in (None, start) else f"{file}:{start}-{end}"


def _get(item, key: str, default=None):
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def render_verdict_card(verdict, seconds: float, cost: float) -> None:
    """Show the final verdict: colored label, ladder, rationale, numbers."""
    label = _get(verdict, "label", "inconclusive")
    level = int(_get(verdict, "evidence_level", 0) or 0)
    style, meaning = VERDICT_STYLE.get(label, ("info", ""))
    getattr(st, style)(f"**{label}** — {meaning}")
    st.write(f"**Evidence level {level} of 5** — {LADDER_MEANING.get(level, '')}")
    st.progress(level / 5)
    st.write(_get(verdict, "rationale", ""))
    time_col, cost_col, saved_col = st.columns(3)
    time_col.metric("Time taken", f"{seconds:.1f}s")
    cost_col.metric("API cost", f"${cost:.4f} (est)")
    saved_col.metric(
        "Analyst minutes saved",
        f"{float(_get(verdict, 'minutes_saved_estimate', 0.0)):.0f} (estimate)",
    )


def render_evidence(claims, evidences) -> None:
    """One expandable evidence section per claim."""
    statements = {
        (c.get("id") if isinstance(c, dict) else c.id): (
            c.get("statement") if isinstance(c, dict) else c.statement
        )
        for c in claims
    }
    for item in evidences:
        claim_id = _get(item, "claim_id", "?")
        status = _get(item, "status", "unverifiable")
        icon = STATUS_ICON.get(status, "…")
        with st.expander(f"{icon} {claim_id} — {status}", expanded=False):
            if claim_id in statements:
                st.write(statements[claim_id])
            st.write(f"Location: `{_evidence_location(item)}`")
            st.write(_get(item, "summary", ""))
            snippet = _get(item, "snippet")
            if snippet:
                st.code(snippet, language="python")
            test_log = _get(item, "test_log")
            if test_log:
                st.write("Sandbox test log:")
                st.code(test_log)


def _run_live_audit(report_text, repo_source, version, ui) -> None:
    """Run the full pipeline, streaming progress into ``ui`` placeholders."""
    try:
        client: LLMClient | None = LLMClient()
    except RuntimeError as exc:
        st.error(str(exc))
        return
    usage_before = (
        client.usage.prompt_tokens,
        client.usage.completion_tokens,
        client.usage.requests,
    )
    started = time.monotonic()

    with st.spinner("Extracting claims…"):
        try:
            claims = extract_claims(report_text, client=client)
        except Exception as exc:
            st.error(f"Claim extraction failed: {type(exc).__name__}: {exc}")
            return
    if not claims:
        st.warning("No factual claims found in the report.")
        return

    try:
        repo = open_repo(repo_source, version)
    except Exception as exc:
        st.error(f"Could not open repo: {type(exc).__name__}: {exc}")
        return

    statuses = {c.id: "pending" for c in claims}
    tool_log: list = []
    lock = threading.Lock()
    max_turns = max(1, int(getattr(client, "max_tool_turns", DEFAULT_MAX_TOOL_TURNS) or 1))

    def _check(claim):
        local_log: list = []
        try:
            evidence = _check_one_claim(claim, repo, client, max_turns, local_log)
        except Exception as exc:  # keep the other claims running
            evidence = Evidence(
                claim_id=claim.id,
                status="unverifiable",
                summary=f"Checker errored ({type(exc).__name__}: {exc}); left unverifiable.",
            )
        with lock:
            tool_log.extend(local_log)
            statuses[claim.id] = evidence.status
        return evidence

    workers = min(MAX_CHECK_WORKERS, len(claims))
    ui["checklist"].markdown(_checklist_markdown(claims, statuses))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check, claim): claim for claim in claims}
        remaining = set(futures)
        while remaining:
            done = {f for f in remaining if f.done()}
            remaining -= done
            with lock:
                snapshot = list(tool_log)
                current = dict(statuses)
            ui["checklist"].markdown(_checklist_markdown(claims, current))
            ui["steps"].markdown(_steps_markdown(snapshot))
            if remaining:
                time.sleep(0.5)
        evidences = [f.result() for f in futures]

    verdict = decide_verdict(claims, evidences, client=client)
    seconds = time.monotonic() - started
    prompt_delta = client.usage.prompt_tokens - usage_before[0]
    completion_delta = client.usage.completion_tokens - usage_before[1]
    cost = estimate_cost_usd(prompt_delta, completion_delta)

    st.session_state["pg_result"] = {
        "claims": [dataclasses.asdict(c) for c in claims],
        "evidences": [dataclasses.asdict(e) for e in evidences],
        "verdict": dataclasses.asdict(verdict),
        "seconds": seconds,
        "cost": cost,
        "tool_log": list(tool_log),
    }
    ui["checklist"].markdown(_checklist_markdown(claims, statuses))
    ui["steps"].markdown(_steps_markdown(tool_log, limit=50))
    render_verdict_card(verdict, seconds, cost)
    render_evidence([dataclasses.asdict(c) for c in claims],
                    [dataclasses.asdict(e) for e in evidences])


def _load_cached_run(name: str) -> dict | None:
    try:
        return json.loads((RUNS_DEMO / name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not load cached run {name}: {exc}")
        return None


def _render_cached_result(run: dict) -> None:
    if run.get("error"):
        st.error(f"Cached run failed: {run['error']}")
        return
    claims = run.get("claims", [])
    evidences = run.get("evidence", [])
    verdict = run.get("verdict", {})
    usage = run.get("usage", {}) or {}
    seconds = float(run.get("seconds", 0.0))
    cost = float(
        run.get("cost_usd_estimate", 0.0)
        or estimate_cost_usd(
            usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
        )
    )
    statuses = {e.get("claim_id", "?"): e.get("status", "?") for e in evidences}
    st.markdown(_checklist_markdown(
        [type("C", (), {"id": c.get("id"), "kind": c.get("kind"),
                        "statement": c.get("statement")})() for c in claims],
        statuses,
    ))
    with st.expander("Agent steps (from cached tool log)", expanded=False):
        st.markdown(_steps_markdown(run.get("tool_log", []), limit=200))
    render_verdict_card(verdict, seconds, cost)
    render_evidence(claims, evidences)


def _on_report_choice() -> None:
    """Copy the selected demo report into the report text area."""
    choice = st.session_state.get("pg_report_choice", "(paste below)")
    if choice != "(paste below)":
        try:
            st.session_state["pg_text"] = (REPORTS_DIR / choice).read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            st.error(f"Could not read {choice}: {exc}")


def audit_tab() -> None:
    """Audit tab: inputs, live progress, verdict card, replay toggle."""
    st.subheader("Audit a report")

    report_files = sorted(
        p.name for p in REPORTS_DIR.glob("*.md") if p.is_file()
    )
    choice = st.selectbox(
        "Load a report from demo/reports (optional)",
        ["(paste below)"] + report_files,
        key="pg_report_choice",
        on_change=_on_report_choice,
    )
    if "pg_text" not in st.session_state:
        st.session_state["pg_text"] = ""
    report_text = st.text_area("Report (markdown)", key="pg_text", height=260)
    repo_source = st.text_input("Repo (local path or git URL)", "demo/target_app")
    version = st.text_input("Version (tag or commit)", "demo-v1")
    replay = st.toggle(
        "Replay cached run (loads runs/demo/ results, no API calls)",
        value=False,
    )

    cached_names = sorted(
        p.name
        for p in RUNS_DEMO.glob("*.json")
        if p.is_file() and p.name != "scorecard.json"
    )
    cached_choice = None
    if replay:
        if not cached_names:
            st.warning("No cached runs in runs/demo/ yet.")
        else:
            cached_choice = st.selectbox("Cached run", cached_names)

    if choice != "(paste below)":
        st.write(f"Auditing: {choice}")

    if st.button("Audit", type="primary"):
        if replay:
            if cached_choice:
                run = _load_cached_run(cached_choice)
                if run is not None:
                    st.session_state["pg_result"] = None
                    _render_cached_result(run)
        else:
            if not report_text.strip():
                st.error("Paste a report or load one from demo/reports.")
            elif not repo_source.strip() or not version.strip():
                st.error("Repo and version are required.")
            else:
                st.session_state["pg_result"] = None
                st.write("**Claims**")
                checklist_box = st.empty()
                st.write("**Agent steps (live)**")
                steps_box = st.empty()
                _run_live_audit(
                    report_text,
                    repo_source.strip(),
                    version.strip(),
                    {"checklist": checklist_box, "steps": steps_box},
                )


def scorecard_tab() -> None:
    """Scorecard tab: render runs/demo/scorecard.json as a table."""
    st.subheader("Scorecard")
    path = RUNS_DEMO / "scorecard.json"
    if not path.is_file():
        st.info("No scorecard yet. Run the full sweep first.")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not load scorecard: {exc}")
        return
    results = data.get("results", [])
    st.metric(
        "Accuracy",
        f"{data.get('correct', 0)}/{data.get('total', len(results))} "
        f"({float(data.get('accuracy', 0.0)):.1%})",
    )
    rows = [
        {
            "report": r.get("report", "?"),
            "expected": r.get("expected", "?"),
            "got": r.get("got", "?"),
            "level": r.get("level", "—"),
            "seconds": round(float(r.get("seconds", 0.0)), 1),
            "match": "✔" if r.get("expected") == r.get("got") else "✘",
        }
        for r in results
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(page_title="ProofGate", layout="wide")
    st.title("ProofGate")
    st.caption(
        "AI gatekeeper for security reports. Verdicts are advisory; "
        "a human makes the final call."
    )
    audit, scorecard = st.tabs(["Audit", "Scorecard"])
    with audit:
        audit_tab()
    with scorecard:
        scorecard_tab()


if __name__ == "__main__":
    main()
