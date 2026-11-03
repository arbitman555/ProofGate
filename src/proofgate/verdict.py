"""Verdict engine: aggregate per-claim evidence into a final verdict.

The judge model (``muse-wonder-1.0``, falling back to ``muse-spark-1.3``
via :meth:`LLMClient.judge`) sees only the extracted claims and the
gathered evidence -- never the original report prose. Deterministic hard
rules in this module are applied AFTER the model reply and override it:

- any ``symbol_exists`` claim refuted with no close match caps the label
  at ``"fabricated"``;
- a passing reproduction test raises ``evidence_level`` to at least 3;
- when no claim is supported, the label can never be ``"confirmed"``.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any

from .llm import JUDGE_MODEL, LLMClient
from .models import Claim, Evidence, Verdict

VALID_LABELS = frozenset(
    {"fabricated", "claim_false", "partially_true", "confirmed", "inconclusive"}
)

#: Labels that imply the report wasted triage time (higher time savings).
DISMISSED_LABELS = frozenset({"fabricated", "claim_false"})

MINUTES_SAVED_DISMISSED = 45
MINUTES_SAVED_OTHER = 20

JUDGE_SYSTEM_PROMPT = """You judge a vulnerability report from its verified claims and evidence.

You receive JSON with two lists: "claims" (atomic factual claims with ids
like c1, c2) and "evidence" (one result per claim: supported, refuted, or
unverifiable, with a summary and file/line citations). Judge ONLY what is
in front of you.

Labels:
- fabricated: the report invents code that does not exist (a symbol_exists
  claim was refuted with no close match).
- claim_false: the code exists but the claimed property/behavior is wrong.
- partially_true: some claims hold while others were refuted.
- confirmed: the key claims are supported by evidence.
- inconclusive: the evidence does not settle the matter.

Evidence level (0-5): 0 nothing verified, 1 code exists as described,
2 behavior observed in code, 3 reproduced by test, 4 security boundary
crossed, 5 independently reproducible.

Output ONLY a JSON object of the form:
{"label": "<one of fabricated, claim_false, partially_true, confirmed, inconclusive>",
 "evidence_level": <int 0-5>,
 "rationale": "<2-3 sentences citing claim ids like c1, c2>"}
No prose, no markdown fences."""


def _response_text(response: Any) -> str:
    """Pull plain text out of a Responses API response, a fake, or a string."""
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    data = getattr(response, "data", None)
    if isinstance(data, str):
        return data
    text_attr = getattr(response, "text", None)
    if isinstance(text_attr, str):
        return text_attr
    return str(response)


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _parse_judge_reply(text: str) -> tuple[str, int, str]:
    """Parse and validate one judge reply. Raises ValueError if invalid."""
    try:
        payload = json.loads(_strip_fences(text))
    except json.JSONDecodeError as exc:
        raise ValueError(f"judge did not return valid JSON: {exc}") from exc
    if isinstance(payload, dict) and isinstance(payload.get("verdict"), dict):
        payload = payload["verdict"]
    if not isinstance(payload, dict):
        raise ValueError(
            "judge reply must be a JSON object with label, "
            f"evidence_level, and rationale; got: {type(payload).__name__}"
        )
    label = payload.get("label")
    if label not in VALID_LABELS:
        raise ValueError(
            f"judge returned invalid label {label!r}; "
            f"expected one of {sorted(VALID_LABELS)}"
        )
    try:
        level = int(payload.get("evidence_level"))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "judge 'evidence_level' must be an int 0-5, "
            f"got: {payload.get('evidence_level')!r}"
        ) from exc
    if not 0 <= level <= 5:
        raise ValueError(f"judge 'evidence_level' out of range: {level}")
    rationale = payload.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("judge 'rationale' must be a non-empty string")
    return label, level, rationale.strip()


def _mentions_close_match(summary: str) -> bool:
    """True when the summary reports a close (renamed/misspelled) match."""
    low = summary.lower()
    has = "close match" in low or "close_match" in low
    negated = (
        "no close match" in low
        or "without close match" in low
        or "no close_match" in low
        or "without a close match" in low
    )
    return has and not negated


def _passing_repro_test(
    claims: list[Claim], evidence: list[Evidence]
) -> Evidence | None:
    """Return the evidence behind a passing repro test, if any."""
    by_id = {c.id: c for c in claims}
    for ev in evidence:
        if ev.status != "supported":
            continue
        claim = by_id.get(ev.claim_id)
        from_test_claim = claim is not None and (
            claim.kind == "reproducible_impact" or claim.check_method == "test"
        )
        log_says_pass = ev.test_log is not None and "outcome: PASS" in ev.test_log
        if from_test_claim or log_says_pass:
            return ev
    return None


def _apply_hard_rules(
    label: str,
    level: int,
    claims: list[Claim],
    evidence: list[Evidence],
) -> tuple[str, int, list[str]]:
    """Apply post-model overrides. Returns (label, level, notes)."""
    notes: list[str] = []
    by_evidence = {e.claim_id: e for e in evidence}

    # Rule 1: a refuted symbol_exists claim with no close match means the
    # report invents code -- the verdict can be at most "fabricated".
    for claim in claims:
        if claim.kind != "symbol_exists":
            continue
        ev = by_evidence.get(claim.id)
        if (
            ev is not None
            and ev.status == "refuted"
            and not _mentions_close_match(ev.summary)
        ):
            if label != "fabricated":
                label = "fabricated"
                notes.append(
                    f"Hard rule applied: claim {claim.id} "
                    f"({claim.target.get('symbol', '?')}) was refuted with "
                    "no close match, so the verdict is capped at "
                    "'fabricated'."
                )
            break

    # Rule 2: a passing reproduction test proves behavior -- level >= 3.
    passing = _passing_repro_test(claims, evidence)
    if passing is not None and level < 3:
        level = 3
        notes.append(
            f"Hard rule applied: reproduction test for claim "
            f"{passing.claim_id} passed, so evidence_level is at least 3."
        )

    # Rule 3: with nothing supported, the report cannot be "confirmed".
    if label == "confirmed" and not any(e.status == "supported" for e in evidence):
        label = "inconclusive"
        notes.append(
            "Hard rule applied: no claim was supported, so the verdict "
            "cannot be 'confirmed'; left 'inconclusive'."
        )

    level = max(0, min(5, int(level)))
    return label, level, notes


def _heuristic_verdict(
    claims: list[Claim], evidence: list[Evidence]
) -> tuple[str, int, str]:
    """Deterministic fallback when the judge model cannot be reached."""
    ids = ", ".join(c.id for c in claims) or "no claims"
    by_evidence = {e.claim_id: e for e in evidence}
    statuses = [e.status for e in evidence]
    n_supported = sum(s == "supported" for s in statuses)
    n_refuted = sum(s == "refuted" for s in statuses)

    invented = any(
        c.kind == "symbol_exists"
        and (ev := by_evidence.get(c.id)) is not None
        and ev.status == "refuted"
        and not _mentions_close_match(ev.summary)
        for c in claims
    )
    if invented:
        return (
            "fabricated",
            0,
            f"A claimed symbol does not exist in the code ({ids}). "
            f"The report describes code that is not there.",
        )
    if n_supported and n_refuted:
        return (
            "partially_true",
            1,
            f"Some claims held while others did not ({ids}). "
            f"The report is only partly accurate.",
        )
    if n_supported and not n_refuted:
        return (
            "confirmed",
            2,
            f"The claims were supported by the code ({ids}). "
            f"The report matches what was found.",
        )
    if n_refuted and not n_supported:
        return (
            "claim_false",
            1,
            f"The code exists but the claims about it did not hold ({ids}). "
            f"The report's conclusions are wrong.",
        )
    return (
        "inconclusive",
        0,
        f"Nothing could be verified either way ({ids}). "
        f"There is not enough evidence to judge the report.",
    )


def _call_judge(client: Any, prompt: str) -> Any:
    """Call the judge model, tolerating minimal fake clients in tests."""
    kwargs: dict[str, Any] = {
        "instructions": JUDGE_SYSTEM_PROMPT,
        "text": {"format": {"type": "json_object"}},
    }
    judge_fn = getattr(client, "judge", None)
    try:
        if callable(judge_fn):
            return judge_fn(prompt, **kwargs)
        return client.generate(prompt, model=JUDGE_MODEL, **kwargs)
    except TypeError:
        if callable(judge_fn):
            return judge_fn(prompt)
        return client.generate(prompt)


def decide_verdict(
    claims: list[Claim],
    evidence: list[Evidence],
    client: LLMClient | Any | None = None,
) -> Verdict:
    """Aggregate per-claim evidence into a final :class:`Verdict`.

    The judge model sees only the claims and evidence (never the original
    report prose) and returns a label, an evidence level, and a rationale.
    Hard rules are then applied in Python and override the model.

    Args:
        claims: Atomic claims extracted from the report.
        evidence: One :class:`Evidence` per claim, in any order.
        client: Optional ``LLMClient`` (tests inject a mock). When omitted
            a default client is created, which requires ``MODEL_API_KEY``.

    Returns:
        A :class:`Verdict` with label, evidence level, rationale,
        per-claim evidence, and a minutes-saved estimate.
    """
    llm = client if client is not None else LLMClient()
    payload = {
        "claims": [dataclasses.asdict(c) for c in claims],
        "evidence": [dataclasses.asdict(e) for e in evidence],
    }
    user_prompt = (
        "Judge this vulnerability report from its verified claims and "
        "evidence only. No report prose is provided; use just the JSON below.\n"
        f"{json.dumps(payload, indent=2)}\n"
        "Reply with ONLY the JSON verdict object: label, evidence_level, "
        "and a 2-3 sentence rationale citing claim ids."
    )

    label: str | None = None
    level = 0
    rationale = ""
    last_error: ValueError | Exception | None = None
    for _ in (1, 2):
        try:
            response = _call_judge(llm, user_prompt)
            label, level, rationale = _parse_judge_reply(_response_text(response))
            last_error = None
            break
        except ValueError as exc:
            last_error = exc
        except Exception as exc:  # model/transport error: deterministic fallback
            last_error = exc
            break
    if label is None:
        if last_error is not None and not isinstance(last_error, ValueError):
            pass  # transport error: go straight to the heuristic fallback
        label, level, rationale = _heuristic_verdict(claims, evidence)

    label, level, notes = _apply_hard_rules(label, level, claims, evidence)

    if not re.search(r"c\d+", rationale):
        ids = ", ".join(c.id for c in claims)
        rationale = f"{rationale.rstrip()} Claims considered: {ids}.".strip()
    for note in notes:
        rationale = f"{rationale.rstrip()} [{note}]".strip()

    minutes = (
        MINUTES_SAVED_DISMISSED if label in DISMISSED_LABELS else MINUTES_SAVED_OTHER
    )
    rationale = (
        f"{rationale.rstrip()} Manual triage of this report would take about "
        f"{minutes} minutes (estimate)."
    )

    return Verdict(
        label=label,  # type: ignore[arg-type]
        evidence_level=level,
        rationale=rationale,
        per_claim=list(evidence),
        minutes_saved_estimate=float(minutes),
    )
