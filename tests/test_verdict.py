"""Tests for the verdict engine (mocked judge; no network)."""

from __future__ import annotations

import json

from proofgate.models import Claim, Evidence
from proofgate.verdict import decide_verdict


class FakeJudge:
    """Stand-in for LLMClient.judge: replays one canned reply."""

    def __init__(self, reply: str):
        self.reply = reply
        self.prompts: list[str] = []

    def judge(self, prompt: str, **kwargs):
        self.prompts.append(prompt)
        return self.reply

    def generate(self, prompt: str, **kwargs):  # fallback path
        self.prompts.append(prompt)
        return self.reply


class FakeGenerateOnly:
    """Minimal fake exposing only generate(), like the claims fakes."""

    def __init__(self, reply: str):
        self.reply = reply
        self.prompts: list[str] = []

    def generate(self, prompt: str, **kwargs):
        self.prompts.append(prompt)
        return self.reply


def _claim(cid="c1", kind="symbol_exists", symbol="verify_jwt_signature"):
    return Claim(
        id=cid,
        kind=kind,
        statement=f"Statement for {cid}.",
        target={"file": "app.py", "symbol": symbol},
        check_method="test" if kind == "reproducible_impact" else "static",
    )


def _evidence(cid="c1", status="refuted", summary="Missing; no close match found."):
    return Evidence(claim_id=cid, status=status, summary=summary)


def _reply(label, level=2, rationale="Rationale citing c1."):
    return json.dumps({"label": label, "evidence_level": level, "rationale": rationale})


def test_refuted_symbol_without_close_match_caps_at_fabricated():
    verdict = decide_verdict(
        [_claim()], [_evidence()], client=FakeJudge(_reply("confirmed", level=4))
    )
    assert verdict.label == "fabricated"
    assert verdict.minutes_saved_estimate == 45.0
    assert "c1" in verdict.rationale


def test_close_match_mentioned_leaves_model_label():
    verdict = decide_verdict(
        [_claim()],
        [_evidence(summary="Close match verify_jwt_signatures in app.py line 44.")],
        client=FakeJudge(_reply("claim_false", level=1)),
    )
    assert verdict.label == "claim_false"
    assert verdict.minutes_saved_estimate == 45.0


def test_passing_repro_test_raises_level_to_three():
    verdict = decide_verdict(
        [_claim("c1", kind="reproducible_impact")],
        [
            Evidence(
                claim_id="c1",
                status="supported",
                summary="Reproduced.",
                test_log="# outcome: PASS in 1.2s",
            )
        ],
        client=FakeJudge(_reply("partially_true", level=1)),
    )
    assert verdict.label == "partially_true"
    assert verdict.evidence_level == 3
    assert verdict.minutes_saved_estimate == 20.0


def test_no_supported_claim_never_confirmed():
    verdict = decide_verdict(
        [_claim("c1", kind="code_property")],
        [_evidence(status="unverifiable", summary="Could not verify c1.")],
        client=FakeJudge(_reply("confirmed", level=2)),
    )
    assert verdict.label == "inconclusive"


def test_judge_sees_claims_not_report_prose():
    # decide_verdict only receives claims+evidence, so the judge prompt is
    # built from those alone -- the raw report prose is never an input.
    client = FakeJudge(_reply("confirmed", level=2, rationale="c1 is supported."))
    decide_verdict(
        [_claim()],
        [_evidence(status="supported", summary="Found at app.py line 44.")],
        client=client,
    )
    assert len(client.prompts) == 1
    prompt = client.prompts[0]
    payload = json.loads(prompt[prompt.index("{") : prompt.rindex("}") + 1])
    assert set(payload) == {"claims", "evidence"}  # nothing else is sent
    assert payload["claims"][0]["id"] == "c1"
    assert payload["evidence"][0]["status"] == "supported"


def test_generate_only_client_works():
    verdict = decide_verdict(
        [_claim()],
        [_evidence(status="supported", summary="Found at app.py line 44.")],
        client=FakeGenerateOnly(_reply("confirmed", level=2)),
    )
    assert verdict.label == "confirmed"


def test_estimate_is_labeled_in_rationale():
    verdict = decide_verdict(
        [_claim()],
        [_evidence()],
        client=FakeJudge(_reply("fabricated", level=0)),
    )
    assert "(estimate)" in verdict.rationale
