"""Data models for ProofGate (skeleton, dataclasses only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ClaimKind = Literal[
    "symbol_exists",
    "location",
    "version_affected",
    "code_property",
    "data_flow",
    "reproducible_impact",
]

CheckMethod = Literal["static", "test"]

EvidenceStatus = Literal["supported", "refuted", "unverifiable"]

VerdictLabel = Literal[
    "fabricated", "claim_false", "partially_true", "confirmed", "inconclusive"
]


@dataclass
class Claim:
    """One atomic factual claim extracted from a vulnerability report."""

    id: str
    kind: ClaimKind
    statement: str  # Plain English.
    target: dict  # Keys: file, symbol, version, line hints.
    check_method: CheckMethod


@dataclass
class Evidence:
    """Result of checking a single claim against the source."""

    claim_id: str
    status: EvidenceStatus
    summary: str
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None  # Max 15 lines.
    test_log: str | None = None

    def __post_init__(self) -> None:
        if self.snippet is not None and len(self.snippet.splitlines()) > 15:
            raise ValueError("snippet must be at most 15 lines")


@dataclass
class Verdict:
    """Final audit verdict with supporting evidence."""

    label: VerdictLabel
    evidence_level: int  # 0-5, see DESIGN.md evidence ladder.
    rationale: str
    per_claim: list[Evidence] = field(default_factory=list)
    minutes_saved_estimate: float = 0.0

    def __post_init__(self) -> None:
        if not 0 <= self.evidence_level <= 5:
            raise ValueError("evidence_level must be between 0 and 5")
