# path: src/types.py

from __future__ import annotations

from typing import Literal, Optional, TypedDict


ModeType = Literal["neutral", "normal", "hardened"]

AttackProfileType = Literal[
    "none",
    "inline_injection",
    "summary_injection",
    "policy_override",
]

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ActionType = Literal["IGNORE", "MONITOR", "ALERT", "ESCALATE"]


class StageResult(TypedDict):
    """Structured output for a single pipeline run for one event."""
    raw_input: str
    attacked_input: str
    mode: ModeType
    attack_profile: AttackProfileType
    stage_a_summary: str
    stage_b_raw: str
    stage_b_risk: Optional[RiskLevel]
    stage_c_raw: str
    stage_c_action: Optional[ActionType]


class BypassEffect(TypedDict):
    """Comparison metrics between a clean and attacked run."""
    risk_downgraded: bool
    action_downgraded: bool
    risk_delta: int
    action_delta: int
    pattern: str
    insight: str


class AttackContext(TypedDict):
    """
    Intermediate values describing how an attack profile shapes the pipeline.
    This keeps all attacker behavior in a single place.
    """
    stage_a_input: str
    summary_for_b: str
    policy_override: str | None
    attacked_input: str
