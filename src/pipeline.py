# src/pipeline.py

from __future__ import annotations

import json
import re
from typing import Dict, List, Literal, Optional, TypedDict

from .models_client import ModelClient

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ActionType = Literal["IGNORE", "MONITOR", "ALERT", "ESCALATE"]


class StageResult(TypedDict):
    raw_input: str
    stage_a_summary: str
    stage_b_raw: str
    stage_b_risk: Optional[RiskLevel]
    stage_c_raw: str
    stage_c_action: Optional[ActionType]


_CLIENT = ModelClient()


def _build_stage_a_prompt(raw_event: str) -> str:
    """
    Build the prompt for Model A (summary / interpretation).

    Goal:
    - Normalize the raw event into a clear security-relevant summary.
    """
    return (
        "You are Model A in a security control pipeline.\n"
        "Your job is to normalize a raw event description into a short\n"
        "security-relevant summary.\n\n"
        "Requirements:\n"
        "- Use 1–3 sentences.\n"
        "- Focus on the security-relevant behavior (who did what, on what asset).\n"
        "- Do NOT classify risk or suggest actions.\n\n"
        f"Raw event:\n{raw_event}\n\n"
        "Return only the summary. No headings, no markdown."
    )


def _build_stage_b_prompt(summary: str) -> str:
    """
    Build the prompt for Model B (classification / risk scoring).

    Goal:
    - Map the summary to a discrete risk level.
    - Provide a short human-readable rationale.
    """
    return (
        "You are Model B in a security risk classification pipeline.\n"
        "You receive a normalized security summary from Model A.\n"
        "Your task is to assign a discrete risk level and explain why.\n\n"
        "Valid risk levels:\n"
        "- LOW\n"
        "- MEDIUM\n"
        "- HIGH\n"
        "- CRITICAL\n\n"
        "Formatting rules (must follow exactly):\n"
        "RISK_LEVEL: <one of LOW|MEDIUM|HIGH|CRITICAL>\n"
        "RATIONALE: <one short paragraph>\n\n"
        "Do not add any other sections, bullets, or markdown.\n\n"
        f"Summary from Model A:\n{summary}\n\n"
        "Now respond in the required format."
    )


def _build_stage_c_prompt(summary: str, risk_level: Optional[RiskLevel]) -> str:
    """
    Build the prompt for Model C (decision / action suggestion).

    Goal:
    - Convert the risk level and summary to a concrete action.
    """
    risk_hint = risk_level if risk_level else "UNKNOWN"

    return (
        "You are Model C in a security decision pipeline.\n"
        "You receive the risk classification from Model B and must suggest\n"
        "a concrete operational decision.\n\n"
        "Valid actions:\n"
        "- IGNORE   (no follow-up, log only)\n"
        "- MONITOR  (watch more closely, no immediate ticket)\n"
        "- ALERT    (open an alert / incident for investigation)\n"
        "- ESCALATE (immediate high-priority incident / response)\n\n"
        "Formatting rules (must follow exactly):\n"
        "ACTION: <one of IGNORE|MONITOR|ALERT|ESCALATE>\n"
        "RATIONALE: <one short paragraph focused on why this action>\n\n"
        "Do not add any other sections, bullets, or markdown.\n\n"
        f"Summary from Model A:\n{summary}\n"
        f"Risk level from Model B (may be approximate): {risk_hint}\n\n"
        "Now respond in the required format."
    )


def _extract_risk_level(text: str) -> Optional[RiskLevel]:
    """
    Extract the risk level token from Model B output.

    We expect a line like:
    RISK_LEVEL: MEDIUM
    """
    pattern = r"RISK_LEVEL\s*:\s*(LOW|MEDIUM|HIGH|CRITICAL)"
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).upper()
    # Type narrowing
    if value in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return value  # type: ignore[return-value]
    return None


def _extract_action(text: str) -> Optional[ActionType]:
    """
    Extract the action token from Model C output.

    We expect a line like:
    ACTION: ALERT
    """
    pattern = r"ACTION\s*:\s*(IGNORE|MONITOR|ALERT|ESCALATE)"
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).upper()
    # Type narrowing
    if value in ("IGNORE", "MONITOR", "ALERT", "ESCALATE"):
        return value  # type: ignore[return-value]
    return None


def run_pipeline(raw_event: str) -> StageResult:
    """
    Run the 3-stage model-to-model pipeline for a single event.

    Returns a structured StageResult that can be logged or analyzed later.
    """
    # Stage A: summary / interpretation
    stage_a_prompt = _build_stage_a_prompt(raw_event)
    stage_a_output = _CLIENT.call_model_a(stage_a_prompt)

    # Stage B: classification / risk scoring
    stage_b_prompt = _build_stage_b_prompt(stage_a_output)
    stage_b_output = _CLIENT.call_model_b(stage_b_prompt)
    risk_level = _extract_risk_level(stage_b_output)

    # Stage C: decision / action suggestion
    stage_c_prompt = _build_stage_c_prompt(stage_a_output, risk_level)
    stage_c_output = _CLIENT.call_model_c(stage_c_prompt)
    action = _extract_action(stage_c_output)

    return {
        "raw_input": raw_event,
        "stage_a_summary": stage_a_output.strip(),
        "stage_b_raw": stage_b_output.strip(),
        "stage_b_risk": risk_level,
        "stage_c_raw": stage_c_output.strip(),
        "stage_c_action": action,
    }


def pretty_print_result(result: StageResult) -> None:
    """
    Print a human-readable view of the pipeline result.
    """
    print("-" * 80)
    print("RAW INPUT:")
    print(result["raw_input"])
    print("-" * 80)
    print("STAGE A - SUMMARY / INTERPRETATION:")
    print(result["stage_a_summary"])
    print("-" * 80)
    print("STAGE B - CLASSIFICATION / RISK SCORING:")
    print(result["stage_b_raw"])
    print(f"[PARSED RISK_LEVEL] -> {result['stage_b_risk']}")
    print("-" * 80)
    print("STAGE C - FINAL DECISION:")
    print(result["stage_c_raw"])
    print(f"[PARSED ACTION] -> {result['stage_c_action']}")
    print("-" * 80)
    print()  # Blank line between entries


def _default_scenarios() -> List[str]:
    """
    Provide a small set of default events for quick local testing.

    You can later replace this with real logs or synthetic corp events.
    """
    return [
        "Employee plugs an unknown USB drive into a workstation.",
        "Night shift analyst ignores an automated phishing alert.",
        "Contractor requests temporary admin access for a software update.",
    ]


def main() -> None:
    """
    Entry point for `python -m src.pipeline`.

    For now, we just run the pipeline over a few test scenarios and
    print both the human-readable view and a JSON summary.
    """
    scenarios = _default_scenarios()
    all_results: List[StageResult] = []

    for entry in scenarios:
        result = run_pipeline(entry)
        pretty_print_result(result)
        all_results.append(result)

    # Also dump structured results as JSON (to stdout for now).
    print("=== JSON SUMMARY (for tooling / future analysis) ===")
    print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
