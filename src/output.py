# path: src/reporting.py

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from .types import StageResult, RiskLevel, ActionType, BypassEffect


theme = Theme(
    {
        "title": "bold magenta",
        "section": "bold cyan",
        "risk.low": "green",
        "risk.medium": "yellow",
        "risk.high": "red",
        "risk.critical": "bold red",
        "action.IGNORE": "dim",
        "action.MONITOR": "cyan",
        "action.ALERT": "bold yellow",
        "action.ESCALATE": "bold red",
    }
)

console = Console(theme=theme)


def _risk_style(level: Optional[RiskLevel]) -> str:
    if not level:
        return ""
    return {
        "LOW": "risk.low",
        "MEDIUM": "risk.medium",
        "HIGH": "risk.high",
        "CRITICAL": "risk.critical",
    }.get(level, "")


def _action_style(action: Optional[ActionType]) -> str:
    if not action:
        return ""
    return {
        "IGNORE": "action.IGNORE",
        "MONITOR": "action.MONITOR",
        "ALERT": "action.ALERT",
        "ESCALATE": "action.ESCALATE",
    }.get(action, "")


def pretty_print_result(result: StageResult) -> None:
    """
    Pretty-print a single StageResult with Rich.
    """
    console.rule(
        f"[title] MODE={result['mode']} | ATTACK={result['attack_profile']} [/title]"
    )

    console.print(
        Panel.fit(
            result["raw_input"],
            title="[section]RAW INPUT (clean)[/section]",
            border_style="cyan",
        )
    )

    if result["attack_profile"] != "none":
        console.print(
            Panel.fit(
                escape(result["attacked_input"]),
                title="[section]FIRST ATTACKED INPUT[/section]",
                border_style="red",
            )
        )

    console.print(
        Panel.fit(
            result["stage_a_summary"],
            title="[section]STAGE A (summary)[/section]",
            border_style="magenta",
        )
    )

    table_b = Table(show_header=False, box=None)
    table_b.add_row("Raw:", result["stage_b_raw"])
    if result["stage_b_risk"]:
        table_b.add_row(
            "Parsed:",
            f"[{_risk_style(result['stage_b_risk'])}]{result['stage_b_risk']}[/]",
        )
    else:
        table_b.add_row("Parsed:", "None")

    console.print(
        Panel.fit(
            table_b,
            title="[section]STAGE B (classification)[/section]",
            border_style="yellow",
        )
    )

    table_c = Table(show_header=False, box=None)
    table_c.add_row("Raw:", result["stage_c_raw"])
    if result["stage_c_action"]:
        table_c.add_row(
            "Parsed:",
            f"[{_action_style(result['stage_c_action'])}]{result['stage_c_action']}[/]",
        )
    else:
        table_c.add_row("Parsed:", "None")

    console.print(
        Panel.fit(
            table_c,
            title="[section]STAGE C (decision)[/section]",
            border_style="green",
        )
    )


def print_bypass_insights(summary: dict[str, dict[str, object]]) -> None:
    """
    Print per-event bypass insights in a readable way.
    """
    console.rule("[title]INSIGHTS[/title]")
    for event, data in summary.items():
        effect = data["effect"]  # type: ignore[assignment]
        assert isinstance(effect, dict)
        console.print(f"[bold]{event}[/bold]")
        console.print(f"Pattern: {effect['pattern']}")
        console.print(f"Insight: {effect['insight']}\n")
