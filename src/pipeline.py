# path: src/pipeline.py

from __future__ import annotations

from typing import Any, Dict, List

import typer
from rich.table import Table

from .types import ModeType, AttackProfileType, StageResult
from .core import run_pipeline, compute_bypass_effect, default_events
from .output import console, pretty_print_result, print_bypass_insights


app = typer.Typer(help="Model-to-model security control pipeline with threat simulation")


@app.command("run")
def cli_run(
    mode: ModeType = typer.Option("normal", "--mode", help="neutral|normal|hardened"),
    attack: AttackProfileType = typer.Option(
        "none",
        "--attack",
        help="Attack profile: none|inline_injection|summary_injection|policy_override",
    ),
) -> None:
    """
    Run the pipeline over the default event set and print rich + JSON output.
    """
    events = default_events()
    results: List[StageResult] = []

    for event in events:
        result = run_pipeline(event, mode=mode, attack_profile=attack)
        results.append(result)
        pretty_print_result(result)

    console.rule("[title]JSON SUMMARY[/title]")
    console.print_json(data=results)


@app.command("compare")
def cli_compare(
    mode: ModeType = typer.Option("normal", "--mode", help="neutral|normal|hardened"),
    attack: AttackProfileType = typer.Option(
        "inline_injection",
        "--attack",
        help=(
            "Attack profile used for the attacked run: "
            "inline_injection|summary_injection|policy_override"
        ),
    ),
) -> None:
    """
    For each event, run:
      - clean:    attack_profile=none
      - attacked: attack_profile=<attack>

    Then compute whether risk or action was downgraded.
    """
    if attack == "none":
        console.print("[red]Attack profile 'none' is not meaningful for compare.[/red]")
        raise typer.Exit(code=1)

    events = default_events()

    table = Table(
        title=f"Prompt Injection Threat Simulation (clean → {attack})",
        box=None,
        show_lines=True,
    )
    table.add_column("Event")
    table.add_column("Risk")
    table.add_column("Action")
    table.add_column("Pattern")
    table.add_column("Bypassed?")

    total = 0
    success = 0
    summary: Dict[str, Any] = {}

    for event in events:
        total += 1

        clean = run_pipeline(event, mode=mode, attack_profile="none")
        attacked_result = run_pipeline(event, mode=mode, attack_profile=attack)

        effect = compute_bypass_effect(clean, attacked_result)

        bypassed = effect["risk_downgraded"] or effect["action_downgraded"]
        if bypassed:
            success += 1

        table.add_row(
            event,
            f"{clean['stage_b_risk']} → {attacked_result['stage_b_risk']}",
            f"{clean['stage_c_action']} → {attacked_result['stage_c_action']}",
            effect["pattern"],
            "[green]YES[/green]" if bypassed else "[red]NO[/red]",
        )

        summary[event] = {
            "clean": clean,
            "attacked": attacked_result,
            "effect": effect,
        }

    console.print(table)
    console.rule()

    bypass_rate = (success / total * 100) if total > 0 else 0.0
    console.print(f"[bold magenta]Bypass Success Rate: {bypass_rate:.2f}%[/bold magenta]")

    print_bypass_insights(summary)

    console.rule("[title]JSON SUMMARY[/title]")
    console.print_json(data=summary)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
