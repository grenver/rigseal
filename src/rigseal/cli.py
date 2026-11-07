from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from rigseal.collectors import COLLECTORS
from rigseal.model import CollectError, Item

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def main() -> None:
    """A lockfile for your AI agent setup."""


def inventory(home: Path, project: Path | None) -> list[Item]:
    items: list[Item] = []
    for collect in COLLECTORS:
        items += collect(home, project)
    return items


def _notes(item: Item) -> str:
    d = item.details
    parts = []
    if d.get("risky_keys"):
        parts.append("risky: " + ", ".join(d["risky_keys"]))
    if d.get("transport"):
        parts.append(d["transport"] + (f" {d['command']}" if d.get("command") else "") + (f" {d['host']}" if d.get("host") else ""))
    if d.get("env_keys"):
        parts.append("env: " + ", ".join(d["env_keys"]))
    if d.get("version"):
        parts.append(f"v{d['version']}")
    if d.get("link"):
        parts.append(f"-> {d['link']}")
    if d.get("enabled") is False:
        parts.append("disabled")
    if d.get("missing"):
        parts.append("install folder missing")
    if item.kind == "skill" and not d.get("has_skill_md"):
        parts.append("no SKILL.md")
    return "; ".join(parts)


@app.command()
def status(
    project: Annotated[Path, typer.Option("--project", "-p", help="Project folder to inspect.")] = Path("."),
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
    home: Annotated[Path, typer.Option(hidden=True)] = Path.home(),
) -> None:
    """Show every skill, plugin, hook and MCP server your agents load."""
    try:
        items = inventory(home, project.resolve())
    except CollectError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from e

    if as_json:
        typer.echo(json.dumps([i.to_dict() for i in items], indent=2))
        return

    table = Table(show_lines=False)
    for col in ("agent", "scope", "kind", "name", "files", "hash", "notes"):
        table.add_column(col, overflow="fold")
    for i in items:
        table.add_row(i.agent, i.scope, i.kind, i.name, str(len(i.files)), i.sha256[:12], _notes(i))
    Console().print(table)
    typer.echo(f"{len(items)} items")
