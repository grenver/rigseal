from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from rigseal import lock as lk
from rigseal import rules, signing
from rigseal.cache import Cache, cache_path
from rigseal.capabilities import enrich
from rigseal.collectors import COLLECTORS
from rigseal.model import CollectError, Finding, Item
from rigseal.signing import SignError

app = typer.Typer(no_args_is_help=True, add_completion=False)
out = Console()
err = Console(stderr=True)

ProjectOpt = Annotated[Path, typer.Option("--project", "-p", help="Project folder to inspect.", exists=True, file_okay=False)]
HomeOpt = Annotated[Path, typer.Option(hidden=True)]
JsonOpt = Annotated[bool, typer.Option("--json", help="Print JSON.")]
RepoOpt = Annotated[bool, typer.Option("--repo", help="Only the repo lock (for CI).")]
KeyOpt = Annotated[Path | None, typer.Option("--key", help="SSH key to sign with (default: $RIGSEAL_SIGNING_KEY, then git user.signingkey).")]
NoSignOpt = Annotated[bool, typer.Option("--no-sign", help="Do not sign.")]
AllowUnsignedOpt = Annotated[bool, typer.Option("--allow-unsigned", help="Allow replacing a signed lock with an unsigned one.")]


@app.callback()
def main() -> None:
    """A lockfile for your AI agent setup."""


def inventory(home: Path, project: Path | None) -> list[Item]:
    items: list[Item] = []
    for collect in COLLECTORS:
        items += collect(home, project)
    cache = Cache(cache_path(home))
    enrich(items, cache)
    cache.save()
    return items


def _fail(message: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {message}")
    return typer.Exit(2)


def _paths(home: Path, project: Path) -> tuple[Path, Path | None]:
    """Resolve paths. The project is None when it is the home folder itself, so user config isn't counted twice."""
    home, project = home.expanduser().resolve(), project.resolve()
    return home, None if project == home else project


@dataclass
class Ctx:
    home: Path
    project: Path | None
    items: list[Item]
    current: lk.Current
    repo: lk.Lock | None
    machine: lk.Lock | None

    @property
    def project_key(self) -> str:
        return str(self.project) if self.project else ""


def load(home: Path, project: Path) -> Ctx:
    home, proj = _paths(home, project)
    try:
        items = inventory(home, proj)
        repo = lk.read_lock(lk.repo_lock_path(proj)) if proj else None
        machine = lk.read_lock(lk.machine_lock_path(home))
    except CollectError as e:
        raise _fail(str(e)) from e
    return Ctx(home, proj, items, lk.split(items, home, proj or home), repo, machine)


def change_findings(ctx: Ctx, found: list[lk.Change]) -> dict[str, list[Finding]]:
    """Findings on added or changed items, plus R1 for any MCP drift, keyed by item key."""
    by_key: dict[str, list[Finding]] = {}
    for f in rules.scan(ctx.items):
        by_key.setdefault(f.key, []).append(f)
    kinds = {k: e["kind"] for part in (ctx.current.repo, ctx.current.machine, ctx.current.local) for k, e in part.items()}
    locked = [ctx.repo.items if ctx.repo else {}] + ([ctx.machine.items, *ctx.machine.projects.values()] if ctx.machine else [])
    for part in locked:
        kinds.update({k: e["kind"] for k, e in part.items() if k not in kinds})
    out: dict[str, list[Finding]] = {}
    for c in found:
        r1 = rules.r1_mcp_drift(c.key, kinds.get(c.key, ""), c.status)
        here = ([r1] if r1 else []) + (by_key.get(c.key, []) if c.status != "removed" else [])
        if here:
            out[c.key] = here
    return out


def changes(ctx: Ctx, repo_only: bool) -> list[lk.Change]:
    """Drift against the locks. A missing repo lock counts as empty, so a fresh clone's MCP servers show as added."""
    result = lk.diff_entries(ctx.repo.items if ctx.repo else {}, ctx.current.repo, "repo")
    if not repo_only:
        if ctx.machine is None:
            raise _fail(f"no machine lock at {lk.machine_lock_path(ctx.home)}. Run `rigseal init` first.")
        result += lk.diff_entries(ctx.machine.items, ctx.current.machine, "machine")
        result += lk.diff_entries(ctx.machine.projects.get(ctx.project_key, {}), ctx.current.local, "machine")
    return result


def signature_problems(ctx: Ctx, repo_only: bool, require: bool) -> list[str]:
    targets = []
    if ctx.repo and ctx.project:
        targets.append((ctx.repo, ctx.project / ".rigseal" / "allowed_signers"))
    if ctx.machine and not repo_only:
        targets.append((ctx.machine, lk.rigseal_dir(ctx.home) / "allowed_signers"))

    problems = []
    for lock, default_signers in targets:
        if not lock.sig_path.exists():
            if lock.signed_by:
                problems.append(f"{lock.path} says it is signed by {lock.signed_by} but {lock.sig_path.name} is missing")
            elif require or default_signers.is_file():  # once signers are set up, unsigned is not ok
                problems.append(f"{lock.path} is not signed")
        elif not lock.signed_by:
            problems.append(f"{lock.path} has a signature but no signedBy")
        else:
            try:
                signing.verify(lock.path, lock.signed_by, signing.allowed_signers_for(default_signers, ctx.project))
            except SignError as e:
                problems.append(str(e))
    return problems


SEV_STYLE = {"high": "red", "medium": "yellow", "low": "dim"}


def finding_line(f: Finding) -> str:
    return f"[{SEV_STYLE[f.severity]}]{f.severity.upper():6}[/] {f.rule:4} {f.message}"


def print_changes(found: list[lk.Change], findings: dict[str, list[Finding]]) -> None:
    marks = {"added": "[green]+[/green]", "removed": "[red]-[/red]", "changed": "[yellow]~[/yellow]"}
    for c in found:
        out.print(f"{marks[c.status]} {c.key}  [dim]({c.lock} lock, {c.status})[/dim]")
        for f in findings.get(c.key, []):
            out.print(f"    {finding_line(f)}")
        if c.status != "changed":
            continue
        for label, files in (("changed", c.files_changed), ("new file", c.files_added), ("gone", c.files_removed)):
            for f in files:
                out.print(f"    {label}: {f}")
        for line in c.capabilities:
            out.print(f"    [bold]{line}[/bold]")
        other = [d for d in c.details_changed if d != "capabilities"]
        if other:
            out.print(f"    details: {', '.join(other)}")


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
def status(project: ProjectOpt = Path("."), as_json: JsonOpt = False, home: HomeOpt = Path.home()) -> None:
    """Show every skill, plugin, hook and MCP server your agents load."""
    home, proj = _paths(home, project)
    try:
        items = inventory(home, proj)
    except CollectError as e:
        raise _fail(str(e)) from e

    if as_json:
        typer.echo(json.dumps([i.to_dict() for i in items], indent=2))
        return

    table = Table(show_lines=False)
    for col in ("agent", "scope", "kind", "name", "files", "hash", "notes"):
        table.add_column(col, overflow="fold")
    for i in items:
        table.add_row(i.agent, i.scope, i.kind, i.name, str(len(i.files)), i.sha256[:12], _notes(i))
    out.print(table)
    typer.echo(f"{len(items)} items")


@app.command()
def diff(project: ProjectOpt = Path("."), repo_only: RepoOpt = False, as_json: JsonOpt = False, home: HomeOpt = Path.home()) -> None:
    """Show what changed since the last approve."""
    ctx = load(home, project)
    found = changes(ctx, repo_only)
    findings = change_findings(ctx, found)
    if as_json:
        typer.echo(json.dumps([{**c.to_dict(), **_findings_json(findings, c.key)} for c in found], indent=2))
    elif found:
        print_changes(found, findings)
    else:
        out.print("no drift")


def _findings_json(findings: dict[str, list[Finding]], key: str) -> dict:
    return {"findings": [f.to_dict() for f in findings[key]]} if key in findings else {}


@app.command()
def check(
    project: ProjectOpt = Path("."),
    repo_only: RepoOpt = False,
    require_signature: Annotated[bool, typer.Option("--require-signature", help="Fail if a lock is unsigned.")] = False,
    as_json: JsonOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Exit 0 if nothing changed and signatures are valid, 1 if not, 2 on error."""
    ctx = load(home, project)
    found = changes(ctx, repo_only)
    findings = change_findings(ctx, found)
    problems = signature_problems(ctx, repo_only, require_signature)
    if as_json:
        changes_json = [{**c.to_dict(), **_findings_json(findings, c.key)} for c in found]
        typer.echo(json.dumps({"changes": changes_json, "signature_problems": problems}, indent=2))
    else:
        for p in problems:
            out.print(f"[red]signature:[/red] {p}")
        print_changes(found, findings)
        out.print(f"{len(found)} change(s), {len(problems)} signature problem(s)" if found or problems else "ok")
    if found or problems:
        raise typer.Exit(1)


def _save(lock: lk.Lock, key: Path | None, signer: str) -> str:
    """Write the lock, then sign it if there is a key. An old signature is removed, since it no longer matches."""
    lock.signed_by = signer if key else None
    lock.write()
    if key is None:
        lock.sig_path.unlink(missing_ok=True)
        return f"wrote {lock.path} [yellow](unsigned)[/yellow]"
    signing.sign(lock.path, key)
    return f"wrote and signed {lock.path}"


def _approve(ctx: Ctx, keys: set[str] | None, key: Path | None) -> list[str]:
    who, when = signing.identity(ctx.project), lk.now()
    notes = []
    if ctx.project and (ctx.repo or ctx.current.repo):
        old = ctx.repo or lk.Lock(lk.repo_lock_path(ctx.project))
        new_items = lk.apply(old.items, ctx.current.repo, keys, who, when)
        if ctx.repo is None or new_items != old.items:
            notes.append(_save(lk.Lock(old.path, new_items), key, who))

    old_m = ctx.machine or lk.Lock(lk.machine_lock_path(ctx.home))
    new_m = lk.apply(old_m.items, ctx.current.machine, keys, who, when)
    projects = dict(old_m.projects)
    if ctx.project:
        projects[ctx.project_key] = lk.apply(projects.get(ctx.project_key, {}), ctx.current.local, keys, who, when)
    if ctx.machine is None or new_m != old_m.items or projects != old_m.projects:
        notes.append(_save(lk.Lock(old_m.path, new_m, projects), key, who))
    return notes


def _interactive() -> bool:
    return sys.stdin.isatty()


def _require_person() -> None:
    """Approving is a human decision. An agent running rigseal through a tool call has no terminal.
    CI and scripts can opt out with RIGSEAL_NONINTERACTIVE=1. See docs/threat-model.md for what this does not stop."""
    if os.environ.get("RIGSEAL_NONINTERACTIVE") == "1":
        return
    if not _interactive():
        raise _fail("approving needs a person at a terminal.")


def _run_approve(ctx: Ctx, keys: set[str] | None, key: Path | None, no_sign: bool, allow_unsigned: bool) -> None:
    sign_key = None if no_sign else signing.signing_key(key, ctx.project)
    signed = [lock for lock in (ctx.repo, ctx.machine) if lock and lock.signed_by]
    if sign_key is None and signed and not allow_unsigned:
        raise _fail(
            f"{signed[0].path} is signed; approving without a key would drop the signature. "
            "Pass --key, or --allow-unsigned if that is what you want."
        )
    try:
        for note in _approve(ctx, keys, sign_key):
            out.print(note)
    except SignError as e:
        raise _fail(str(e)) from e


@app.command()
def init(
    project: ProjectOpt = Path("."),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing locks.")] = False,
    key: KeyOpt = None,
    no_sign: NoSignOpt = False,
    allow_unsigned: AllowUnsignedOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Write the machine lock, and the repo lock if this project has agent config."""
    ctx = load(home, project)
    _require_person()
    existing = [str(lock.path) for lock in (ctx.repo, ctx.machine) if lock]
    if existing and not force:
        raise _fail(f"lock already exists: {', '.join(existing)}. Use `rigseal approve`, or --force.")
    old_repo, old_machine = ctx.repo, ctx.machine
    if (old_repo and old_repo.signed_by) or (old_machine and old_machine.signed_by):
        sign_key = None if no_sign else signing.signing_key(key, ctx.project)
        if sign_key is None and not allow_unsigned:
            raise _fail("the existing lock is signed; --force without a key would drop the signature. Pass --key or --allow-unsigned.")
    ctx.repo = ctx.machine = None
    _run_approve(ctx, None, key, no_sign, allow_unsigned=True)


@app.command()
def approve(
    keys: Annotated[list[str] | None, typer.Argument(help="Item keys to approve (default: all changes).")] = None,
    project: ProjectOpt = Path("."),
    key: KeyOpt = None,
    no_sign: NoSignOpt = False,
    allow_unsigned: AllowUnsignedOpt = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Don't ask; approve what is listed.")] = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Accept the current state into the locks. Shows what you are approving and asks first."""
    _require_person()
    ctx = load(home, project)
    pending = changes(ctx, repo_only=False)
    wanted = set(keys) if keys else None
    if wanted and (unknown := wanted - {c.key for c in pending}):
        raise _fail(f"not a pending change: {', '.join(sorted(unknown))}. See `rigseal diff`.")
    if not pending:
        out.print("nothing to approve")
        return
    if not yes and os.environ.get("RIGSEAL_NONINTERACTIVE") != "1":
        shown = [c for c in pending if wanted is None or c.key in wanted]
        print_changes(shown, change_findings(ctx, shown))
        if not typer.confirm(f"Approve {len(shown)} change(s)?", default=False):
            raise typer.Exit(1)
    _run_approve(ctx, wanted, key, no_sign, allow_unsigned)


@app.command()
def scan(
    project: ProjectOpt = Path("."),
    fail_on: Annotated[str, typer.Option("--fail-on", help="Exit 1 at this severity or worse: high, medium, low, never.")] = "high",
    as_json: JsonOpt = False,
    home: HomeOpt = Path.home(),
) -> None:
    """Run the rules on everything your agents load, approved or not."""
    if fail_on not in (*rules.SEVERITIES, "never"):
        raise _fail("--fail-on must be high, medium, low or never")
    home, proj = _paths(home, project)
    try:
        findings = rules.scan(inventory(home, proj))
    except CollectError as e:
        raise _fail(str(e)) from e
    if as_json:
        typer.echo(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for key in dict.fromkeys(f.key for f in findings):
            out.print(key)
            for f in findings:
                if f.key == key:
                    out.print(f"    {finding_line(f)}")
        counts = {s: sum(f.severity == s for f in findings) for s in rules.SEVERITIES}
        out.print(", ".join(f"{n} {s}" for s, n in counts.items()) if findings else "no findings")
    if fail_on != "never" and any(rules.SEVERITIES.index(f.severity) <= rules.SEVERITIES.index(fail_on) for f in findings):
        raise typer.Exit(1)
