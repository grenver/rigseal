"""Add rigseal's hooks to the user's agent config. Only appends: existing settings and hooks are kept."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from rigseal.model import CollectError
from rigseal.readers import read_json

CLAUDE_COMMAND = "rigseal hook claude-code"
CURSOR_COMMAND = "rigseal hook cursor"


def _claude(matcher: str) -> dict:
    return {"matcher": matcher, "hooks": [{"type": "command", "command": CLAUDE_COMMAND, "timeout": 30}]}


@dataclass
class Target:
    agent: str
    path: Path
    command: str
    wanted: dict[str, dict]  # event -> the entry to add
    base: dict  # what a new file starts with


def targets(home: Path) -> list[Target]:
    """One target per agent that is installed, which means its folder exists."""
    found = []
    if (home / ".claude").is_dir():
        wanted = {
            "SessionStart": _claude("startup|resume"),
            "PreToolUse": _claude("mcp__.*"),
            "ConfigChange": _claude("user_settings|project_settings|local_settings|skills"),
        }
        found.append(Target("claude-code", home / ".claude" / "settings.json", CLAUDE_COMMAND, wanted, {}))
    if (home / ".cursor").is_dir():
        wanted = {"sessionStart": {"command": CURSOR_COMMAND}, "beforeMCPExecution": {"command": CURSOR_COMMAND, "failClosed": True}}
        found.append(Target("cursor", home / ".cursor" / "hooks.json", CURSOR_COMMAND, wanted, {"version": 1}))
    return found


def _read(target: Target) -> dict:
    doc = read_json(target.path)
    if doc is None:
        return dict(target.base)
    try:
        json.loads(target.path.read_text().strip() or "{}")
    except ValueError as e:  # read_json accepts comments, but writing the file back would lose them
        raise CollectError(f"{target.path} has comments or trailing commas, so rigseal won't rewrite it. Add the hooks by hand (see the README).") from e
    hooks = doc.get("hooks", {})
    if not isinstance(hooks, dict) or not all(isinstance(v, list) for v in hooks.values()):
        raise CollectError(f"{target.path}: `hooks` is not in the expected format, so rigseal won't rewrite it.")
    return doc


def _has(entries: list, command: str) -> bool:
    commands = []
    for e in entries:
        if isinstance(e, dict):
            nested = e.get("hooks")
            commands += [h.get("command") for h in (nested if isinstance(nested, list) else [e]) if isinstance(h, dict)]
    return any(isinstance(c, str) and c.endswith(command) for c in commands)


def missing(target: Target) -> list[str]:
    """Events that don't call rigseal yet. Raises CollectError if the file can't be safely rewritten."""
    hooks = _read(target).get("hooks", {})
    return [event for event in target.wanted if not _has(hooks.get(event, []), target.command)]


def add(target: Target) -> None:
    doc = _read(target)
    hooks = doc.setdefault("hooks", {})
    for event in missing(target):
        hooks.setdefault(event, []).append(target.wanted[event])
    _write(target.path, doc)


def _write(path: Path, doc: dict) -> None:
    path = path.resolve()  # a symlink into a dotfiles repo stays a symlink
    tmp = path.with_name(path.name + ".rigseal-tmp")
    try:
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        if path.exists():
            shutil.copymode(path, tmp)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
