"""Collect what Cursor loads: MCP servers, skills, hooks.json, rules."""

from __future__ import annotations

from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item
from rigseal.readers import read_json

AGENT = "cursor"


def collect(home: Path, project: Path | None) -> list[Item]:
    items: list[Item] = []
    roots = [(home / ".cursor", "user")]
    if project is not None:
        roots.append((project / ".cursor", "project"))

    for root, scope in roots:
        mcp = root / "mcp.json"
        items += common.mcp_items(AGENT, (read_json(mcp) or {}).get("mcpServers"), scope, mcp)
        items += _hooks(root / "hooks.json", scope)
        items += common.skill_dirs(AGENT, root / "skills", scope)
        items += common.files_matching(AGENT, root / "rules", ".mdc", "rule", scope)

    if project is not None:
        items += common.optional_file(AGENT, project / ".cursorrules", "project", "rule")
    return items


def _hooks(path: Path, scope: str) -> list[Item]:
    data = read_json(path)
    if data is None:
        return []
    return [common.settings_item(AGENT, path, data, scope, ("hooks",))]
