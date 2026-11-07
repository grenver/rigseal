"""Collect everything Claude Code loads: settings, MCP servers, skills, commands, agents, plugins, instructions."""

from __future__ import annotations

from functools import partial
from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item, hash_tree, tree_digest
from rigseal.readers import read_json

AGENT = "claude-code"

# Settings keys that can run code, widen permissions or redirect traffic.
RISKY_SETTINGS_KEYS = (
    "hooks",
    "env",
    "apiKeyHelper",
    "permissions",
    "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
    "extraKnownMarketplaces",
    "enabledPlugins",
    "statusLine",
)

optional_file = partial(common.optional_file, AGENT)
files_matching = partial(common.files_matching, AGENT)
skill_dirs = partial(common.skill_dirs, AGENT)
mcp_items = partial(common.mcp_items, AGENT)


def collect(home: Path, project: Path | None) -> list[Item]:
    items: list[Item] = []
    claude_dir = home / ".claude"

    items += _settings(claude_dir / "settings.json", "user")
    items += optional_file(claude_dir / "CLAUDE.md", "user", "instructions")
    items += _user_mcp(home / ".claude.json", project)
    items += skill_dirs(claude_dir / "skills", "user")
    items += files_matching(claude_dir / "commands", ".md", "command", "user")
    items += files_matching(claude_dir / "agents", ".md", "agent", "user")
    items += _plugins(claude_dir / "plugins" / "installed_plugins.json")

    if project is not None:
        pc = project / ".claude"
        items += _settings(pc / "settings.json", "project")
        items += _settings(pc / "settings.local.json", "local")
        mcp_json = project / ".mcp.json"
        items += mcp_items((read_json(mcp_json) or {}).get("mcpServers"), "project", mcp_json)
        items += skill_dirs(pc / "skills", "project")
        items += files_matching(pc / "commands", ".md", "command", "project")
        items += files_matching(pc / "agents", ".md", "agent", "project")
        for name, scope in (("CLAUDE.md", "project"), ("CLAUDE.local.md", "local"), ("AGENTS.md", "project")):
            items += optional_file(project / name, scope, "instructions")
    return items


def _settings(path: Path, scope: str) -> list[Item]:
    data = read_json(path)
    if data is None:
        return []
    return [common.settings_item(AGENT, path, data, scope, RISKY_SETTINGS_KEYS)]


def _user_mcp(path: Path, project: Path | None) -> list[Item]:
    data = read_json(path)
    if data is None:
        return []
    items = mcp_items(data.get("mcpServers"), "user", path)
    if project is not None:
        proj = (data.get("projects") or {}).get(str(project)) or {}
        items += mcp_items(proj.get("mcpServers"), "local", path)
    return items


def _plugins(path: Path) -> list[Item]:
    data = read_json(path)
    if data is None:
        return []
    items = []
    for name, installs in sorted((data.get("plugins") or {}).items()):
        for inst in installs or []:
            install_path = Path(inst.get("installPath", ""))
            details = {"version": inst.get("version"), "plugin_scope": inst.get("scope")}
            if inst.get("gitCommitSha"):
                details["git_commit"] = inst["gitCommitSha"]
            if install_path.is_dir():
                digest, files = hash_tree(install_path)
            else:
                details["missing"] = True
                files = []
                digest = tree_digest(files)
            items.append(Item(AGENT, "plugin", "plugin", name, str(install_path), digest, files, details))
    return items
