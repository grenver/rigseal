"""Collect everything Claude Code loads: settings, MCP servers, skills, commands, agents, plugins, instructions."""

from __future__ import annotations

from functools import partial
from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item, tree_digest
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

# Session bookkeeping inside synced plugins (one file per running session). Not part of the plugin.
SYNCED_PLUGIN_IGNORE = frozenset({".in_use"})

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
    items += skill_dirs(claude_dir / "skills", "user", skip=("synced",))
    items += _synced_skills(claude_dir / "skills" / "synced")
    items += files_matching(claude_dir / "commands", ".md", "command", "user")
    items += files_matching(claude_dir / "agents", ".md", "agent", "user")
    items += _plugins(claude_dir / "plugins" / "installed_plugins.json")
    items += _synced_plugins(claude_dir / "plugins" / "synced")

    if project is not None:
        pc = project / ".claude"
        items += _settings(pc / "settings.json", "project")
        items += _settings(pc / "settings.local.json", "local")
        mcp_json = project / ".mcp.json"
        items += mcp_items((read_json(mcp_json) or {}).get("mcpServers"), "project", mcp_json)
        items += skill_dirs(pc / "skills", "project", within=project)
        items += files_matching(pc / "commands", ".md", "command", "project", within=project)
        items += files_matching(pc / "agents", ".md", "agent", "project", within=project)
        for name, scope in (("CLAUDE.md", "project"), ("CLAUDE.local.md", "local"), ("AGENTS.md", "project")):
            items += optional_file(project / name, scope, "instructions", within=project)
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
                items.append(common.tree_item(AGENT, install_path, "plugin", "plugin", name, details))
                items += common.plugin_mcp(AGENT, install_path, name.split("@")[0])
            else:
                details["missing"] = True
                items.append(Item(AGENT, "plugin", "plugin", name, str(install_path), tree_digest([]), [], details))
    return items


def _synced_plugins(root: Path) -> list[Item]:
    """Plugins synced from claude.ai: synced/<account>/<plugin>[~<marketplace>]/ with a .claude-plugin folder."""
    if not root.is_dir():
        return []
    items = []
    for account in sorted(p for p in root.iterdir() if p.is_dir()):
        for d in sorted(p for p in account.iterdir() if (p / ".claude-plugin").is_dir()):
            manifest = read_json(d / ".claude-plugin" / "plugin.json") or {}
            name = str(manifest.get("name") or d.name.split("~")[0])
            items.append(common.tree_item(AGENT, d, "plugin", "plugin", name, {"source": "synced"}, SYNCED_PLUGIN_IGNORE))
            items += common.plugin_mcp(AGENT, d, name)
    return items


def _synced_skills(root: Path) -> list[Item]:
    """Skills synced from claude.ai: synced/<account>/<skill>/SKILL.md."""
    if not root.is_dir():
        return []
    items = []
    for account in sorted(p for p in root.iterdir() if p.is_dir()):
        items += [common.skill_item(AGENT, d, "synced") for d in sorted(account.iterdir()) if d.is_dir()]
    return items
