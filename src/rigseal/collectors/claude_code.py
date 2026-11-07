"""Collect everything Claude Code loads: settings, MCP servers, skills, commands, agents, plugins, instructions.

Read-only. Secret values (env, args, headers, apiKeyHelper) are hashed into the item hash and never
copied into `details`.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from rigseal.model import CollectError, FileHash, Item, hash_file, hash_json, hash_tree, tree_digest

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


def collect(home: Path, project: Path | None) -> list[Item]:
    items: list[Item] = []
    claude_dir = home / ".claude"

    items += _settings(claude_dir / "settings.json", "user")
    items += _instructions(claude_dir / "CLAUDE.md", "user")
    items += _user_mcp(home / ".claude.json", project)
    items += _skills(claude_dir / "skills", "user")
    items += _markdown_items(claude_dir / "commands", "command", "user")
    items += _markdown_items(claude_dir / "agents", "agent", "user")
    items += _plugins(claude_dir / "plugins" / "installed_plugins.json")

    if project is not None:
        pc = project / ".claude"
        items += _settings(pc / "settings.json", "project")
        items += _settings(pc / "settings.local.json", "local")
        items += _project_mcp(project / ".mcp.json")
        items += _skills(pc / "skills", "project")
        items += _markdown_items(pc / "commands", "command", "project")
        items += _markdown_items(pc / "agents", "agent", "project")
        for name, scope in (("CLAUDE.md", "project"), ("CLAUDE.local.md", "local"), ("AGENTS.md", "project")):
            items += _instructions(project / name, scope)
    return items


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise CollectError(f"cannot read {path}: {e}") from e
    if not isinstance(data, dict):
        raise CollectError(f"{path}: expected a JSON object")
    return data


def _single_file(path: Path, scope: str, kind: str, name: str, details: dict | None = None) -> Item:
    digest = hash_file(path)
    return Item(AGENT, scope, kind, name, str(path), digest, [FileHash(path.name, digest)], details or {})


def _settings(path: Path, scope: str) -> list[Item]:
    data = _read_json(path)
    if data is None:
        return []
    risky = [k for k in RISKY_SETTINGS_KEYS if k in data]
    details: dict = {"risky_keys": risky}
    if isinstance(data.get("hooks"), dict):
        details["hook_events"] = sorted(data["hooks"])
    return [_single_file(path, scope, "settings", path.name, details)]


def _instructions(path: Path, scope: str) -> list[Item]:
    if not path.is_file():
        return []
    return [_single_file(path, scope, "instructions", path.name)]


def _mcp_item(name: str, cfg: object, scope: str, where: Path) -> Item:
    details: dict = {}
    if isinstance(cfg, dict):
        transport = cfg.get("type") or ("stdio" if "command" in cfg else "http" if "url" in cfg else "unknown")
        details["transport"] = transport
        if "command" in cfg:
            details["command"] = str(cfg["command"])
            details["arg_count"] = len(cfg.get("args") or [])
        if "url" in cfg:
            details["host"] = urlparse(str(cfg["url"])).netloc
        for key in ("env", "headers"):
            if isinstance(cfg.get(key), dict) and cfg[key]:
                details[f"{key}_keys"] = sorted(cfg[key])
    return Item(AGENT, scope, "mcp", name, str(where), hash_json(cfg), [], details)


def _user_mcp(path: Path, project: Path | None) -> list[Item]:
    data = _read_json(path)
    if data is None:
        return []
    items = [_mcp_item(n, c, "user", path) for n, c in sorted((data.get("mcpServers") or {}).items())]
    if project is not None:
        proj = (data.get("projects") or {}).get(str(project)) or {}
        items += [_mcp_item(n, c, "local", path) for n, c in sorted((proj.get("mcpServers") or {}).items())]
    return items


def _project_mcp(path: Path) -> list[Item]:
    data = _read_json(path)
    if data is None:
        return []
    return [_mcp_item(n, c, "project", path) for n, c in sorted((data.get("mcpServers") or {}).items())]


def _skills(root: Path, scope: str) -> list[Item]:
    if not root.is_dir():
        return []
    items = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        digest, files = hash_tree(d)
        items.append(Item(AGENT, scope, "skill", d.name, str(d), digest, files, {"has_skill_md": (d / "SKILL.md").is_file()}))
    return items


def _markdown_items(root: Path, kind: str, scope: str) -> list[Item]:
    if not root.is_dir():
        return []
    items = []
    for f in sorted(root.rglob("*.md")):
        name = f.relative_to(root).with_suffix("").as_posix()
        items.append(_single_file(f, scope, kind, name))
    return items


def _plugins(path: Path) -> list[Item]:
    data = _read_json(path)
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
