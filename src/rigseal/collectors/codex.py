"""Collect what OpenAI Codex loads: config.toml (MCP servers, hooks, plugins), skills, plugins, rules, AGENTS.md."""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item, hash_tree
from rigseal.readers import read_toml

AGENT = "codex"

RISKY_CONFIG_KEYS = (
    "approval_policy",
    "sandbox_mode",
    "hooks",
    "notify",
    "shell_environment_policy",
    "model_providers",
    "marketplaces",
    "plugins",
)

optional_file = partial(common.optional_file, AGENT)
skill_dirs = partial(common.skill_dirs, AGENT)


def collect(home: Path, project: Path | None) -> list[Item]:
    codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
    items: list[Item] = []

    config = _config(codex_home / "config.toml", "user", items)
    items += skill_dirs(codex_home / "skills", "user", skip=(".system",))
    items += skill_dirs(codex_home / "skills" / ".system", "system")
    items += _plugins(codex_home / "plugins" / "cache", (config or {}).get("plugins") or {})
    items += common.files_matching(AGENT, codex_home / "rules", ".rules", "rule", "user")
    items += optional_file(codex_home / "AGENTS.md", "user", "instructions")

    if project is not None:
        _config(project / ".codex" / "config.toml", "project", items)
        items += skill_dirs(project / ".codex" / "skills", "project")
    return items


def _config(path: Path, scope: str, items: list[Item]) -> dict | None:
    data = read_toml(path)
    if data is None:
        return None
    items.append(common.settings_item(AGENT, path, data, scope, RISKY_CONFIG_KEYS))
    items += common.mcp_items(AGENT, data.get("mcp_servers"), scope, path)
    return data


def _plugins(cache: Path, enabled: dict) -> list[Item]:
    """Plugins live in cache/<marketplace>/<plugin>/. The config says which are enabled."""
    if not cache.is_dir():
        return []
    items = []
    for market in sorted(p for p in cache.iterdir() if p.is_dir()):
        for plugin in sorted(p for p in market.iterdir() if p.is_dir()):
            name = f"{plugin.name}@{market.name}"
            digest, files = hash_tree(plugin)
            entry = enabled.get(name)
            details = {"enabled": bool(entry.get("enabled")) if isinstance(entry, dict) else False}
            items.append(Item(AGENT, "plugin", "plugin", name, str(plugin), digest, files, details))
    return items
