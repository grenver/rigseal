"""Building blocks shared by the per-agent collectors."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from rigseal.model import FileHash, Item, hash_bytes, hash_file, hash_json, hash_tree
from rigseal.readers import read_json


def escapes(path: Path, within: Path | None) -> bool:
    """True if `path` is a symlink that resolves outside `within` (the project). Such links are not followed:
    a cloned repo could point a skill at / or at ~/.ssh."""
    if within is None or not path.is_symlink():
        return False
    try:
        return not path.resolve().is_relative_to(within.resolve())
    except OSError:
        return True


def link_item(agent: str, path: Path, scope: str, kind: str, name: str) -> Item:
    """A symlink leaving the project: hashed by its target string, never read."""
    target = os.readlink(path)
    return Item(agent, scope, kind, name, str(path), hash_bytes(b"symlink:" + target.encode()), [], {"link": target, "outside_project": True})


def single_file(agent: str, path: Path, scope: str, kind: str, name: str, details: dict | None = None) -> Item:
    digest = hash_file(path)
    return Item(agent, scope, kind, name, str(path), digest, [FileHash(path.name, digest)], details or {})


def optional_file(agent: str, path: Path, scope: str, kind: str, within: Path | None = None) -> list[Item]:
    if escapes(path, within):
        return [link_item(agent, path, scope, kind, path.name)]
    if not path.is_file():
        return []
    return [single_file(agent, path, scope, kind, path.name)]


def files_matching(agent: str, root: Path, suffix: str, kind: str, scope: str, within: Path | None = None) -> list[Item]:
    """One item per file under root ending in suffix, named by its relative path without the suffix."""
    if not root.is_dir() or escapes(root, within):
        return []
    items = []
    for f in sorted(p for p in root.rglob(f"*{suffix}") if p.is_file() or p.is_symlink()):
        name = f.relative_to(root).as_posix().removesuffix(suffix)
        if escapes(f, within):
            items.append(link_item(agent, f, scope, kind, name))
        elif f.is_file():
            items.append(single_file(agent, f, scope, kind, name))
    return items


def settings_item(agent: str, path: Path, data: dict, scope: str, risky_keys: tuple[str, ...]) -> Item:
    details: dict = {"risky_keys": [k for k in risky_keys if k in data]}
    if isinstance(data.get("hooks"), dict):
        details["hook_events"] = sorted(data["hooks"])
    item = single_file(agent, path, scope, "settings", path.name, details)
    item.raw = data
    return item


def mcp_item(agent: str, name: str, cfg: object, scope: str, where: Path) -> Item:
    """An MCP server entry. The full config is hashed; only non-secret facts go in details."""
    details: dict = {}
    if isinstance(cfg, dict):
        transport = cfg.get("type") or ("stdio" if "command" in cfg else "http" if "url" in cfg else "unknown")
        details["transport"] = transport
        if "command" in cfg:
            details["command"] = str(cfg["command"])
            details["arg_count"] = len(cfg.get("args") or [])
        if "url" in cfg:
            details["host"] = urlparse(str(cfg["url"])).netloc
        for key in ("env", "headers", "http_headers"):
            if isinstance(cfg.get(key), dict) and cfg[key]:
                details[f"{key}_keys"] = sorted(cfg[key])
    return Item(agent, scope, "mcp", name, str(where), hash_json(cfg), [], details, raw=cfg)


def mcp_items(agent: str, servers: object, scope: str, where: Path) -> list[Item]:
    if not isinstance(servers, dict):
        return []
    return [mcp_item(agent, n, c, scope, where) for n, c in sorted(servers.items())]


def tree_item(agent: str, d: Path, scope: str, kind: str, name: str, details: dict | None = None,
              ignore: frozenset[str] = frozenset()) -> Item:  # fmt: skip
    tree = hash_tree(d, ignore)
    details = dict(details or {})
    if tree.truncated:
        details["truncated"] = True
    return Item(agent, scope, kind, name, str(d), tree.sha256, tree.files, details)


def skill_item(agent: str, d: Path, scope: str, kind: str = "skill", within: Path | None = None) -> Item:
    if escapes(d, within):
        return link_item(agent, d, scope, kind, d.name)
    details: dict = {"has_skill_md": (d / "SKILL.md").is_file()}
    if d.is_symlink():
        details["link"] = os.readlink(d)
    return tree_item(agent, d, scope, kind, d.name, details)


def skill_dirs(agent: str, root: Path, scope: str, skip: tuple[str, ...] = (), kind: str = "skill",
               within: Path | None = None) -> list[Item]:  # fmt: skip
    """One item per folder in root, hidden ones too. Symlinked folders are followed and their target is recorded,
    except in a project (`within`), where links leaving the project are recorded but not followed."""
    if not root.is_dir() or escapes(root, within):
        return []
    return [
        skill_item(agent, d, scope, kind, within)
        for d in sorted(root.iterdir())
        if d.name not in skip and (d.is_dir() or escapes(d, within))
    ]


def plugin_mcp(agent: str, plugin_dir: Path, plugin: str) -> list[Item]:
    """MCP servers a plugin ships: `.mcp.json` at its root, or what `.claude-plugin/plugin.json` points to
    (a relative path, or the servers inline). Named `plugin:server`, as the agents show them."""
    sources: list[tuple[Path, object]] = []
    manifest = read_json(plugin_dir / ".claude-plugin" / "plugin.json") or {}
    declared = manifest.get("mcpServers")
    if isinstance(declared, dict):
        sources.append((plugin_dir / ".claude-plugin" / "plugin.json", declared))
    elif isinstance(declared, str):
        path = (plugin_dir / declared).resolve()
        if path.is_relative_to(plugin_dir.resolve()):
            sources.append((path, (read_json(path) or {}).get("mcpServers")))
    else:
        path = plugin_dir / ".mcp.json"
        sources.append((path, (read_json(path) or {}).get("mcpServers")))
    items = []
    for where, servers in sources:
        if isinstance(servers, dict):
            items += [mcp_item(agent, f"{plugin}:{n}", c, "plugin", where) for n, c in sorted(servers.items())]
    return items
