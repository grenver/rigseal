"""Building blocks shared by the per-agent collectors."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from rigseal.model import FileHash, Item, hash_file, hash_json, hash_tree


def single_file(agent: str, path: Path, scope: str, kind: str, name: str, details: dict | None = None) -> Item:
    digest = hash_file(path)
    return Item(agent, scope, kind, name, str(path), digest, [FileHash(path.name, digest)], details or {})


def optional_file(agent: str, path: Path, scope: str, kind: str) -> list[Item]:
    if not path.is_file():
        return []
    return [single_file(agent, path, scope, kind, path.name)]


def files_matching(agent: str, root: Path, suffix: str, kind: str, scope: str) -> list[Item]:
    """One item per file under root ending in suffix, named by its relative path without the suffix."""
    if not root.is_dir():
        return []
    items = []
    for f in sorted(p for p in root.rglob(f"*{suffix}") if p.is_file()):
        name = f.relative_to(root).as_posix().removesuffix(suffix)
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


def skill_item(agent: str, d: Path, scope: str, kind: str = "skill") -> Item:
    digest, files = hash_tree(d)
    details: dict = {"has_skill_md": (d / "SKILL.md").is_file()}
    if d.is_symlink():
        details["link"] = os.readlink(d)
    return Item(agent, scope, kind, d.name, str(d), digest, files, details)


def skill_dirs(agent: str, root: Path, scope: str, skip: tuple[str, ...] = (), kind: str = "skill") -> list[Item]:
    """One item per folder in root, hidden ones too. Symlinked folders are followed and their target is recorded."""
    if not root.is_dir():
        return []
    return [skill_item(agent, d, scope, kind) for d in sorted(root.iterdir()) if d.is_dir() and d.name not in skip]
