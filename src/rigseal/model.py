"""The normalized inventory item and the hashing helpers every collector uses."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


class CollectError(Exception):
    """A config file exists but can't be read or parsed."""


@dataclass
class FileHash:
    path: str  # relative to the item's root
    sha256: str


@dataclass
class Item:
    agent: str  # e.g. "claude-code"
    scope: str  # user | project | local | plugin
    kind: str  # settings | mcp | skill | command | agent | plugin | instructions
    name: str
    path: str  # where the item was found
    sha256: str  # one hash over everything that defines the item
    files: list[FileHash] = field(default_factory=list)
    details: dict = field(default_factory=dict)  # non-secret facts, shown to the user

    def to_dict(self) -> dict:
        return asdict(self)


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_json(value: object) -> str:
    """Stable hash of a JSON value. Used so secrets in configs are hashed, never stored."""
    return hash_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def hash_tree(root: Path) -> tuple[str, list[FileHash]]:
    """Hash every file under root, dotfiles included. Symlinks are recorded by target, not followed."""
    files: list[FileHash] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        base = Path(dirpath)
        # os.walk does not descend into symlinked dirs, so record them here.
        for name in sorted(dirnames + filenames):
            p = base / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                files.append(FileHash(rel, hash_bytes(b"symlink:" + os.readlink(p).encode())))
            elif p.is_file():
                files.append(FileHash(rel, hash_file(p)))
    files.sort(key=lambda f: f.path)
    return tree_digest(files), files


def tree_digest(files: list[FileHash]) -> str:
    lines = "".join(f"{f.path}\0{f.sha256}\n" for f in sorted(files, key=lambda f: f.path))
    return hash_bytes(lines.encode())
