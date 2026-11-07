"""On-disk cache of per-file analysis, keyed by file hash.

Agent setups rarely change, so most runs only need to hash files. The cache is thrown away whenever the
analysis code changes (its version is a hash of the modules that produce the results).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ANALYSIS_MODULES = ("capabilities.py", "text_rules.py")


def analysis_version() -> str:
    h = hashlib.sha256()
    for name in ANALYSIS_MODULES:
        h.update((Path(__file__).parent / name).read_bytes())
    return h.hexdigest()[:16]


def cache_path(home: Path) -> Path:
    base = Path(os.environ["XDG_CACHE_HOME"]) if os.environ.get("XDG_CACHE_HOME") else home / ".cache"
    return base / "rigseal" / "analysis.json"


class Cache:
    def __init__(self, path: Path):
        self.path = path
        self.version = analysis_version()
        self.entries: dict[str, dict] = {}
        self.used: set[str] = set()
        self.dirty = False
        try:
            doc = json.loads(path.read_text())
            if doc.get("version") == self.version:
                self.entries = doc.get("entries") or {}
        except (OSError, ValueError, AttributeError):
            pass  # missing or broken cache: start empty

    def get(self, key: str) -> dict | None:
        if key in self.entries:
            self.used.add(key)
            return self.entries[key]
        return None

    def put(self, key: str, value: dict) -> None:
        self.entries[key] = value
        self.used.add(key)
        self.dirty = True

    def save(self) -> None:
        """Write the entries used this run, so files that are gone drop out."""
        if not self.dirty and self.used == set(self.entries):
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps({"version": self.version, "entries": {k: self.entries[k] for k in sorted(self.used)}}))
            tmp.replace(self.path)
        except OSError:
            pass  # a cache that can't be written only costs speed
