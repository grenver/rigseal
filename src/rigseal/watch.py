"""`rigseal watch`: re-check as soon as a watched file changes, and report drift as it appears and clears.

Polls file stats (no new dependency, works the same on every OS): every item's files, the folders they live in, and
the lockfiles. A stat change triggers a full check. A full check also runs every `rescan` seconds, to catch config
showing up in a place that had none.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from rigseal.lock import Change
from rigseal.model import Item


def watched_paths(items: list[Item], extra: list[Path]) -> list[Path]:
    paths = set(extra)
    for item in items:
        p = Path(item.path)
        paths.update((p, p.parent))
        if item.files and p.is_dir():
            paths.update(p / f.path for f in item.files)
    return sorted(paths)


def fingerprint(paths: list[Path]) -> tuple:
    out = []
    for p in paths:
        try:
            st = p.stat()
            out.append((st.st_mtime_ns, st.st_size, st.st_ino))
        except OSError:
            out.append(None)
    return tuple(out)


@dataclass
class Result:
    paths: list[Path]
    found: list[Change]
    shas: dict[str, str | None]  # current hash per drifted key, so a second edit of a drifted item is reported again


@dataclass
class Watcher:
    check: Callable[[], Result]
    rescan: float = 30.0
    clock: Callable[[], float] = time.monotonic
    seen: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    _paths: list[Path] = field(default_factory=list)
    _print: tuple = ()
    _last: float = float("-inf")

    def poll(self) -> tuple[list[Change], list[str]] | None:
        """One tick. Returns (new or changed drift, keys whose drift cleared), or None if nothing was checked."""
        if self._paths and fingerprint(self._paths) == self._print and self.clock() - self._last < self.rescan:
            return None
        r = self.check()
        self._paths, self._print, self._last = r.paths, fingerprint(r.paths), self.clock()
        now = {c.key: (c.status, r.shas.get(c.key)) for c in r.found}
        new = [c for c in r.found if self.seen.get(c.key) != now[c.key]]
        cleared = sorted(self.seen.keys() - now.keys())
        self.seen = now
        return new, cleared
