"""Lockfiles and drift.

Two locks:
- repo lock (`rigseal.lock` in the project): project-scope items, paths relative to the project. Committed.
- machine lock (`$RIGSEAL_DIR/machine.lock`, default `~/.rigseal`): user, plugin and system items, plus
  local-scope items grouped per project. Never committed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rigseal import __version__
from rigseal.model import CollectError, Item

LOCK_VERSION = 0
REPO_LOCK_NAME = "rigseal.lock"


def rigseal_dir(home: Path) -> Path:
    return Path(os.environ["RIGSEAL_DIR"]) if os.environ.get("RIGSEAL_DIR") else home / ".rigseal"


def machine_lock_path(home: Path) -> Path:
    return rigseal_dir(home) / "machine.lock"


def repo_lock_path(project: Path) -> Path:
    return project / REPO_LOCK_NAME


def item_key(item: Item) -> str:
    return f"{item.agent}/{item.scope}/{item.kind}/{item.name}"


def _rel(path: str, base: Path, prefix: str) -> str:
    try:
        return prefix + Path(path).relative_to(base).as_posix()
    except ValueError:
        return path


def entry(item: Item, base: Path, prefix: str) -> dict:
    return {
        "agent": item.agent,
        "scope": item.scope,
        "kind": item.kind,
        "name": item.name,
        "path": _rel(item.path, base, prefix),
        "sha256": item.sha256,
        "files": {f.path: f.sha256 for f in item.files},
        "details": item.details,
    }


def keyed(items: list[Item], base: Path, prefix: str) -> dict[str, dict]:
    """Items as lock entries by key. Same key twice (e.g. a plugin installed twice) gets #2, #3."""
    out: dict[str, dict] = {}
    for item in items:
        key = item_key(item)
        n = 1
        while key in out:
            n += 1
            key = f"{item_key(item)}#{n}"
        out[key] = entry(item, base, prefix)
    return out


@dataclass
class Current:
    """The live inventory split the way the two locks store it."""

    repo: dict[str, dict]
    machine: dict[str, dict]
    local: dict[str, dict]


def split(items: list[Item], home: Path, project: Path) -> Current:
    repo = [i for i in items if i.scope == "project"]
    local = [i for i in items if i.scope == "local"]
    machine = [i for i in items if i.scope not in ("project", "local")]
    return Current(keyed(repo, project, ""), keyed(machine, home, "~/"), keyed(local, home, "~/"))


# --- files -------------------------------------------------------------------


@dataclass
class Lock:
    path: Path
    items: dict[str, dict] = field(default_factory=dict)
    projects: dict[str, dict[str, dict]] = field(default_factory=dict)  # machine lock only
    signed_by: str | None = None

    @property
    def sig_path(self) -> Path:
        return self.path.with_name(self.path.name + ".sig")

    def to_json(self) -> str:
        doc: dict = {"lockfileVersion": LOCK_VERSION, "generator": f"rigseal {__version__}"}
        if self.signed_by:
            doc["signedBy"] = self.signed_by
        doc["items"] = dict(sorted(self.items.items()))
        if self.projects:
            doc["projects"] = {p: dict(sorted(v.items())) for p, v in sorted(self.projects.items()) if v}
        return json.dumps(doc, indent=2, sort_keys=False) + "\n"

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(self.to_json())
        tmp.replace(self.path)


def read_lock(path: Path) -> Lock | None:
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise CollectError(f"cannot read lock {path}: {e}") from e
    if not isinstance(doc, dict) or doc.get("lockfileVersion") != LOCK_VERSION:
        raise CollectError(f"{path}: not a rigseal v{LOCK_VERSION} lockfile")
    return Lock(path, doc.get("items") or {}, doc.get("projects") or {}, doc.get("signedBy"))


# --- diff --------------------------------------------------------------------


@dataclass
class Change:
    key: str
    status: str  # added | removed | changed
    lock: str  # repo | machine
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    details_changed: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)  # "+ network", "+ host evil.com", "- shell"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v or k in ("key", "status", "lock")}


def diff_entries(locked: dict[str, dict], current: dict[str, dict], lock_name: str) -> list[Change]:
    changes = []
    for key in sorted(locked.keys() | current.keys()):
        old, new = locked.get(key), current.get(key)
        if old is None:
            changes.append(Change(key, "added", lock_name, files_added=sorted(new["files"])))
        elif new is None:
            changes.append(Change(key, "removed", lock_name))
        elif old["sha256"] != new["sha256"] or old.get("details") != new.get("details"):
            of, nf = old.get("files", {}), new["files"]
            od, nd = old.get("details") or {}, new.get("details") or {}
            changes.append(
                Change(
                    key,
                    "changed",
                    lock_name,
                    files_added=sorted(nf.keys() - of.keys()),
                    files_removed=sorted(of.keys() - nf.keys()),
                    files_changed=sorted(k for k in of.keys() & nf.keys() if of[k] != nf[k]),
                    details_changed=sorted(k for k in od.keys() | nd.keys() if od.get(k) != nd.get(k)),
                    capabilities=capability_diff(od.get("capabilities") or {}, nd.get("capabilities") or {}),
                )
            )
    return changes


CAP_LABELS = {"hosts": "host", "sensitive_paths": "sensitive path", "allowed_tools": "allowed tool"}


def capability_diff(old: dict, new: dict) -> list[str]:
    """Readable lines for what an item can now do that it couldn't before (and the reverse)."""
    lines = []
    for k in sorted(old.keys() | new.keys()):
        a, b = old.get(k), new.get(k)
        if a == b:
            continue
        if isinstance(a, bool) or isinstance(b, bool):
            lines.append(f"{'+' if b else '-'} {k}")
        elif k == "hidden_chars":
            lines += [f"+ hidden chars in {f}" for f in sorted((b or {}).keys() - (a or {}).keys())]
            lines += [f"- hidden chars in {f}" for f in sorted((a or {}).keys() - (b or {}).keys())]
        else:
            label = CAP_LABELS.get(k, k)
            lines += [f"+ {label} {v}" for v in sorted(set(b or []) - set(a or []))]
            lines += [f"- {label} {v}" for v in sorted(set(a or []) - set(b or []))]
    return lines


def apply(locked: dict[str, dict], current: dict[str, dict], keys: set[str] | None, who: str, when: str) -> dict[str, dict]:
    """Accept current state for `keys` (all if None). Returns the new locked entries."""
    out = dict(locked)
    for key in locked.keys() | current.keys():
        if keys is not None and key not in keys:
            continue
        if key in current:
            if locked.get(key, {}).get("sha256") == current[key]["sha256"] and locked[key].get("details") == current[key]["details"]:
                continue  # unchanged: keep the original approval
            out[key] = {**current[key], "approvedBy": who, "approvedAt": when}
        else:
            out.pop(key, None)
    return out


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
