"""Dogfood log: how often does the lock go off on a real machine, and why?

  log     run `rigseal check --json` once and append the result to ~/.rigseal/dogfood.jsonl
  report  summarize the log: drift events per week, how many look like routine plugin updates

Run `log` daily from cron. Needs a machine lock first (`rigseal init`, at a terminal).
Usage: uv run --project ~/projects/personal/rigseal python evals/dogfood.py log|report
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from rigseal.lock import rigseal_dir

LOG = rigseal_dir(Path.home()) / "dogfood.jsonl"


def classify(change: dict) -> str:
    """Rough reason for a change: a plugin or its MCP server changing is most likely an auto-update."""
    _, scope, kind = change["key"].split("/")[:3]
    if scope in ("plugin", "system", "synced"):
        return "auto-update"
    if kind == "settings":
        return "settings"
    return "user-change"


def log() -> int:
    started = datetime.now(UTC)
    proc = subprocess.run(["rigseal", "check", "--json"], capture_output=True, text=True, check=False)
    entry: dict = {"at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "exit": proc.returncode}
    try:
        result = json.loads(proc.stdout)
        entry["changes"] = [
            {
                "key": c["key"],
                "status": c["status"],
                "sha256": c.get("sha256", ""),
                "reason": classify(c),
                "files": len(c.get("files_changed", [])) + len(c.get("files_added", [])) + len(c.get("files_removed", [])),
                "rules": sorted({f["rule"] for f in c.get("findings", [])}),
            }
            for c in result["changes"]
        ]
        entry["signature_problems"] = len(result["signature_problems"])
    except (ValueError, KeyError):
        entry["error"] = (proc.stderr or proc.stdout).strip()[:500]
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return 0


def report() -> int:
    if not LOG.exists():
        print(f"no log yet at {LOG}")
        return 1
    entries = [json.loads(line) for line in LOG.read_text().splitlines() if line.strip()]
    if not entries:
        print(f"no log yet at {LOG}")
        return 1
    errors = [e for e in entries if "error" in e]
    # A change stays pending until approved, so count each state of an item once.
    seen: dict[tuple, dict] = {}
    for e in entries:
        for c in e.get("changes", []):
            seen.setdefault((c["key"], c["status"], c["files"], c.get("sha256")), {**c, "first_seen": e["at"]})
    first, last = entries[0]["at"], entries[-1]["at"]
    days = max((datetime.fromisoformat(last) - datetime.fromisoformat(first)).days, 1)
    reasons = Counter(c["reason"] for c in seen.values())
    print(f"{len(entries)} checks from {first} to {last} ({days} days), {len(errors)} errors")
    print(f"{len(seen)} distinct drift events, {len(seen) / days * 7:.1f} per week")
    for reason, n in reasons.most_common():
        print(f"  {reason:12} {n:4}  ({n / days * 7:.1f} per week)")
    flagged = [c for c in seen.values() if c["rules"]]
    print(f"{len(flagged)} events had rule findings")
    return 0


if __name__ == "__main__":
    commands = {"log": log, "report": report}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print(__doc__)
        sys.exit(2)
    sys.exit(commands[sys.argv[1]]())
