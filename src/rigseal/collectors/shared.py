"""The shared Agent Skills folder (~/.agents/skills) that several agents read or link to."""

from __future__ import annotations

from pathlib import Path

from rigseal.collectors import common
from rigseal.model import Item

AGENT = "shared"


def collect(home: Path, project: Path | None) -> list[Item]:
    items = common.skill_dirs(AGENT, home / ".agents" / "skills", "user")
    if project is not None:
        items += common.skill_dirs(AGENT, project / ".agents" / "skills", "project", within=project)
    return items
