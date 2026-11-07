"""SARIF 2.1.0 output, so GitHub code scanning (and other tools) can show findings next to the files."""

from __future__ import annotations

from pathlib import Path

from rigseal import __version__
from rigseal.lock import Change, item_key
from rigseal.model import Finding, Item

RULES = {
    "SIGNATURE": "A lockfile signature is missing or does not verify",
    "DRIFT": "An agent skill, plugin, hook, setting or MCP server changed since it was approved",
    "R1": "MCP server added, removed or changed without approval",
    "R2": "MCP server runs inline shell or interpreter code, pipes a download into a shell, or lives in a temp folder",
    "R3": "Project settings that approve themselves (auto-enable MCP servers, broad shell permissions, hooks, API redirects)",
    "R7": "Asks to install a prerequisite from a direct download link",
    "R8": "Encoded blob together with a decoder",
    "R9": "Password-protected archive with the password in the text",
    "R10": "Reverse shell pattern",
    "R11": "Code that touches keys, wallets or browser data and makes a network call",
    "R12": "Hidden folder, binary or archive in a skill; link leaving the project; too large to hash fully",
    "R13": "Words mixing Latin and Cyrillic letters",
    "R14": "Decodes code and runs it, or pipes a download into a shell",
    "R15": "Hidden Unicode characters (tags, bidi controls, zero-width)",
    "R16": "npx/uvx/bunx package without a pinned version",
    "R18": "Uses shell or network without declaring it in allowed-tools",
    "R19": "Prompt-injection classifier flagged this text",
}
LEVELS = {"high": "error", "medium": "warning", "low": "note"}
SCORES = {"high": "8.0", "medium": "5.0", "low": "2.0"}


def _uri(path: str, file: str | None, project: Path | None) -> str:
    p = Path(path)
    if file and p.is_dir():
        p = p / file
    if project is not None:
        try:
            return p.resolve().relative_to(project.resolve()).as_posix()
        except ValueError:
            pass
    return p.as_uri() if p.is_absolute() else p.as_posix()


def _location(uri: str) -> dict:
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}


def report(
    items: list[Item],
    findings: list[Finding],
    changes: list[Change],
    project: Path | None,
    signature_problems: list[str] | None = None,
) -> dict:
    paths = {item_key(i): i.path for i in items}
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule,
                "level": LEVELS[f.severity],
                "message": {"text": f"{f.key}: {f.message}"},
                "locations": [_location(_uri(paths.get(f.key, f.key), f.file, project))],
                "properties": {"item": f.key, "severity": f.severity},
            }
        )
    for c in changes:
        detail = ", ".join(c.capabilities[:5] + c.files_changed[:5] + c.files_added[:5])
        results.append(
            {
                "ruleId": "DRIFT",
                "level": "error",
                "message": {"text": f"{c.key} {c.status} since last approve ({c.lock} lock)" + (f": {detail}" if detail else "")},
                "locations": [_location(_uri(paths.get(c.key, c.key), None, project))],
                "properties": {"item": c.key, "status": c.status},
            }
        )
    for problem in signature_problems or []:
        results.append({"ruleId": "SIGNATURE", "level": "error", "message": {"text": problem}, "locations": []})
    used = sorted({r["ruleId"] for r in results}, key=lambda r: (r[1:].isdigit(), int(r[1:]) if r[1:].isdigit() else 0, r))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rigseal",
                        "version": __version__,
                        "informationUri": "https://github.com/jayhemnani9910/rigseal",
                        "rules": [
                            {
                                "id": r,
                                "shortDescription": {"text": RULES.get(r, r)},
                                "properties": {"security-severity": SCORES["high" if r in ("DRIFT", "SIGNATURE") else _rule_severity(r, findings)]},
                            }
                            for r in used
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def _rule_severity(rule: str, findings: list[Finding]) -> str:
    sevs = [f.severity for f in findings if f.rule == rule]
    return min(sevs, key=["high", "medium", "low"].index) if sevs else "medium"
