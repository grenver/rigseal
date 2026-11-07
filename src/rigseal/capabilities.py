"""Work out what a skill, command, rule or plugin can do by reading its text files.

The result goes in item.details["capabilities"], so it is locked and a change shows in `rigseal diff`.
Heuristics, not proof: the lock still catches any byte change.
"""

from __future__ import annotations

import re
from pathlib import Path

from rigseal.model import Item

TEXT_KINDS = {"skill", "command", "agent", "rule", "instructions", "prompt", "plugin"}
TEXT_SUFFIXES = {
    ".md", ".mdc", ".txt", ".rules", ".json", ".toml", ".yaml", ".yml",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
}  # fmt: skip
SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd"}
CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}
PROSE_SUFFIXES = {".md", ".mdc", ".txt", ".rules"}  # text the agent reads as instructions
MAX_BYTES = 512 * 1024
# Vendored code: still hashed (so any change is drift), but not read for capabilities.
SKIP_DIRS = {"node_modules", ".venv", "venv", "site-packages", "__pycache__", ".git"}

FENCE = re.compile(r"```([\w+-]*)[^\n]*\n(.*?)```", re.S)
SHELL_FENCES = {"bash", "sh", "shell", "zsh", "console", "shellscript", "powershell", "ps1"}
BANG_COMMAND = re.compile(r"!`[^`\n]+`")  # Claude Code commands run !`cmd` before the prompt
SHELL_IN_CODE = re.compile(r"\b(subprocess|os\.system|os\.popen|child_process|execSync|spawnSync|Runtime\.exec)\b")
NETWORK = re.compile(r"\b(curl|wget|Invoke-WebRequest|requests\.(get|post)|urllib|httpx|fetch\(|axios|net\.connect|socket\.)")
URL_HOST = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SENSITIVE = re.compile(
    r"(~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.netrc|\.npmrc|\.pypirc|"
    r"\.docker/config\.json|\.kube/config|\.gnupg|_history\b|/etc/shadow|/etc/passwd|"
    r"(?<![\w.])\.env(?![\w.-])|Keychains?/|wallet\.dat|\.bitcoin|electrum|exodus|metamask)",
    re.I,
)

# Cheap substring test before the regex, which is slow on big files. Each SENSITIVE branch contains one of these.
SENSITIVE_HINTS = (
    ".ssh", "id_rsa", "id_ed25519", ".aws", ".git-credentials", ".netrc", ".npmrc", ".pypirc", ".docker",
    ".kube", ".gnupg", "_history", "/etc/", ".env", "keychain", "wallet.dat", ".bitcoin", "electrum", "exodus", "metamask",
)  # fmt: skip

# Characters people can't see but models read.
HIDDEN = {
    "tag": re.compile("[\U000e0000-\U000e007f]"),
    "bidi": re.compile("[‪-‮⁦-⁩]"),
    "zero-width": re.compile("[​-‍⁠᠎]|(?<!^)﻿"),
}


def hidden_chars(text: str, prose: bool = True) -> dict[str, int]:
    """Tag characters count everywhere. Bidi and zero-width only in prose: code and tests use them legitimately."""
    kinds = HIDDEN if prose else {"tag": HIDDEN["tag"]}
    return {name: n for name, pat in kinds.items() if (n := len(pat.findall(text)))}


def frontmatter(text: str) -> dict[str, list[str]]:
    """The few frontmatter keys we need (allowed-tools, tools), as lists. Not a full YAML parser."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    out: dict[str, list[str]] = {}
    current = None
    for line in text[3:end].splitlines():
        if m := re.match(r"^([\w-]+):\s*(.*)$", line):
            current, value = m.group(1), m.group(2).strip()
            value = value.strip("[]")
            out[current] = [v.strip().strip("\"'") for v in re.split(r"[,\s]+(?![^(]*\))", value) if v.strip()]
        elif current and (m := re.match(r"^\s+-\s*(.+)$", line)):
            out[current].append(m.group(1).strip().strip("\"'"))
    return out


def _read(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in (".cursorrules",):
        return None
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(errors="replace")
    except OSError:
        return None


def extract(item: Item) -> dict:
    shell = network = False
    hosts: set[str] = set()
    sensitive: set[str] = set()
    hidden: dict[str, dict[str, int]] = {}
    allowed_tools: list[str] | None = None

    for rel, full in item.text_files():
        if SKIP_DIRS.intersection(Path(rel).parts[:-1]):
            continue
        text = _read(full)
        if text is None:
            continue
        suffix = full.suffix.lower()
        if found := hidden_chars(text, prose=suffix in PROSE_SUFFIXES or full.name == ".cursorrules"):
            hidden[rel] = found
        lowered = text.lower()
        if any(h in lowered for h in SENSITIVE_HINTS):
            sensitive.update(m.group(0).lower() for m in SENSITIVE.finditer(text))

        if suffix in SHELL_SUFFIXES or suffix in CODE_SUFFIXES:
            code = text
            shell = shell or suffix in SHELL_SUFFIXES or bool(SHELL_IN_CODE.search(text))
        else:
            fences = FENCE.findall(text)
            code = "\n".join(body for _, body in fences)
            shell = shell or any(lang.lower() in SHELL_FENCES for lang, _ in fences) or bool(BANG_COMMAND.search(text))
            code += "\n".join(BANG_COMMAND.findall(text))
        if NETWORK.search(code):
            network = True
        hosts.update(h.lower() for h in URL_HOST.findall(code))

        if full.name in ("SKILL.md",) or (item.kind in ("command", "agent") and suffix == ".md"):
            fm = frontmatter(text)
            if "allowed-tools" in fm or "tools" in fm:
                allowed_tools = fm.get("allowed-tools", fm.get("tools"))

    caps: dict = {}
    if shell:
        caps["shell"] = True
    if network or hosts:
        caps["network"] = True
    if hosts:
        caps["hosts"] = sorted(hosts)
    if sensitive:
        caps["sensitive_paths"] = sorted(sensitive)
    if hidden:
        caps["hidden_chars"] = hidden
    if allowed_tools is not None:
        caps["allowed_tools"] = allowed_tools
    return caps


def enrich(items: list[Item]) -> None:
    for item in items:
        if item.kind in TEXT_KINDS and item.files:
            if caps := extract(item):
                item.details["capabilities"] = caps
