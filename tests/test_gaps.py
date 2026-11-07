"""Plugin-shipped MCP servers, synced plugins and skills, and hostile project content."""

import json
import os
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rigseal import model
from rigseal.cli import app
from rigseal.collectors import claude_code, codex, common
from rigseal.model import CollectError
from rigseal.readers import read_json
from rigseal.rules import scan


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def rows(items, kind):
    return {(i.scope, i.name) for i in items if i.kind == kind}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    for var in ("CODEX_HOME", "RIGSEAL_DIR", "XDG_CACHE_HOME"):
        monkeypatch.delenv(var, raising=False)


# --- item 1: MCP servers that plugins ship ------------------------------------


def test_claude_plugin_mcp_from_mcp_json_and_manifest(tmp_path):
    home = tmp_path
    a = home / ".claude/plugins/cache/m/a/1.0"
    write(a / ".mcp.json", json.dumps({"mcpServers": {"web": {"type": "http", "url": "https://x.io/mcp"}}}))
    b = home / ".claude/plugins/cache/m/b/1.0"
    write(b / ".claude-plugin/plugin.json", json.dumps({"name": "b", "mcpServers": "./servers.json"}))
    write(b / "servers.json", json.dumps({"mcpServers": {"run": {"command": "bash", "args": ["-c", "x"]}}}))
    c = home / ".claude/plugins/cache/m/c/1.0"
    write(c / ".claude-plugin/plugin.json", json.dumps({"mcpServers": {"inline": {"command": "npx", "args": ["pkg"]}}}))
    installs = {f"{n}@m": [{"installPath": str(p), "version": "1.0"}] for n, p in (("a", a), ("b", b), ("c", c))}
    write(home / ".claude/plugins/installed_plugins.json", json.dumps({"plugins": installs}))

    items = claude_code.collect(home, None)
    assert rows(items, "mcp") == {("plugin", "a:web"), ("plugin", "b:run"), ("plugin", "c:inline")}
    assert {(f.rule, f.key) for f in scan(items) if f.rule in ("R2", "R16")} == {
        ("R2", "claude-code/plugin/mcp/b:run"),
        ("R16", "claude-code/plugin/mcp/c:inline"),
    }


def test_manifest_path_cannot_leave_plugin(tmp_path):
    p = tmp_path / "plug"
    write(p / ".claude-plugin/plugin.json", json.dumps({"mcpServers": "../../outside.json"}))
    write(tmp_path / "outside.json", json.dumps({"mcpServers": {"x": {"command": "x"}}}))
    assert common.plugin_mcp("claude-code", p, "plug") == []


def test_synced_plugins_and_skills(tmp_path):
    home = tmp_path
    acct = home / ".claude/plugins/synced/acct-1"
    write(acct / "sales~g2/.claude-plugin/plugin.json", json.dumps({"name": "sales"}))
    write(acct / "sales~g2/.mcp.json", json.dumps({"mcpServers": {"slack": {"type": "http", "url": "https://mcp.slack.com/mcp"}}}))
    write(acct / "uuid-123/.claude-plugin/plugin.json", json.dumps({"name": "productivity"}))
    write(acct / "uuid-123/.in_use/4242", "session")
    write(acct / "sales~g2.meta.json", "{}")
    write(home / ".claude/skills/synced/acct-1/pdf/SKILL.md", "# pdf")
    write(home / ".claude/skills/synced/acct-1/.last-complete-round", "x")

    items = claude_code.collect(home, None)
    assert rows(items, "plugin") == {("plugin", "sales"), ("plugin", "productivity")}
    assert rows(items, "mcp") == {("plugin", "sales:slack")}
    assert rows(items, "skill") == {("synced", "pdf")}
    prod = next(i for i in items if i.name == "productivity")
    assert [f.path for f in prod.files] == [".claude-plugin/plugin.json"]  # session files are not hashed


def test_codex_plugin_mcp(tmp_path):
    home = tmp_path
    write(home / ".codex/config.toml", '[plugins."gh@curated"]\nenabled = true\n')
    write(home / ".codex/plugins/cache/curated/gh/abc123/.mcp.json", json.dumps({"mcpServers": {"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}}}))
    items = codex.collect(home, None)
    [mcp] = [i for i in items if i.kind == "mcp"]
    assert mcp.name == "gh:github" and mcp.details["plugin_enabled"] is True and mcp.details["version"] == "abc123"


# --- item 3: hostile project content -----------------------------------------


def test_project_symlink_to_root_is_not_followed(tmp_path):
    project = tmp_path / "repo"
    (project / ".claude/skills").mkdir(parents=True)
    os.symlink("/", project / ".claude/skills/evil")
    os.symlink("/etc/hostname", project / "CLAUDE.md")
    started = time.monotonic()
    items = claude_code.collect(tmp_path / "home", project)
    assert time.monotonic() - started < 2
    evil = next(i for i in items if i.name == "evil")
    assert evil.files == [] and evil.details == {"link": "/", "outside_project": True}
    claude_md = next(i for i in items if i.name == "CLAUDE.md")
    assert claude_md.details["outside_project"] is True
    assert {(f.rule, f.severity) for f in scan(items)} == {("R12", "high")}


def test_symlink_inside_project_is_followed(tmp_path):
    project = tmp_path / "repo"
    write(project / "shared/pdf/SKILL.md", "# pdf")
    (project / ".claude/skills").mkdir(parents=True)
    os.symlink("../../shared/pdf", project / ".claude/skills/pdf")
    [skill] = [i for i in claude_code.collect(tmp_path / "home", project) if i.kind == "skill"]
    assert [f.path for f in skill.files] == ["SKILL.md"] and "outside_project" not in skill.details


def test_user_scope_symlinks_still_followed(tmp_path):
    home = tmp_path
    write(home / ".agents/skills/docx/SKILL.md", "# docx")
    (home / ".claude/skills").mkdir(parents=True)
    os.symlink("../../.agents/skills/docx", home / ".claude/skills/docx")
    [skill] = [i for i in claude_code.collect(home, None) if i.kind == "skill"]
    assert skill.files and skill.details["link"] == "../../.agents/skills/docx"


def test_tree_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(model, "MAX_TREE_FILES", 5)
    d = tmp_path / "skill"
    for n in range(10):
        write(d / f"f{n}.md", "x")
    item = common.skill_item("claude-code", d, "user")
    assert len(item.files) == 5 and item.details["truncated"] is True
    assert ("R12", "medium") in {(f.rule, f.severity) for f in scan([item])}


def test_fifo_and_huge_config_are_refused(tmp_path, monkeypatch):
    os.mkfifo(tmp_path / ".mcp.json")
    with pytest.raises(CollectError, match="not a regular file"):
        read_json(tmp_path / ".mcp.json")
    monkeypatch.setattr("rigseal.readers.MAX_CONFIG_BYTES", 10)
    write(tmp_path / "big.json", json.dumps({"x": "y" * 50}))
    with pytest.raises(CollectError, match="over"):
        read_json(tmp_path / "big.json")


def test_hostile_repo_check_is_fast_and_fails(tmp_path):
    home, project = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    (project / ".claude/skills").mkdir(parents=True)
    os.symlink("/", project / ".claude/skills/evil")
    started = time.monotonic()
    r = CliRunner().invoke(app, ["check", "--repo", "--home", str(home), "-p", str(project)])
    assert time.monotonic() - started < 3
    assert r.exit_code == 1 and "outside the project" in r.output


# --- item 2: the agent should not approve its own changes ---------------------


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(write(tmp_path / "gitconfig", "[user]\n\temail = dev@example.com\n")))
    home, project = tmp_path / "home", tmp_path / "proj"
    write(home / ".claude/skills/pdf/SKILL.md", "# pdf")
    write(project / ".mcp.json", json.dumps({"mcpServers": {"db": {"command": "db-mcp"}}}))
    return home, project


def cli(env, *args, **kw):
    home, project = env
    return CliRunner().invoke(app, [*args, "--home", str(home), "-p", str(project)], **kw)


def test_approve_without_terminal_is_refused(env, monkeypatch):
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    assert cli(env, "init", "--no-sign").exit_code == 0
    monkeypatch.delenv("RIGSEAL_NONINTERACTIVE")
    write(env[1] / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash"}}}))
    r = cli(env, "approve", "--no-sign")
    assert r.exit_code == 2 and "person at a terminal" in r.output
    assert cli(env, "init", "--no-sign", "--force").exit_code == 2


def test_approve_shows_changes_and_asks(env, monkeypatch):
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    cli(env, "init", "--no-sign")
    monkeypatch.delenv("RIGSEAL_NONINTERACTIVE")
    monkeypatch.setattr("rigseal.cli._interactive", lambda: True)
    write(env[1] / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash", "args": ["-c", "x"]}}}))

    r = cli(env, "approve", "--no-sign", input="n\n")
    assert r.exit_code == 1 and "+ claude-code/project/mcp/evil" in r.output and "R2" in r.output
    assert "evil" not in (env[1] / "rigseal.lock").read_text()
    r = cli(env, "approve", "--no-sign", input="y\n")
    assert r.exit_code == 0 and "evil" in (env[1] / "rigseal.lock").read_text()


def test_signed_lock_cannot_be_silently_downgraded(env, tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    assert cli(env, "init", "--key", str(key)).exit_code == 0
    write(env[1] / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash"}}}))
    r = cli(env, "approve")
    assert r.exit_code == 2 and "would drop the signature" in r.output
    assert cli(env, "init", "--force").exit_code == 2
    assert cli(env, "approve", "--allow-unsigned").exit_code == 0


def test_allowed_signers_makes_signature_required(env, monkeypatch):
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    cli(env, "init", "--no-sign")
    assert cli(env, "check").exit_code == 0
    write(env[1] / ".rigseal/allowed_signers", 'dev@example.com namespaces="rigseal" ssh-ed25519 AAAA\n')
    r = cli(env, "check")
    assert r.exit_code == 1 and "is not signed" in " ".join(r.output.split())


# --- item 4: dogfood log ------------------------------------------------------


def test_dogfood_report_counts_each_pending_change_once(tmp_path, monkeypatch, capsys):
    import importlib.util

    spec = importlib.util.spec_from_file_location("dogfood", Path(__file__).parent.parent / "evals" / "dogfood.py")
    dogfood = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dogfood)
    log = tmp_path / "dogfood.jsonl"
    monkeypatch.setattr(dogfood, "LOG", log)
    plugin = {"key": "claude-code/plugin/plugin/hud", "status": "changed", "reason": "auto-update", "files": 3, "rules": []}
    skill = {"key": "claude-code/user/skill/pdf", "status": "changed", "reason": "user-change", "files": 1, "rules": ["R14"]}
    lines = [
        {"at": "2026-11-01T09:00:00Z", "exit": 1, "changes": [plugin]},
        {"at": "2026-11-02T09:00:00Z", "exit": 1, "changes": [plugin, skill]},  # plugin still pending: not a new event
        {"at": "2026-11-08T09:00:00Z", "exit": 2, "error": "boom"},
    ]
    log.write_text("".join(json.dumps(x) + "\n" for x in lines))
    assert dogfood.report() == 0
    out = capsys.readouterr().out
    assert "3 checks" in out and "7 days), 1 errors" in out
    assert "2 distinct drift events, 2.0 per week" in out
    assert "auto-update     1" in out and "1 events had rule findings" in out
    assert dogfood.classify({"key": "codex/plugin/mcp/gh:github"}) == "auto-update"
