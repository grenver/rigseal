import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rigseal import cli as cli_module
from rigseal.cli import app

run = CliRunner().invoke


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    for var in ("CODEX_HOME", "RIGSEAL_DIR", "RIGSEAL_SIGNING_KEY", "XDG_CACHE_HOME"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("RIGSEAL_NONINTERACTIVE", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setattr(cli_module.shutil, "which", lambda name: f"/bin/{name}")
    write(tmp_path / "gitconfig", "[user]\n\temail = dev@example.com\n")


@pytest.fixture
def env(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    write(home / ".claude/settings.json", json.dumps({"theme": "dark", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}]}}))
    write(home / ".cursor/mcp.json", json.dumps({"mcpServers": {}}))
    write(project / ".mcp.json", json.dumps({"mcpServers": {"db": {"command": "db-mcp"}}}))
    return home, project


def cli(env, *args):
    home, project = env
    return run(app, [*args, "--home", str(home), "-p", str(project)])


def settings(home):
    return json.loads((home / ".claude/settings.json").read_text())


def test_setup_adds_hooks_keeps_settings_and_locks(env):
    home, project = env
    r = cli(env, "setup", "--no-sign")
    assert r.exit_code == 0, r.output
    doc = settings(home)
    assert doc["theme"] == "dark"
    assert doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "mine"
    assert doc["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == "rigseal hook claude-code"
    assert set(doc["hooks"]) == {"SessionStart", "PreToolUse", "ConfigChange"}
    assert json.loads((home / ".cursor/hooks.json").read_text())["hooks"]["beforeMCPExecution"][0]["failClosed"] is True
    assert (home / ".rigseal/machine.lock").exists() and (project / "rigseal.lock").exists()
    assert cli(env, "check").exit_code == 0  # the new hooks are part of the lock


def test_setup_twice_changes_nothing(env):
    home, _ = env
    cli(env, "setup", "--no-sign")
    before = (home / ".claude/settings.json").read_text()
    r = cli(env, "setup", "--no-sign")
    assert r.exit_code == 0 and "already set up" in r.output
    assert (home / ".claude/settings.json").read_text() == before


def test_setup_skips_agents_that_are_not_installed(env):
    home, _ = env
    shutil.rmtree(home / ".cursor")
    assert cli(env, "setup", "--no-sign").exit_code == 0
    assert not (home / ".cursor").exists()


def test_setup_does_not_approve_existing_drift(env):
    _, project = env
    cli(env, "init", "--no-sign")
    write(project / ".mcp.json", json.dumps({"mcpServers": {"db": {"command": "evil"}}}))
    r = cli(env, "setup", "--no-sign")
    assert r.exit_code == 0 and "rigseal approve" in r.output
    found = {c["key"] for c in json.loads(cli(env, "check", "--json").stdout)["changes"]}
    assert "claude-code/project/mcp/db" in found


def test_setup_on_a_fresh_clone_leaves_the_repo_lock_alone(env):
    home, project = env
    cli(env, "init", "--no-sign")
    (home / ".rigseal/machine.lock").unlink()
    write(project / ".mcp.json", json.dumps({"mcpServers": {"db": {"command": "evil"}}}))
    before = (project / "rigseal.lock").read_text()
    assert cli(env, "setup", "--no-sign").exit_code == 0
    assert (project / "rigseal.lock").read_text() == before
    assert (home / ".rigseal/machine.lock").exists()
    assert "claude-code/project/mcp/db" in {c["key"] for c in json.loads(cli(env, "check", "--json").stdout)["changes"]}


def test_setup_refuses_a_file_it_cannot_rewrite(env):
    home, _ = env
    text = '{"theme": "dark", // mine\n}'
    write(home / ".claude/settings.json", text)
    assert cli(env, "setup", "--no-sign").exit_code == 2
    assert (home / ".claude/settings.json").read_text() == text
    assert not (home / ".rigseal/machine.lock").exists()


def test_setup_needs_a_person(env, monkeypatch):
    home, _ = env
    monkeypatch.delenv("RIGSEAL_NONINTERACTIVE")
    before = (home / ".claude/settings.json").read_text()
    assert cli(env, "setup", "--no-sign", "--yes").exit_code == 2
    assert (home / ".claude/settings.json").read_text() == before


def test_setup_needs_rigseal_on_path(env, monkeypatch):
    home, _ = env
    monkeypatch.setattr(cli_module.shutil, "which", lambda _: None)
    before = (home / ".claude/settings.json").read_text()
    r = cli(env, "setup", "--no-sign")
    assert r.exit_code == 2 and "PATH" in r.output
    assert (home / ".claude/settings.json").read_text() == before


def test_setup_keeps_a_symlinked_settings_file(env, tmp_path):
    home, _ = env
    real = tmp_path / "dotfiles" / "settings.json"
    write(real, json.dumps({"theme": "light"}))
    (home / ".claude/settings.json").unlink()
    (home / ".claude/settings.json").symlink_to(real)
    assert cli(env, "setup", "--no-sign").exit_code == 0
    assert (home / ".claude/settings.json").is_symlink()
    assert "SessionStart" in json.loads(real.read_text())["hooks"]


def test_status_is_a_summary_and_all_lists_items(env):
    r = cli(env, "status")
    assert r.exit_code == 0
    assert "not set up" in r.output and "db" not in r.output.replace("db-mcp", "")
    assert "claude-code/project" not in r.output
    cli(env, "setup", "--no-sign")
    r = cli(env, "status")
    assert "0 changed" in r.output and "claude-code on" in r.output and "cursor on" in r.output
    assert "db" in cli(env, "status", "--all").output


def test_status_counts_drift(env):
    _, project = env
    cli(env, "setup", "--no-sign")
    write(project / ".mcp.json", json.dumps({"mcpServers": {"db": {"command": "evil"}}}))
    r = cli(env, "status")
    assert r.exit_code == 0 and "1 changed" in r.output


def test_scan_hides_low_unless_asked(env):
    home, _ = env
    write(home / ".claude/skills/net/SKILL.md", "# net\n\n```bash\ncurl https://example.com/x\n```\n")
    r = cli(env, "scan")
    assert "R18" not in r.output and "low hidden" in r.output
    assert "R18" in cli(env, "scan", "--all").output
    r = cli(env, "scan", "--fail-on", "low")
    assert r.exit_code == 1 and "R18" in r.output  # never fail on something it didn't show


def test_plugin_update_is_summed_up(env):
    home, _ = env
    folder = home / ".claude/plugins/cache/hud"
    write(folder / "a.md", "one")
    write(folder / "b.md", "two")
    write(home / ".claude/plugins/installed_plugins.json", json.dumps({"plugins": {"hud@m": [{"installPath": str(folder), "version": "1"}]}}))
    cli(env, "init", "--no-sign")
    write(folder / "a.md", "one more")
    write(folder / "b.md", "curl https://evil.example.net/x")
    r = cli(env, "diff")
    assert "files: 2 changed" in r.output and "changed: a.md" not in r.output
    assert "changed: a.md" in cli(env, "diff", "--files").output


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_setup_with_a_signing_key_verifies_itself(env, tmp_path):
    home, project = env
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "dev@example.com", "-f", str(key)], check=True)
    assert cli(env, "setup", "--key", str(key)).exit_code == 0
    assert (project / "rigseal.lock.sig").is_file()
    assert "dev@example.com" in (home / ".rigseal/allowed_signers").read_text()
    assert cli(env, "check").exit_code == 0
    assert "0 changed" in cli(env, "status").output


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_setup_keeps_an_existing_signer_list(env, tmp_path):
    home, _ = env
    write(home / ".rigseal/allowed_signers", "someone@example.com ssh-ed25519 AAAA\n")
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    cli(env, "setup", "--key", str(key))
    assert (home / ".rigseal/allowed_signers").read_text() == "someone@example.com ssh-ed25519 AAAA\n"
