# rigseal

A lockfile for your AI agent setup. Pin every skill, plugin, hook and MCP server your coding agents load, and see when anything changes. Runs 100% local.

Status: early. Today it inventories Claude Code, Codex, Cursor, VS Code/Copilot and the shared `~/.agents/skills` folder. Lockfile and diff come next.

## Install

```sh
uv tool install git+https://github.com/jayhemnani9910/rigseal
```

## Use

```sh
rigseal status              # inventory for your user config + the current repo
rigseal status --json       # same, as JSON
rigseal status -p ../other  # inventory for another project
```

rigseal only reads files. It never runs MCP servers, and it never prints secret values: env vars, args and headers are hashed, and only their key names are shown.

## What it reads

| Agent | Where |
|---|---|
| Claude Code | `~/.claude/settings.json`, `.claude/settings{,.local}.json`, `~/.claude.json` (user + per-project MCP), `.mcp.json`, `skills/*/`, `commands/**/*.md`, `agents/**/*.md`, `~/.claude/plugins/installed_plugins.json` + install folders, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` |
| Codex | `~/.codex/config.toml` (or `$CODEX_HOME`) and `.codex/config.toml`: settings, `mcp_servers`, hooks; `skills/*/` incl. `.system/`; `plugins/cache/<market>/<plugin>/`; `rules/*.rules`; `AGENTS.md` |
| Cursor | `~/.cursor/` and `.cursor/`: `mcp.json`, `hooks.json`, `skills/*/`, `rules/**/*.mdc`; `.cursorrules` |
| VS Code / Copilot | VS Code user `mcp.json` + `prompts/` (Linux and macOS paths), `.vscode/mcp.json`, `.github/copilot-instructions.md`, `.github/{instructions,prompts}/`, `.github/skills/`; `~/.copilot/mcp-config.json`, `skills/`, `installed-plugins/` |
| Shared | `~/.agents/skills/*/`, `.agents/skills/*/` |

Skill folders are hashed file by file, dotfiles included. Symlinked skills are listed under each agent that loads them, with the link target shown. JSON files with comments (VS Code, Copilot) are read too.

## Develop

```sh
uv sync
uv run pytest
```

## License

Apache-2.0
