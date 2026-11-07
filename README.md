# rigseal

A lockfile for your AI agent setup. Pin every skill, plugin, hook and MCP server your coding agents load, and see when anything changes. Runs 100% local.

Status: early. Today it inventories Claude Code. Lockfile, diff and other agents come next.

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

## What it reads (Claude Code)

| Kind | Where |
|---|---|
| settings | `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json` |
| mcp | `~/.claude.json` (user + per-project), `.mcp.json` |
| skill | `~/.claude/skills/*/`, `.claude/skills/*/` (every file, dotfiles too) |
| command, agent | `commands/**/*.md`, `agents/**/*.md` (user + project) |
| plugin | `~/.claude/plugins/installed_plugins.json` + each install folder |
| instructions | `~/.claude/CLAUDE.md`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` |

## Develop

```sh
uv sync
uv run pytest
```

## License

Apache-2.0
