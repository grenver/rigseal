# rigseal

A lockfile for your AI agent setup. Pin every skill, plugin, hook and MCP server your coding agents load, and see when anything changes. Runs 100% local.

Status: early. Today it inventories Claude Code, Codex, Cursor, VS Code/Copilot and the shared `~/.agents/skills` folder. It can lock that state, show drift, and sign the locks with your SSH key.

## Install

```sh
uv tool install git+https://github.com/jayhemnani9910/rigseal
```

## Use

```sh
rigseal status              # inventory for your user config + the current repo
rigseal init                # lock it: ~/.rigseal/machine.lock, and rigseal.lock in the repo
rigseal diff                # what changed since you approved
rigseal approve [KEY...]    # accept changes (all, or just these keys)
rigseal check               # exit 0 clean, 1 drift or bad signature, 2 error
rigseal check --repo --require-signature   # in CI: repo lock only, must be signed
```

`rigseal scan` runs the rules on everything, approved or not, and exits 1 on any HIGH finding (`--fail-on medium|low|never` to change that). `diff` and `check` show the same findings on items that were added or changed.

## Rules

| Rule | Severity | Flags |
|---|---|---|
| R1 | high | an MCP server added, removed or changed without approval |
| R2 | high | MCP server runs inline shell or interpreter code (`bash -c`, `python -c`), pipes a download into a shell, or lives in a temp folder |
| R3 | high | project settings that approve themselves: `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `Bash(*)`, `bypassPermissions`, hooks, `apiKeyHelper`, `*_BASE_URL`/proxy env; Codex `approval_policy = never`, `danger-full-access`, `model_providers`, hooks; Cursor hooks |
| R15 | high | hidden characters: Unicode tags anywhere; bidi and zero-width in instruction files and MCP config |
| R16 | medium | `npx`/`uvx`/`bunx`/`pnpm dlx` package without a pinned version |
| R18 | low/medium | skill, command or agent uses shell or network but `allowed-tools` doesn't declare it |

Each skill, command, agent, rule and plugin also gets a capability summary (shell, network, hosts in code, sensitive paths like `~/.ssh`, `allowed-tools`). It is locked, so `diff` shows lines like `+ host evil.io` or `+ shell`. Vendored folders (`node_modules`, `.venv`, `.git`) are hashed but not read for capabilities. Findings name the pattern that matched, never config values.

`rigseal.lock` holds project-level items and is meant to be committed. The machine lock holds your user-level setup and stays on your laptop. In a fresh clone with no `rigseal.lock`, every project MCP server, skill and hook shows up as new.

**Signing.** `init` and `approve` sign each lock with `ssh-keygen -Y sign` using `--key`, `$RIGSEAL_SIGNING_KEY`, or git's SSH `user.signingkey`. `check` verifies against `.rigseal/allowed_signers` in the repo (or `~/.rigseal/allowed_signers` for the machine lock), in git's allowed-signers format:

```
you@example.com namespaces="rigseal" ssh-ed25519 AAAA...
```

Format details: [docs/lockfile.md](docs/lockfile.md).

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
