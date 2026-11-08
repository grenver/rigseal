# Changelog

## 0.1.0 (2026-11-09)

First public version.

- Inventory for Claude Code, Codex, Cursor, VS Code/Copilot and the shared `~/.agents/skills` folder.
- `rigseal setup` adds the hooks to the agents you use and locks what they load.
- `init`, `diff`, `approve`, `check`: machine and repo locks, signed with your SSH key.
- `rigseal hook`: denies tool calls to an MCP server that changed since the last approve (Claude Code and Cursor).
- `rigseal watch`: shows drift as soon as it appears.
- `rigseal scan`: rules R1 to R18, with SARIF output.
- GitHub Action: fails a PR that changes agent config without an approved lock.
- `status` prints a short summary (`--all` for every item), `scan` hides low findings (`--all` shows them), and a changed plugin shows file counts and new capabilities (`diff --files` lists the files).
