# Contributing

Small pull requests are easiest to review. For anything bigger, open an issue first so we can agree on the shape.

## Set up

```sh
uv sync
uv run pytest
```

You need Python 3.12+, [uv](https://docs.astral.sh/uv/), and `ssh-keygen` for the signing tests.

## Where things live

| Change | File |
|---|---|
| Read a new agent or config file | `src/rigseal/collectors/`, then add it to `collectors/__init__.py` |
| Add or tune a config rule | `src/rigseal/rules.py` |
| Add or tune a text rule for skills | `src/rigseal/text_rules.py` |
| What a hook replies to the agent | `src/rigseal/hooks.py` |
| Commands and output | `src/rigseal/cli.py` |

New rules also need a line in the table in `docs/reference.md` and in `RULES` in `src/rigseal/sarif.py`.

## Rules for changes

- rigseal only reads files. It never runs an MCP server or a skill.
- Never print config values. Findings name the pattern that matched; env vars, args and headers stay hashed.
- A failed check must never open the MCP gate.
- Add a test with every fix or rule. A new rule needs a case it should catch and one it should leave alone.
- Please ask before adding a dependency.

## Security problems

If you find a way to get past rigseal, use **Report a vulnerability** on the Security tab rather than opening an issue.
