# Threat model

## Who the attacker is

The coding agent itself, after a prompt injection (a poisoned web page, issue, skill or tool description). It runs as **your user**, with your shell. It can read and write anything you can: your home folder, `~/.rigseal/`, the repo, and any SSH key file that isn't locked behind a passphrase or an agent prompt.

The second attacker is **a repo you clone**: its `.mcp.json`, `.claude/settings.json`, skills and hooks arrive with the code.

## What rigseal does about it

| Threat | What rigseal does | Limit |
|---|---|---|
| A cloned repo adds an MCP server, hook or skill | `rigseal check --repo` in CI, or before you start the agent, shows it as `added` with rule findings (R1–R3) | Only if you run it before the agent loads the config |
| A repo links a skill to `/` or `~/.ssh` to stall or leak | Project links that leave the repo are recorded, not followed (R12, high). Folders are capped at 20,000 files / 500 MB; configs at 10 MB; FIFOs refused | |
| The agent edits a skill, plugin or MCP config | The file hash changes, so `check` reports drift | rigseal must run after the change and before the next session |
| The agent runs `rigseal approve` to accept its own change | `approve` and `init` refuse without a terminal; at a terminal `approve` shows the changes and asks | An agent can set `RIGSEAL_NONINTERACTIVE=1` or fake a terminal. This is a speed bump, not a wall |
| The agent drops the signature (`approve --no-sign`) | Refused while the lock is signed, unless `--allow-unsigned` | Same: the agent can pass the flag |
| The agent edits the lock directly | A signed lock no longer verifies; `check` fails. A lock whose `.sig` was deleted fails. If `allowed_signers` exists, an unsigned lock fails | Only if the agent can't sign. See below |
| A repo writer adds their own key to `.rigseal/allowed_signers` | The repo lock must also pass a list from outside the repo (`--allowed-signers`, `$RIGSEAL_ALLOWED_SIGNERS`, `~/.rigseal/allowed_signers`). `--require-signature` fails without one. The Action uses the base branch's list on a PR | With no outside list, deleting the signature and the repo's list together goes unnoticed unless `--require-signature` is on |
| The agent signs with your key | Nothing in rigseal can stop this if the key is readable and has no passphrase | Use one of the setups below |

## What actually makes approvals trustworthy

Signing only means something if **the agent cannot make a valid signature**. Pick one:

1. **ssh-agent with confirmation.** Load the key with `ssh-add -c ~/.ssh/id_ed25519_signing`. Every signature then pops up a dialog (needs `ssh-askpass`) that a person has to click. Point rigseal at the public key (`--key ~/.ssh/id_ed25519_signing.pub`) so it signs through the agent.
2. **A hardware key** (`ed25519-sk` on a YubiKey or similar): every signature needs a touch.
3. **Approve in CI, not on the laptop**, for the repo lock: commit `rigseal.lock` and `.rigseal/allowed_signers`, and run `rigseal check --repo --require-signature --allowed-signers <list from outside the PR>` in CI (the GitHub Action does this with the base branch's list). Changes to the lock then go through code review like any other change.

A passphrase on the key file helps only until the agent sees you type it, or reads it from a keyring it can reach.

## What rigseal does not do

- It does not watch in real time yet. Until `rigseal watch` and the agent hooks exist (plan: week 7), a change is caught at the next `check`.
- It does not see claude.ai connectors (Gmail, Drive and others): they are set up on your account, not on disk.
- It does not stop an attacker who already has your user and a usable signing key. Nothing on the same machine can; that needs approvals somewhere the agent can't reach (option 3).
- Detection rules are a helper. On the public benchmark they catch a small share of malicious skills (see [eval.md](eval.md)). The lock is what catches every change.
