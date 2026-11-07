"""Sign and verify lockfiles with an SSH key, the same way git signs commits (ssh-keygen -Y)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

NAMESPACE = "rigseal"


class SignError(Exception):
    pass


def _git_config(key: str, cwd: Path | None = None) -> str | None:
    try:
        out = subprocess.run(["git", "config", "--get", key], cwd=cwd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    return out.stdout.strip() or None


def identity(cwd: Path | None = None) -> str:
    """Who is approving: git user.email, else the OS user."""
    return _git_config("user.email", cwd) or os.environ.get("USER") or "unknown"


def signing_key(explicit: Path | None, cwd: Path | None = None) -> Path | None:
    """--key, then $RIGSEAL_SIGNING_KEY, then git's SSH user.signingkey. None means sign nothing."""
    if explicit:
        return explicit
    if os.environ.get("RIGSEAL_SIGNING_KEY"):
        return Path(os.environ["RIGSEAL_SIGNING_KEY"]).expanduser()
    if _git_config("gpg.format", cwd) == "ssh" and (key := _git_config("user.signingkey", cwd)):
        if key.startswith("key::"):
            return None  # literal key in config; ssh-agent signing is not supported yet
        return Path(key).expanduser()
    return None


def sign(path: Path, key: Path) -> Path:
    """Write <path>.sig. The key may be the private key or its .pub (ssh-agent then holds the private half)."""
    sig = path.with_name(path.name + ".sig")
    sig.unlink(missing_ok=True)
    out = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-n", NAMESPACE, "-f", str(key), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0 or not sig.exists():
        raise SignError(f"signing {path} with {key} failed: {out.stderr.strip()}")
    return sig


def verify(path: Path, signer: str, allowed_signers: Path) -> None:
    """Raise SignError unless <path>.sig is a valid signature by `signer` listed in allowed_signers."""
    sig = path.with_name(path.name + ".sig")
    if not allowed_signers.is_file():
        raise SignError(f"no allowed signers file at {allowed_signers}")
    with path.open("rb") as data:
        out = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", signer, "-n", NAMESPACE, "-s", str(sig)],
            stdin=data,
            capture_output=True,
            text=True,
            check=False,
        )
    if out.returncode != 0:
        raise SignError(f"bad signature on {path}: {out.stderr.strip() or out.stdout.strip()}")


def allowed_signers_for(default: Path, cwd: Path | None = None) -> Path:
    """`default` if it exists, else git's gpg.ssh.allowedSignersFile, else `default` (verify then fails clearly)."""
    if default.is_file():
        return default
    git_file = _git_config("gpg.ssh.allowedSignersFile", cwd)
    return Path(git_file).expanduser() if git_file else default
