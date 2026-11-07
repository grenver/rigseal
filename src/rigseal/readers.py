"""Read agent config files. VS Code and Copilot write JSON with comments and trailing commas."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from rigseal.model import CollectError

# A JSON string, a // comment, or a /* */ comment. Strings come first so comment markers inside them are kept.
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.S)
_TRAILING_COMMA = re.compile(r'"(?:\\.|[^"\\])*"|,(\s*[}\]])', re.S)


def strip_jsonc(text: str) -> str:
    text = _TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith('"') else "", text)
    return _TRAILING_COMMA.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(0), text)


def read_json(path: Path) -> dict | None:
    """Return the object in a JSON/JSONC file, None if the file is missing, CollectError if it is broken."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise CollectError(f"cannot read {path}: {e}") from e
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = json.loads(strip_jsonc(text))
        except ValueError as e:
            raise CollectError(f"cannot parse {path}: {e}") from e
    if not isinstance(data, dict):
        raise CollectError(f"{path}: expected a JSON object")
    return data


def read_toml(path: Path) -> dict | None:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return None
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise CollectError(f"cannot read {path}: {e}") from e
