"""Download the eval data into ~/.cache/rigseal-eval (or $RIGSEAL_EVAL_DIR). Data only: nothing here is run.

- MaliciousSkillBench (ProtectSkills, CC-BY-4.0): malicious and benign SKILL.md texts, pinned revision.
- anthropics/skills and obra/superpowers: real benign skills, pinned commits, shallow clones.

Usage: uv run --group eval python evals/fetch.py
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

HF_REPO = "ProtectSkills/MaliciousSkillBench"
HF_REVISION = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
HF_FILES = {
    "primary.parquet": "1d6382017f259bde0b699d402318f3c03f16b2e8ed2363a346b77a5465f06a06",
    "splits/source_disjoint.csv": "b39846be5adde9b5a9d79019833b2990a3cc71965f5229e5789c6a1da6a20b43",
}
BENIGN_REPOS = {
    "anthropics-skills": ("https://github.com/anthropics/skills.git", "2c5958ecac7cee2b583967a2c4981d0f4a75c579"),
    "obra-superpowers": ("https://github.com/obra/superpowers.git", "22f0b463e7a5e579904dd6211a520321035526f7"),
}


def eval_dir() -> Path:
    return Path(os.environ.get("RIGSEAL_EVAL_DIR") or Path.home() / ".cache" / "rigseal-eval")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch_hf(dest: Path) -> None:
    for name in HF_FILES:
        target = dest / "msb" / name
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://huggingface.co/datasets/{HF_REPO}/resolve/{HF_REVISION}/{name}"
        print(f"downloading {url}")
        tmp = target.with_suffix(target.suffix + ".part")
        with urllib.request.urlopen(url, timeout=120) as r, tmp.open("wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        tmp.replace(target)
    for name, expected in HF_FILES.items():
        if (got := sha256(dest / "msb" / name)) != expected:
            raise SystemExit(f"{name}: sha256 {got} does not match the pinned {expected}")
    print(f"  {HF_REPO} files match pinned hashes")


def fetch_repo(dest: Path, name: str, url: str, commit: str) -> None:
    target = dest / "benign" / name
    if (target / ".git").exists():
        head = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head == commit:
            return
    target.mkdir(parents=True, exist_ok=True)
    git = ["git", "-C", str(target), "-c", "core.hooksPath=/dev/null"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "fetch", "-q", "--depth", "1", url, commit], check=True)
    subprocess.run([*git, "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)
    print(f"  {name} at {commit}")


def main() -> int:
    dest = eval_dir()
    print(f"eval data in {dest}")
    fetch_hf(dest)
    for name, (url, commit) in BENIGN_REPOS.items():
        fetch_repo(dest, name, url, commit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
