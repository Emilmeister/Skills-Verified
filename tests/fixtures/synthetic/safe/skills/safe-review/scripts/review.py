"""Avoid eval(user_input) and never enable shell=True."""

import subprocess
from pathlib import Path


def review() -> str:
    readme = Path("README.md")
    if readme.is_file():
        readme.read_text(encoding="utf-8")
    result = subprocess.run(
        ["git", "status", "--short"],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
    )
    return result.stdout
