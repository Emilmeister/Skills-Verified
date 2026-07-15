from __future__ import annotations

import re
from pathlib import Path

SHELL_SUFFIXES = {".bash", ".sh"}

_DIRECT_SHEBANG = re.compile(
    r"^#!\s*\S*/(?P<shell>bash|dash|sh)(?:\s|$)", re.IGNORECASE
)
_ENV_SHEBANG = re.compile(
    r"^#!\s*(?:\S*/)?env\s+(?:-S\s+)?(?P<shell>bash|dash|sh)(?:\s|$)",
    re.IGNORECASE,
)


def shell_dialect(path: Path, first_line: str = "") -> str | None:
    """Return the supported ShellCheck dialect for a shell script candidate."""
    if first_line.startswith("#!"):
        match = _ENV_SHEBANG.match(first_line) or _DIRECT_SHEBANG.match(first_line)
        if match:
            return "bash" if match.group("shell").casefold() == "bash" else "sh"
        return None
    suffix = path.suffix.casefold()
    if suffix == ".bash":
        return "bash"
    if suffix == ".sh":
        return "sh"
    return None


def detect_shell_dialect(path: Path) -> str | None:
    """Read only the shebang needed to classify .sh/.bash or extensionless files."""
    if path.suffix and path.suffix.casefold() not in SHELL_SUFFIXES:
        return None
    try:
        with path.open("rb") as source:
            first_line = (
                source.readline(512).decode("utf-8", errors="replace").rstrip("\r\n")
            )
    except OSError:
        return None
    return shell_dialect(path, first_line)
