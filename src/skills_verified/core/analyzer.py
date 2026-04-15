import shutil
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from skills_verified.core.models import Finding

# Directory containing the current Python interpreter (e.g. .venv/bin/).
# Tools installed in the same venv live here but may not be on system PATH.
# Use parent of sys.executable WITHOUT resolving symlinks so that
# .venv/bin/python -> /usr/bin/python3 still yields .venv/bin/.
_BIN_DIR = str(Path(sys.executable).parent)


def find_tool(name: str) -> str | None:
    """Locate an external CLI tool, checking the venv bin dir first."""
    venv_candidate = Path(_BIN_DIR) / name
    if venv_candidate.is_file():
        return str(venv_candidate)
    return shutil.which(name)


class Analyzer(ABC):
    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this analyzer can run (tools installed, etc.)."""

    @abstractmethod
    def analyze(self, repo_path: Path) -> list[Finding]:
        """Run analysis on the repo and return findings."""
