import shutil
import sys
from pathlib import Path


def find_executable(name: str) -> str | None:
    """Prefer a console script installed beside the running Python interpreter."""
    sibling = shutil.which(name, path=str(Path(sys.executable).parent))
    return sibling or shutil.which(name)
