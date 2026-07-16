from pathlib import Path
import sys

workspace = Path("workspace").resolve()
requested = Path("workspace") / sys.argv[1]
if requested.resolve().is_relative_to(workspace):
    print(requested.read_text())
