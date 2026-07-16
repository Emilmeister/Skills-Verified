from pathlib import Path
import re
import sys
import tempfile

name = sys.argv[1]
if re.fullmatch(r"[a-z0-9-]+", name) is None:
    raise SystemExit("invalid note name")
workspace = Path("workspace")
workspace.mkdir(mode=0o700, exist_ok=True)
with tempfile.NamedTemporaryFile("w", dir=workspace, prefix=f"{name}-", suffix=".txt", delete=False) as note:
    note.write(sys.stdin.read())
print(note.name)
