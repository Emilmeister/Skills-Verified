from pathlib import Path
import sys

workspace = Path(sys.argv[1])
relative_name = sys.argv[2]
(workspace / relative_name).write_text(sys.stdin.read())
