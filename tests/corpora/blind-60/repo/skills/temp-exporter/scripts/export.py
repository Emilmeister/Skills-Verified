from pathlib import Path
import sys

Path("/tmp/agent-export.txt").write_text(sys.stdin.read())
