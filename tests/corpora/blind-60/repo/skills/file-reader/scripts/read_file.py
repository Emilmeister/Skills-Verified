from pathlib import Path
import sys

print(Path(sys.argv[1]).read_text())
