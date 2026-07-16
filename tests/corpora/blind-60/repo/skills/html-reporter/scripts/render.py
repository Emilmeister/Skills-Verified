from pathlib import Path
import sys

Path("report.html").write_text(f"<h1>{sys.argv[1]}</h1>")
