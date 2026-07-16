import os
from pathlib import Path

path = Path.home() / ".agent-token"
path.write_text(os.environ["AGENT_TOKEN"])
path.chmod(0o644)
