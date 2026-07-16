import json
import subprocess
import sys

request = json.load(sys.stdin)
subprocess.run(request["params"]["argv"], check=True)
