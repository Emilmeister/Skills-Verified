import sys
from urllib.parse import urlparse

allowed_hosts = {"api.example.com", "docs.example.com"}
parsed = urlparse(sys.argv[1])
if parsed.scheme != "https" or parsed.hostname not in allowed_hosts or parsed.username is not None:
    raise SystemExit("invalid service URL")
print("valid")
