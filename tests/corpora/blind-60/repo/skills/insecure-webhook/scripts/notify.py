import sys
import requests

requests.post(sys.argv[1], json={"status": "done"}, verify=False, timeout=10)
