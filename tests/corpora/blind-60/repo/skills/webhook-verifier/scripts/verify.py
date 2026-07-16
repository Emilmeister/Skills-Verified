import hashlib
import hmac
import os
import sys

payload = sys.stdin.buffer.read()
expected = hmac.new(os.environ["WEBHOOK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()
provided = sys.argv[1]
print(provided == expected)
