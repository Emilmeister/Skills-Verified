import hashlib
import sys

digest = hashlib.sha256()
while chunk := sys.stdin.buffer.read(65536):
    digest.update(chunk)
print(digest.hexdigest())
