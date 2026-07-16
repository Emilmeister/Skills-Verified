import hashlib
import sys

print(hashlib.md5(sys.stdin.buffer.read()).hexdigest())
