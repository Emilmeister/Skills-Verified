import gzip
import sys

compressed = sys.stdin.buffer.read()
sys.stdout.buffer.write(gzip.decompress(compressed))
