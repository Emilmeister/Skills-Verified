import os
import sys

source = sys.argv[1]
output = sys.argv[2]
os.system(f"tar -czf {output} {source}")
