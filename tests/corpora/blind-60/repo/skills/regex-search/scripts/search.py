import re
import sys

pattern = sys.argv[1]
document = sys.stdin.read()
print(bool(re.search(pattern, document)))
