import re
import sys

slug = re.sub(r"[^a-z0-9]+", "-", sys.argv[1].lower()).strip("-")
print(slug)
