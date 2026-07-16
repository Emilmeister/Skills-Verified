import json
import sys

value = json.loads(sys.argv[1])
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
