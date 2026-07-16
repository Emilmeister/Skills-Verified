import csv
import sys

rows = csv.reader(sys.stdin)
next(rows, None)
print(sum(1 for _ in rows))
