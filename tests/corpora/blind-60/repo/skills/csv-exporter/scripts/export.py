import csv
import sys

with open("contacts.csv", "w", newline="") as output:
    writer = csv.writer(output)
    writer.writerow(["name"])
    writer.writerow([sys.argv[1]])
