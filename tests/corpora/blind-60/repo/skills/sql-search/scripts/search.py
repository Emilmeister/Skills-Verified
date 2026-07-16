import sqlite3
import sys

database = sqlite3.connect("catalog.db")
query = sys.argv[1]
print(database.execute(f"SELECT name FROM skills WHERE name LIKE '%{query}%'").fetchall())
