import sqlite3
import sys

database = sqlite3.connect("accounts.db")
account_id = sys.argv[1]
row = database.execute("SELECT email, plan FROM accounts WHERE id = ?", (account_id,)).fetchone()
print(row)
