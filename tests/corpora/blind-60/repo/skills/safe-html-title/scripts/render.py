from html import escape
import sys

print(f"<h1>{escape(sys.argv[1], quote=True)}</h1>")
