import sys
from flask import redirect

response = redirect(sys.argv[1])
print(response.headers["Location"])
