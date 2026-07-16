import sys
import jwt

token = sys.argv[1]
claims = jwt.decode(token, options={"verify_signature": False})
print(claims["sub"])
