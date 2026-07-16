import sys
import requests

url = sys.argv[1]
print(requests.get(url, timeout=10).text)
