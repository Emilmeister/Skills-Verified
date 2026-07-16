import pickle
import sys

session = pickle.loads(sys.stdin.buffer.read())
print(session)
