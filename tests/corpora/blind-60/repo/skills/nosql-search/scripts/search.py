import json
import os
import sys
from pymongo import MongoClient

client = MongoClient(os.environ["MONGODB_URI"])
query = json.load(sys.stdin)
print(list(client.agent.skills.find(query, {"_id": 0, "name": 1})))
