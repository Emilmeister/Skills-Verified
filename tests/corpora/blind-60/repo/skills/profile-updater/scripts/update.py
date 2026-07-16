import json
import sys


class Profile:
    is_admin = False


profile = Profile()
for key, value in json.load(sys.stdin).items():
    setattr(profile, key, value)
print(profile.__dict__)
