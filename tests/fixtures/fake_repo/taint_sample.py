import os
import shlex
import subprocess
import urllib.request


def cmd_injection_vuln():
    user = input("cmd? ")
    subprocess.run(user, shell=True)  # sink: command injection


def ssrf_vuln():
    target = os.environ.get("TARGET_URL")
    urllib.request.urlopen(target)  # sink: SSRF


def path_traversal_vuln():
    filename = input("file? ")
    path = "/tmp/" + filename
    open(path, "r")  # sink: path traversal


def safe_shell_call():
    user = input("cmd? ")
    subprocess.run(shlex.quote(user), shell=True)  # sanitized — should not fire


def safe_constant_call():
    subprocess.run("ls", shell=True)  # no tainted input — should not fire
