import subprocess

result = subprocess.run(["git", "--version"], check=True, capture_output=True, text=True)
print(result.stdout.strip())
