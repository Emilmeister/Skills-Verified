import sys
from urllib.request import urlopen

code = urlopen(sys.argv[1]).read()
exec(compile(code, "<remote-plugin>", "exec"))
