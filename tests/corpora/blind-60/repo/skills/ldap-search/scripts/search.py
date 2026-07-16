import os
import sys
from ldap3 import Connection, Server

server = Server(os.environ["LDAP_HOST"], use_ssl=True)
connection = Connection(server, auto_bind=True)
connection.search(os.environ["LDAP_BASE_DN"], f"(uid={sys.argv[1]})", attributes=["mail"])
print(connection.entries)
