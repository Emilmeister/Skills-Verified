import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = bytes.fromhex(os.environ["RECORD_AES_KEY"])
cipher = AES.new(key, AES.MODE_ECB)
sys.stdout.buffer.write(cipher.encrypt(pad(sys.stdin.buffer.read(), AES.block_size)))
