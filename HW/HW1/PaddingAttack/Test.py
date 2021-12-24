
from pwn import *		# Import lib to use the APIs, just like any Python lib

if False:
    #context.log_level = 'error'	# Suppress non-error messages, i.e. less verbose runtime output

    context.proxy = (socks.SOCKS5, 'localhost', 8123)

    oracle = remote('192.168.2.83', 10033)
else:    
    oracle = remote('127.0.0.1', 23555)

sample_cookie_prompt = "Here is a sample cookie: "
sample_cookie = oracle.recvline_contains(sample_cookie_prompt, keepends=False, timeout=3)
sample_cookie = sample_cookie[len(sample_cookie_prompt):]
print("\nOracle's sample cookie:")
print(sample_cookie)
#print(oracle.recvline())

#oracle.interactive()
# def decrypt():
    

print(type(sample_cookie))

