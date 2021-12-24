def pad(s):
  return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

plain = '{"username": "guest", "expires": "2000-01-07", "is_admin": "false"}'

plain_new = '{"username": "guest", "expires": "2030-01-07", "is_admin": "true"}'
IV="This is an IV456"
plain_hex = pad(plain_new.encode("hex"))
x = pad(plain_new).encode("hex")

print(plain_hex)
print(x)