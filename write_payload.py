#!/usr/bin/env python3

# The content you provided (Shellcode + Key 0xAA)
# Notice we use the b"..." syntax to tell Python these are raw bytes
content = (
    b"\xe2\x12\x85\xc8\xc3\xc4\x85\xd9\xc2\xaa\x33\xfa\xfe\xf5\xf8\xcc"
    b"\xc2\x87\xc9\xfe\xf4\xf8\x42\xbb\xaa\xaa\xaa\xcf\xc9\xc2\xc5\x8a"
    b"\xc2\xcf\xc6\xc6\xc5\x8a\xde\xc2\xcf\xd8\xcf\xaa\xfc\xfd\xfe\xf4"
    b"\xc0\x91\xf2\xa5\xaf\xaa"
)

filename = "payload.bin"

print(f"[*] Writing {len(content)} bytes to {filename}...")

# Open in 'wb' mode (Write Binary). This guarantees NO newlines are added.
with open(filename, "wb") as f:
    f.write(content)

print("[+] Success.")