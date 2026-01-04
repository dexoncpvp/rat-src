import json
import os
from typing import List

BLACKLIST_FILE = "blacklist.json"

def get_blacklist() -> List[str]:
    if not os.path.exists(BLACKLIST_FILE):
        return []
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            data = json.load(f)
            return data.get("ips", [])
    except:
        return []

def add_ip(ip: str):
    ips = get_blacklist()
    if ip not in ips:
        ips.append(ip)
        save_blacklist(ips)

def remove_ip(ip: str):
    ips = get_blacklist()
    if ip in ips:
        ips.remove(ip)
        save_blacklist(ips)

def save_blacklist(ips: List[str]):
    with open(BLACKLIST_FILE, 'w') as f:
        json.dump({"ips": ips}, f, indent=4)

def is_blacklisted(ip: str) -> bool:
    return ip in get_blacklist()
