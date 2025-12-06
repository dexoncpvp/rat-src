#!/bin/bash

echo "🔐 Skidfuscator Obfuscation Setup"
echo "=================================="

# Check if Skidfuscator is already downloaded
if [ ! -f "skidfuscator.jar" ]; then
    echo "📥 Downloading Skidfuscator..."
    
    # Get latest release
    LATEST_RELEASE=$(curl -s https://api.github.com/repos/skidfuscatordev/skidfuscator-java-obfuscator/releases/latest | grep "browser_download_url.*jar" | cut -d '"' -f 4 | head -1)
    
    if [ -z "$LATEST_RELEASE" ]; then
        echo "❌ Could not find Skidfuscator release"
        echo "📝 Manual download: https://github.com/skidfuscatordev/skidfuscator-java-obfuscator/releases"
        echo "   Place skidfuscator.jar in: $(pwd)"
        exit 1
    fi
    
    wget -O skidfuscator.jar "$LATEST_RELEASE"
    echo "✅ Skidfuscator downloaded!"
else
    echo "✅ Skidfuscator already exists"
fi

# Create Skidfuscator config
cat > skidfuscator-config.yml << 'EOF'
# Skidfuscator Configuration for Minecraft Mod
version: 3

# Phantom classes (don't exist but confuse decompilers)
phantom:
  enabled: true
  count: 50

# Flow obfuscation (makes control flow hard to understand)
flow:
  enabled: true
  intensity: high

# String encryption
string:
  enabled: true
  algorithm: AES

# Number mutation
number:
  enabled: true

# Reference obfuscation
reference:
  enabled: true

# Outlining (extract code to new methods)
outlining:
  enabled: true
  intensity: high

# Exception obfuscation
exception:
  enabled: true

# Anti-debug
debug:
  enabled: true

# Anti-tamper
tamper:
  enabled: true

# Exclusions (don't obfuscate Minecraft/Fabric classes)
exclusions:
  - "net/minecraft/**"
  - "net/fabricmc/**"
  - "com/mojang/**"
  - "org/slf4j/**"
EOF

echo "✅ Skidfuscator config created: skidfuscator-config.yml"

# Create obfuscation script
cat > obfuscate.sh << 'SCRIPT'
#!/bin/bash

echo "🔐 Starting Obfuscation Process..."
echo "==================================="

# Step 1: Build the mod
echo "📦 Step 1: Building mod..."
./gradlew clean shadowJar
if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

# Find the jar file
JAR_FILE=$(find build/libs -name "*-shadow.jar" | head -1)

if [ -z "$JAR_FILE" ]; then
    echo "❌ No shadow jar found!"
    exit 1
fi

echo "✅ Found jar: $JAR_FILE"

# Step 2: Run Skidfuscator
echo "🔐 Step 2: Running Skidfuscator obfuscation..."

if [ ! -f "skidfuscator.jar" ]; then
    echo "❌ skidfuscator.jar not found!"
    echo "Run ./setup_skidfuscator.sh first"
    exit 1
fi

java -jar skidfuscator.jar \
    -cp "$JAR_FILE" \
    -i "$JAR_FILE" \
    -o "build/libs/optimizer-1.0.0-obfuscated.jar" \
    -cfg skidfuscator-config.yml \
    -verbose

if [ $? -ne 0 ]; then
    echo "❌ Obfuscation failed!"
    exit 1
fi

echo "✅ Obfuscation complete!"

# Step 3: Remap with Fabric Loom
echo "🔄 Step 3: Remapping for Fabric..."
cp build/libs/optimizer-1.0.0-obfuscated.jar build/libs/optimizer-1.0.0.jar
./gradlew remapJar

echo ""
echo "✅ COMPLETE! Obfuscated mod ready:"
echo "   📍 build/libs/optimizer-1.0.0.jar"
echo "   📦 Size: $(du -h build/libs/optimizer-1.0.0.jar | cut -f1)"
echo ""
echo "🎯 Features:"
echo "   ✔ Shadow JAR (all dependencies included)"
echo "   ✔ Skidfuscator obfuscation (flow, strings, numbers)"
echo "   ✔ Phantom classes (50+ fake classes)"
echo "   ✔ Anti-debug & anti-tamper"
echo "   ✔ Base64 encoded Telegram credentials"
echo ""
SCRIPT

chmod +x obfuscate.sh

echo ""
echo "✅ Setup Complete!"
echo ""
echo "📋 Next Steps:"
echo "   1. Build and obfuscate:  ./obfuscate.sh"
echo "   2. Or manual build:      ./gradlew clean shadowJar"
echo "   3. Then obfuscate:       java -jar skidfuscator.jar -i build/libs/*-shadow.jar -o output.jar"
echo ""
echo "📁 Files created:"
echo "   • skidfuscator.jar - Obfuscator"
echo "   • skidfuscator-config.yml - Configuration"
echo "   • obfuscate.sh - Complete build & obfuscate script"
echo ""
