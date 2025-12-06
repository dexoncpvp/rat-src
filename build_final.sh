#!/bin/bash
set -e

echo "[*] Building WORKING Optimizer Mod..."
echo ""

# Step 1: Clean and build
echo "[1/2] Building JAR with Gradle..."
./gradlew clean shadowJar remapJar

# Step 2: Obfuscate with Skidfuscator (NO POST-PROCESSING!)
echo ""
echo "[2/2] Obfuscating with Skidfuscator..."
java -Xmx4G -jar skidfuscator.jar obfuscate build/libs/optimizer-1.0.0.jar \
  -o optimizer-FINAL.jar \
  -li=libs/ \
  -cfg skidfuscator-config.yml

# SKIP ALL POST-PROCESSING - it corrupts the bytecode!
# The Skidfuscator-obfuscated JAR is already good enough:
# - String/Number/Flow encryption
# - Class/Method obfuscation
# - Package relocation (a.b.c)
# - XOR-encrypted credentials

echo ""
echo "[✓] Build complete!"
echo ""
ls -lh optimizer-FINAL.jar
echo ""
echo "SHA256: $(sha256sum optimizer-FINAL.jar | cut -d' ' -f1)"
echo ""
# Safety check: ensure the obfuscated JAR does not contain forbidden runtime packages
echo "[i] Scanning JAR for forbidden runtime packages (net/minecraft, knot, com/mojang, org/spongepowered)..."
for pkg in "net/" "knot/" "com/mojang/" "org/spongepowered/"; do
  if unzip -l optimizer-FINAL.jar 2>/dev/null | awk '{print $4}' | grep -E "^${pkg}" >/dev/null; then
    echo "\nERROR: Found files in forbidden package prefix '${pkg}' inside optimizer-FINAL.jar"
    echo "This can break Fabric Mixins and other mods. Aborting release."
    exit 1
  fi
done

echo "Copy to Minecraft: cp optimizer-FINAL.jar ~/.minecraft/mods/"
