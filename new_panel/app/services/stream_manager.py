from datetime import datetime
from typing import Dict, Any, Optional
import asyncio

class StreamManager:
    def __init__(self):
        # Guardian connections: {player_name: {'sid': str, 'user_id': int, 'type': str, 'fps': int, 'quality': int, 'last_frame': datetime}}
        self.active_streams: Dict[str, Any] = {}
        
        # Viewer connections: {sid: {'player': str, 'type': str, 'user_id': int}}
        self.viewers: Dict[str, Any] = {}
        
        # Frame buffers for smooth streaming: {room: {'frame': bytes, 'timestamp': datetime}}
        self.frame_buffers: Dict[str, Any] = {}

    def register_guardian(self, player: str, sid: str, user_id: int = None, build_key: str = None):
        """Register a guardian connection"""
        self.active_streams[player] = {
            'sid': sid,
            'user_id': user_id,
            'build_key': build_key,
            'connected_at': datetime.now(),
            'streaming': False,
            'last_frame': None,
            'frame_count': 0
        }
        return True

    def update_stream_stats(self, player: str, stream_type: str, fps: int, quality: int):
        """Update stream statistics"""
        if player in self.active_streams:
            self.active_streams[player].update({
                'streaming': True,
                'type': stream_type,
                'fps': fps,
                'quality': quality,
                'last_frame': datetime.now(),
                'frame_count': self.active_streams[player].get('frame_count', 0) + 1
            })

    def store_frame(self, player: str, stream_type: str, frame_data: str):
        """Store latest frame in buffer and on disk for persistence"""
        room = f"{stream_type}_{player}"
        self.frame_buffers[room] = {
            'frame': frame_data,
            'timestamp': datetime.now()
        }
        
        # Save to disk
        try:
            import os
            import base64
            
            # Path: new_panel/static/previews
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            static_dir = os.path.join(base_dir, "static", "previews")
            os.makedirs(static_dir, exist_ok=True)
            
            file_path = os.path.join(static_dir, f"{stream_type}_{player}.jpg")
            
            # Decode if it's base64 (handle data:image/png;base64 prefix)
            b64_str = frame_data
            if "," in b64_str:
                b64_str = b64_str.split(",")[1]
                
            with open(file_path, "wb") as f:
                f.write(base64.b64decode(b64_str))
                
        except Exception as e:
            print(f"Error saving preview to disk: {e}")

    def get_latest_frame(self, player: str, stream_type: str) -> Optional[str]:
        """Get latest frame from buffer"""
        room = f"{stream_type}_{player}"
        buffer = self.frame_buffers.get(room)
        if buffer:
            return buffer.get('frame')
        return None

    def get_stats(self, player: str) -> Optional[dict]:
        """Get stream stats for a player"""
        return self.active_streams.get(player)

    def get_guardian_user_id(self, player: str) -> Optional[int]:
        """Get user_id that owns this guardian"""
        if player in self.active_streams:
            return self.active_streams[player].get('user_id')
        return None

    def register_viewer(self, sid: str, player: str, stream_type: str, user_id: int):
        """Register a panel viewer"""
        self.viewers[sid] = {
            'player': player,
            'type': stream_type,
            'user_id': user_id,
            'joined_at': datetime.now()
        }

    def unregister_viewer(self, sid: str):
        """Unregister a panel viewer"""
        if sid in self.viewers:
            del self.viewers[sid]

    def get_viewer_info(self, sid: str) -> Optional[dict]:
        """Get viewer info"""
        return self.viewers.get(sid)

    def remove_guardian(self, sid: str) -> Optional[str]:
        """Remove guardian by socket ID"""
        player_to_remove = None
        for player, data in self.active_streams.items():
            if data['sid'] == sid:
                player_to_remove = player
                break
        
        if player_to_remove:
            del self.active_streams[player_to_remove]
            # Clean up frame buffers
            for stream_type in ['screen', 'webcam']:
                room = f"{stream_type}_{player_to_remove}"
                if room in self.frame_buffers:
                    del self.frame_buffers[room]
            return player_to_remove
        return None

    def remove_guardian_by_player(self, player: str):
        """Remove guardian by player name"""
        if player in self.active_streams:
            del self.active_streams[player]
            # Clean up frame buffers
            for stream_type in ['screen', 'webcam']:
                room = f"{stream_type}_{player}"
                if room in self.frame_buffers:
                    del self.frame_buffers[room]

    def get_all_players_for_user(self, user_id: int, is_admin: bool = False) -> list:
        """Get all players owned by a user (or all if admin)"""
        result = []
        for player, data in self.active_streams.items():
            if is_admin or data.get('user_id') == user_id:
                result.append({
                    'name': player,
                    'streaming': data.get('streaming', False),
                    'type': data.get('type'),
                    'connected_at': data.get('connected_at')
                })
        return result

    def can_user_access_stream(self, user_id: int, player: str, is_admin: bool = False) -> bool:
        """Check if user can access this stream"""
        if is_admin:
            return True
        if player in self.active_streams:
            owner_id = self.active_streams[player].get('user_id')
            # Type-safe comparison
            if str(owner_id) == str(user_id):
                return True
            print(f"DEBUG: Stream Access Denied. Player={player}, Owner={owner_id} ({type(owner_id)}), RequestUser={user_id} ({type(user_id)})")
        else:
             print(f"DEBUG: Stream Access Denied. Player {player} not in active_streams. Keys: {list(self.active_streams.keys())}")
        return False

stream_manager = StreamManager()
