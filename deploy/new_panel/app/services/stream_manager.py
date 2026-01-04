from datetime import datetime
from typing import Dict, Any

class StreamManager:
    def __init__(self):
        # {player_name: {'sid': str, 'type': str, 'fps': int, 'quality': int, 'last_frame': datetime}}
        self.active_streams: Dict[str, Any] = {}

    def register_guardian(self, player: str, sid: str):
        self.active_streams[player] = {
            'sid': sid,
            'connected_at': datetime.now(),
            'streaming': False
        }

    def update_stream_stats(self, player: str, stream_type: str, fps: int, quality: int):
        if player in self.active_streams:
            self.active_streams[player].update({
                'streaming': True,
                'type': stream_type,
                'fps': fps,
                'quality': quality,
                'last_frame': datetime.now()
            })

    def get_stats(self, player: str):
        return self.active_streams.get(player)

    def remove_guardian(self, sid: str):
        # Find player by sid
        player_to_remove = None
        for player, data in self.active_streams.items():
            if data['sid'] == sid:
                player_to_remove = player
                break
        
        if player_to_remove:
            del self.active_streams[player_to_remove]
            return player_to_remove
        return None

stream_manager = StreamManager()
