import socketio
from app.services.stream_manager import stream_manager

def register_socket_events(sio: socketio.AsyncServer):
    
    @sio.event
    async def connect(sid, environ):
        print(f"Client connected: {sid}")

    @sio.event
    async def disconnect(sid):
        print(f"Client disconnected: {sid}")
        player = stream_manager.remove_guardian(sid)
        if player:
            print(f"Guardian disconnected: {player}")

    @sio.event
    async def guardian_connect(sid, data):
        player = data.get('player', '')
        if player:
            stream_manager.register_guardian(player, sid)
            print(f"Guardian registered: {player}")
            await sio.emit('guardian_registered', {'status': 'ok', 'player': player}, room=sid)

    @sio.event
    async def join_stream(sid, data):
        player = data.get('player', '')
        stream_type = data.get('type', 'screen')
        room = f"{stream_type}_{player}"
        sio.enter_room(sid, room)
        print(f"Panel joined stream room: {room}")
        await sio.emit('stream_joined', {'room': room, 'player': player}, room=sid)

    @sio.event
    async def leave_stream(sid, data):
        player = data.get('player', '')
        stream_type = data.get('type', 'screen')
        room = f"{stream_type}_{player}"
        sio.leave_room(sid, room)

    @sio.event
    async def stream_frame(sid, data):
        # Broadcast frame to room
        player = data.get('player')
        if not player: return

        stream_type = data.get('type', 'screen')
        room = f"{stream_type}_{player}"
        
        # Update stats
        stream_manager.update_stream_stats(
            player, 
            stream_type, 
            data.get('fps', 30), 
            data.get('quality', 85)
        )

        # Broadcast
        await sio.emit('frame', data, room=room, skip_sid=sid)

    @sio.event
    async def start_stream(sid, data):
        player = data.get('player', '')
        # Find guardian SID
        stats = stream_manager.get_stats(player)
        if stats and 'sid' in stats:
            await sio.emit('start_capture', data, room=stats['sid'])

    @sio.event
    async def stop_stream(sid, data):
        player = data.get('player', '')
        stats = stream_manager.get_stats(player)
        if stats and 'sid' in stats:
            await sio.emit('stop_capture', data, room=stats['sid'])
