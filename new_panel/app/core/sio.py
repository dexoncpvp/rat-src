import socketio

# Create a shared Socket.IO instance
# This is imported by main.py (to attach to ASGI) and by endpoints (to emit events)
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
