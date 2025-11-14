#!/usr/bin/env python3
"""
Minimal SocketIO test server
Test if SocketIO can run properly
"""

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO, emit

app = Flask(__name__)
CORS(app)

# Create SocketIO instance
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)

@app.route('/')
def index():
    return {'status': 'ok', 'message': 'SocketIO test server'}

@app.route('/test')
def test():
    return {'socketio': 'ready'}

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print('[TEST] Client connected!')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('[TEST] Client disconnected!')

@socketio.on('test_event')
def handle_test(data):
    print(f'[TEST] Received: {data}')
    emit('test_response', {'received': data})

if __name__ == '__main__':
    print("=" * 60)
    print("MINIMAL SOCKETIO TEST SERVER")
    print("=" * 60)
    print("Starting SocketIO server on http://0.0.0.0:5001")
    print("Test endpoints:")
    print("  - HTTP: http://localhost:5001/")
    print("  - HTTP: http://localhost:5001/test")
    print("  - WebSocket: ws://localhost:5001/socket.io/")
    print("=" * 60)
    print()
    
    # Run with SocketIO
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)