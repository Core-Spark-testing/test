#!/usr/bin/env python3
from app import create_app, create_socketio
from config import Config

# Create Flask app
app = create_app()

# Create SocketIO instance
socketio = create_socketio(app)

if __name__ == '__main__':
    config = Config()
    debug = config.get('flask.debug', False)
    host = '0.0.0.0'
    port = 5000
    
    # Start the server
    socketio.run(app, host=host, port=port)
