from flask import Flask
from flask_socketio import SocketIO
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app)

from frontend.routes import frontend
app.register_blueprint(frontend)

# Initialize database on startup
from backend.database import init_db
with app.app_context():
    init_db()

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
