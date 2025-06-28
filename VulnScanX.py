import os
import argparse
from flask import Flask, request 
from flask_socketio import SocketIO, emit
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tools.database import Base # Assuming Base is defined here for SQLAlchemy

# Import the new routes and scan orchestrator
from routes import register_routes
from scan_orchestrator import full_scan, custom_scan # Import scan functions

# Initialize Flask app
flask_app = Flask(__name__)

# Configure Flask-SocketIO
# cors_allowed_origins should be set to your frontend's origin in production
socketio = SocketIO(flask_app, cors_allowed_origins="*", async_mode='threading')

# Path to the scans directory (needed for some tool outputs)
scans_dir = "scans"
os.makedirs(scans_dir, exist_ok=True)

# Set SCANS_BASE_DIR in Flask app config
flask_app.config['SCANS_BASE_DIR'] = scans_dir
# Set a secret key for Flask sessions (important for security)
flask_app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_that_should_be_changed')

# Database initialization
db_path = 'sqlite:///vulnscanx.db'
engine = create_engine(db_path)
Base.metadata.create_all(engine) # Create tables if they don't exist
Session = sessionmaker(bind=engine) # Session factory

# Parse command-line arguments for port
parser = argparse.ArgumentParser(description="Run VulnScanX with custom port.")
parser.add_argument("-p", "--port", type=int, default=80, help="Port to run the application on (default: 80)")
args = parser.parse_args()

# Global variable for number of threads (can be made configurable via app.config if desired)
NUM_THREADS = 10 # Default number of threads for concurrent tasks

# Dictionary to hold threading.Event objects for each scan_id that needs interactive login
# This allows the Socket.IO handler to signal the correct scan thread to resume.
scan_login_events = {}

# Helper function to emit progress updates via SocketIO
def emit_progress(scan_id, message, progress_type='info', sid=None, percentage=0):
    """
    Emits scan progress updates to the frontend via Socket.IO.
    Args:
        scan_id (int): The ID of the current scan.
        message (str): The progress message.
        progress_type (str): Type of message (e.g., 'info', 'success', 'error', 'login_required').
        sid (str, optional): The Socket.IO session ID of the client to send to.
        percentage (int): The current progress percentage (0-100).
    """
    data = {
        'scan_id': scan_id,
        'message': message,
        'status': progress_type,
        'progress': percentage
    }
    if sid:
        socketio.emit('scan_progress', data, room=sid)
    else:
        socketio.emit('scan_progress', data)
    print(f"Scan {scan_id} Progress ({percentage}%): {message} [{progress_type}]")


# Helper function to emit new vulnerabilities via SocketIO
def emit_vulnerability(scan_id, vulnerability_data, sid=None):
    """
    Emits new vulnerability findings to the frontend via Socket.IO.
    Args:
        scan_id (int): The ID of the current scan.
        vulnerability_data (dict): Dictionary containing vulnerability details.
        sid (str, optional): The Socket.IO session ID of the client to send to.
    """
    data = {
        'scan_id': scan_id,
        'vulnerability': vulnerability_data
    }
    if sid:
        socketio.emit('new_vulnerability', data, room=sid)
    else:
        socketio.emit('new_vulnerability', data)
    print(f"Scan {scan_id} Vulnerability Found: {vulnerability_data.get('vulnerability_type', 'N/A')}")


# Register all routes from routes.py
register_routes(
    app=flask_app,
    sio=socketio, 
    db_session_factory=Session,
    db_engine=engine,
    progress_emitter=emit_progress,
    vulnerability_emitter=emit_vulnerability,
    num_threads_global=NUM_THREADS,
    full_scan_func=full_scan,      
    custom_scan_func=custom_scan,
    scan_login_events=scan_login_events # FIX: Pass the scan_login_events dictionary
)

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    """Handles new client connections."""
    print(f'Client connected: {request.sid}')
    emit('my response', {'data': 'Connected to VulnScanX WebSocket', 'sid': request.sid}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    """Handles client disconnections."""
    print(f'Client disconnected: {request.sid}')

@socketio.on('login_complete_signal')
def handle_login_complete_signal(data):
    """
    Handles the signal from the frontend that manual login is complete.
    Resumes the paused scan thread.
    """
    scan_id = data.get('scan_id')
    if scan_id and scan_id in scan_login_events:
        print(f"Received login_complete_signal for scan_id: {scan_id}. Resuming scan.")
        scan_login_events[scan_id].set() # Set the event to release the waiting thread
        del scan_login_events[scan_id] # Clean up the event object
    else:
        print(f"Warning: login_complete_signal received for unknown or completed scan_id: {scan_id}")


# Run the app with the specified port using SocketIO
if __name__ == '__main__':
    socketio.run(flask_app, host='0.0.0.0', port=args.port, debug=True)
