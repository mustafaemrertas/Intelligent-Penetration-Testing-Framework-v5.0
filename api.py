"""
Flask API module for Ultra Penetration Testing Framework v5.0
Provides web interface and REST API endpoints
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
import threading
import time
from datetime import datetime
import os
import json

from utils import Logger, ConfigManager

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ultra_pentest_secret_key_2024')

# Initialize limiter for rate limiting (underground protection)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize logger and config
logger = Logger("api.log")
config = ConfigManager()

# Basic auth credentials (underground - change in production)
USERS = {
    "admin": generate_password_hash("ultra_pentest_2024")
}

# Global variables for scan management
current_scan = None
scan_thread = None
scan_results = {}

# HTML Templates
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultra Penetration Testing Framework v5.0</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .card { background: #2d2d2d; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .status { padding: 10px; border-radius: 4px; margin: 10px 0; }
        .status.running { background: #ffc107; color: black; }
        .status.completed { background: #28a745; }
        .status.error { background: #dc3545; }
        input, select { padding: 8px; margin: 5px; width: 200px; }
        .logout { float: right; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Ultra Penetration Testing Framework v5.0</h1>
            <p>Advanced AI-Powered Penetration Testing Tool</p>
            <a href="{{ url_for('logout') }}" class="btn logout">Logout</a>
        </div>

        <div class="card">
            <h2>Dashboard</h2>
            <div class="status {{ 'running' if scan_status == 'running' else 'completed' if scan_status == 'completed' else 'error' }}">
                Current Scan Status: {{ scan_status or 'Idle' }}
            </div>
            {% if scan_results %}
            <h3>Latest Results</h3>
            <p>Total Vulnerabilities: {{ scan_results.get('total_vulnerabilities', 0) }}</p>
            <p>Critical Issues: {{ scan_results.get('critical_count', 0) }}</p>
            {% endif %}
        </div>

        <div class="card">
            <h2>Start New Scan</h2>
            <form method="POST" action="{{ url_for('start_scan') }}">
                <label for="target">Target (URL or IP):</label>
                <input type="text" id="target" name="target" required placeholder="example.com or 192.168.1.1">
                <br>
                <label for="stealth">Stealth Mode:</label>
                <select id="stealth" name="stealth">
                    <option value="false">Normal</option>
                    <option value="true">Stealth</option>
                </select>
                <br>
                <button type="submit" class="btn">Start Scan</button>
            </form>
        </div>

        <div class="card">
            <h2>Quick Actions</h2>
            <a href="{{ url_for('welcome') }}" class="btn">API Welcome</a>
            <a href="{{ url_for('scan_status') }}" class="btn">View Scan Status</a>
            <a href="{{ url_for('results') }}" class="btn">View Results</a>
        </div>
    </div>
</body>
</html>
"""

RESULTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results - Ultra Pentest</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: #2d2d2d; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .vulnerability { padding: 10px; margin: 5px 0; border-left: 5px solid; border-radius: 4px; }
        .CRITICAL { border-color: #dc3545; background: #3d1f1f; }
        .HIGH { border-color: #fd7e14; background: #3d2a1f; }
        .MEDIUM { border-color: #ffc107; background: #3d3a1f; }
        .LOW { border-color: #28a745; background: #1f3d23; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; text-decoration: none; display: inline-block; }
        .back { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Scan Results</h1>
        {% if scan_results %}
            <div class="card">
                <h2>Summary</h2>
                <p>Total Vulnerabilities: {{ scan_results.get('total_vulnerabilities', 0) }}</p>
                <p>Critical: {{ scan_results.get('critical_count', 0) }}</p>
                <p>High: {{ scan_results.get('high_count', 0) }}</p>
                <p>Correlations: {{ scan_results.get('correlation_count', 0) }}</p>
            </div>

            <div class="card">
                <h2>Vulnerabilities</h2>
                {% for vuln in scan_results.get('vulnerabilities', [])[:20] %}
                <div class="vulnerability {{ vuln.get('severity', 'LOW') }}">
                    <h4>{{ vuln.get('type', 'Unknown') }}</h4>
                    <p><strong>Severity:</strong> {{ vuln.get('severity', 'Unknown') }}</p>
                    <p><strong>CVSS:</strong> {{ vuln.get('cvss_score', 'N/A') }}</p>
                    <p><strong>Details:</strong> {{ vuln.get('detail', 'N/A') }}</p>
                </div>
                {% endfor %}
            </div>
        {% else %}
            <p>No results available. Run a scan first.</p>
        {% endif %}
        <a href="{{ url_for('index') }}" class="btn back">Back to Dashboard</a>
    </div>
</body>
</html>
"""

# Routes
@app.before_request
def require_login():
    allowed_routes = ['login', 'welcome', 'api_scan', 'api_status', 'scan_status', 'start_scan']  # Public routes including API
    if request.endpoint not in allowed_routes and 'username' not in session:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and check_password_hash(USERS[username], password):
            session['username'] = username
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head><title>Login - Ultra Pentest</title>
    <style>body{background:#1a1a1a;color:#fff;text-align:center;margin:100px;}input{padding:10px;margin:10px;}</style>
    </head>
    <body><h1>Login</h1><form method="POST">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <button type="submit">Login</button></form></body></html>
    """)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    global scan_results
    scan_status = 'running' if scan_thread and scan_thread.is_alive() else 'completed' if scan_results else 'idle'
    return render_template_string(INDEX_TEMPLATE, scan_status=scan_status, scan_results=scan_results)

@app.route('/welcome', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("10 per minute")
def welcome():
    # Log request metadata
    method = request.method
    path = request.path
    user_agent = request.headers.get('User-Agent', 'Unknown')
    ip = request.remote_addr

    logger.info(f"API Request - Method: {method}, Path: {path}, IP: {ip}, User-Agent: {user_agent}")

    # Return JSON welcome message
    return jsonify({
        "message": "Welcome to the Ultra Penetration Testing Framework API!",
        "timestamp": datetime.now().isoformat(),
        "request_info": {
            "method": method,
            "path": path,
            "ip": ip
        }
    })

@app.route('/start_scan', methods=['POST'])
def start_scan():
    global current_scan, scan_thread, scan_results

    if scan_thread and scan_thread.is_alive():
        flash('Scan already running')
        return redirect(url_for('index'))

    target = request.form.get('target')
    stealth = request.form.get('stealth') == 'true'

    if not target:
        flash('Target required')
        return redirect(url_for('index'))

    # Start scan in background thread
    def run_scan():
        global scan_results
        try:
            pentest = UltraCompletePenTest(target, stealth_mode=stealth)
            pentest.banner()
            pentest.phase1_ultra_recon()
            pentest.phase2_ultra_scanning()
            pentest.phase3_exploitation()
            pentest.phase4_post_exploitation()
            pentest.phase5_reporting()

            # Store results
            scan_results = {
                'total_vulnerabilities': len(pentest.correlator.vulnerabilities),
                'critical_count': len([v for v in pentest.correlator.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high_count': len([v for v in pentest.correlator.vulnerabilities if v['severity'] == 'HIGH']),
                'correlation_count': len(pentest.correlator.correlations),
                'vulnerabilities': pentest.correlator.vulnerabilities[:50]  # Limit for display
            }
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_results = {'error': str(e)}

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

    flash('Scan started successfully')
    return redirect(url_for('index'))

@app.route('/scan_status')
def scan_status():
    global scan_thread
    status = 'running' if scan_thread and scan_thread.is_alive() else 'completed'
    return jsonify({'status': status})

@app.route('/results')
def results():
    global scan_results
    return render_template_string(RESULTS_TEMPLATE, scan_results=scan_results)

@app.route('/api/v1/scan', methods=['POST'])
@limiter.limit("5 per hour")
def api_scan():
    """REST API endpoint for starting scans"""
    data = request.get_json()
    target = data.get('target')
    stealth = data.get('stealth', False)

    if not target:
        return jsonify({'error': 'Target required'}), 400

    # Similar to start_scan but return JSON
    global current_scan, scan_thread
    if scan_thread and scan_thread.is_alive():
        return jsonify({'error': 'Scan already running'}), 409

    def run_scan():
        try:
            pentest = UltraCompletePenTest(target, stealth_mode=stealth)
            pentest.banner()
            pentest.phase1_ultra_recon()
            pentest.phase2_ultra_scanning()
            pentest.phase3_exploitation()
            pentest.phase4_post_exploitation()
            pentest.phase5_reporting()
            return pentest.correlator.vulnerabilities
        except Exception as e:
            logger.error(f"API scan failed: {e}")
            return []

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

    return jsonify({'message': 'Scan started', 'target': target}), 202

@app.route('/api/v1/status')
def api_status():
    global scan_thread, scan_results
    status = 'running' if scan_thread and scan_thread.is_alive() else 'idle'
    return jsonify({
        'status': status,
        'last_scan_results': scan_results if scan_results else None
    })

if __name__ == '__main__':
    logger.info("Starting Ultra Pentest API server")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
