```
intelligent-security-alerts/app/__init__.py
# Flask app initialization
from flask import Flask
from dotenv import load_dotenv
import os

def create_app():
    app = Flask(__name__)
    load_dotenv()
    
    # Register routes
    from .routes import main
    app.register_blueprint(main)
    
    return app

intelligent-security-alerts/app/models.py
# Database models for recipients and logs
import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("security_alerts.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS recipients (
        phone_number TEXT PRIMARY KEY,
        name TEXT,
        opt_in INTEGER DEFAULT 1
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alert_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone_number TEXT,
        message TEXT,
        timestamp TEXT,
        status TEXT
    )""")
    conn.commit()
    conn.close()

def log_alert(phone_number, message, status):
    conn = sqlite3.connect("security_alerts.db")
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute(
        "INSERT INTO alert_logs (phone_number, message, timestamp, status) VALUES (?, ?, ?, ?)",
        (phone_number, message, timestamp, status)
    )
    conn.commit()
    conn.close()

def get_recipients():
    conn = sqlite3.connect("security_alerts.db")
    c = conn.cursor()
    c.execute("SELECT phone_number FROM recipients WHERE opt_in = 1")
    recipients = [row[0] for row in c.fetchall()]
    conn.close()
    return recipients

intelligent-security-alerts/app/routes.py
# Routes for web interface, API, and subscription
from flask import Blueprint, request, jsonify, render_template
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
from datetime import datetime
import random
import os
import re
from .models import init_db, log_alert, get_recipients

main = Blueprint("main", __name__)

# Initialize Twilio client
client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN"))

# Initialize database
init_db()

# Generative alert templates (includes +675 local cell number for PNG)
ALERT_TEMPLATES = [
    "CODE {level}: {incident} at {location}, {time}. {action}. Contact HQ at {local_number}. Reply CONFIRM or REPORT. STOP to opt out. [IntelligentSec]",
    "ALERT {level}: {incident} detected in {location}, {time}. {action}. Call {local_number} for details. Reply CONFIRM or REPORT. STOP to opt out. [IntelligentSec]"
]

INCIDENT_TYPES = ["Breach", "Intrusion", "Threat", "Unauthorized Access"]
LOCATIONS = ["Sector A", "Sector B", "Gate 1", "HQ"]
ACTIONS = ["Respond to post", "Secure area", "Escort to safe zone"]
LEVELS = ["RED", "YELLOW", "BLACK"]

def generate_alert(incident_type=None, location=None, level=None):
    template = random.choice(ALERT_TEMPLATES)
    incident = incident_type or random.choice(INCIDENT_TYPES)
    location = location or random.choice(LOCATIONS)
    level = level or random.choice(LEVELS)
    action = random.choice(ACTIONS)
    time = datetime.now().strftime("%H%M hrs")
    return template.format(
        level=level,
        incident=incident,
        location=location,
        time=time,
        action=action,
        local_number=os.getenv("LOCAL_CELL_NUMBER")
    )

def send_sms(phone_number, message):
    try:
        client.messages.create(
            body=message,
            from_=os.getenv("TWILIO_PHONE_NUMBER"),
            to=phone_number
        )
        log_alert(phone_number, message, "SENT")
        return True
    except Exception as e:
        log_alert(phone_number, message, f"FAILED: {str(e)}")
        return False

def forward_reply(from_number, body):
    try:
        client.messages.create(
            body=f"Reply from {from_number}: {body}",
            from_=os.getenv("TWILIO_PHONE_NUMBER"),
            to=os.getenv("LOCAL_CELL_NUMBER")
        )
        log_alert(from_number, body, "FORWARDED")
        return True
    except Exception as e:
        log_alert(from_number, body, f"FORWARD_FAILED: {str(e)}")
        return False

@main.route("/")
def index():
    return render_template("index.html")

@main.route("/subscribe", methods=["GET", "POST"])
def subscribe():
    if request.method == "POST":
        phone_number = request.form.get("phone_number")
        name = request.form.get("name", "")
        consent = request.form.get("consent")
        
        # Validate phone number (+675 format)
        if not phone_number.startswith("+675") or not re.match(r"\+675\d{7,8}$", phone_number):
            return jsonify({"error": "Invalid phone number. Must be +675 followed by 7-8 digits."}), 400
        
        # Validate consent
        if consent != "on":
            return jsonify({"error": "You must consent to receive SMS alerts."}), 400
        
        # Add to recipients
        conn = sqlite3.connect("security_alerts.db")
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO recipients (phone_number, name, opt_in) VALUES (?, ?, 1)",
            (phone_number, name)
        )
        conn.commit()
        conn.close()
        
        # Send confirmation SMS
        confirmation_message = "You've subscribed to Intelligent Security alerts. Reply STOP to opt out."
        send_sms(phone_number, confirmation_message)
        
        return jsonify({"message": "Subscribed successfully! Confirmation SMS sent."})
    
    return render_template("subscribe.html")

@main.route("/trigger_alert", methods=["POST"])
def trigger_alert():
    incident_type = request.form.get("incident_type")
    location = request.form.get("location")
    level = request.form.get("level")
    message = generate_alert(incident_type, location, level)
    recipients = get_recipients()
    results = []
    for phone in recipients:
        success = send_sms(phone, message)
        results.append({"phone": phone, "success": success})
    return jsonify({"message": "Alerts sent", "results": results})

@main.route("/api/trigger_alert", methods=["POST"])
def api_trigger_alert():
    data = request.json
    incident_type = data.get("incident_type")
    location = data.get("location")
    level = data.get("level")
    message = generate_alert(incident_type, location, level)
    recipients = get_recipients()
    results = []
    for phone in recipients:
        success = send_sms(phone, message)
        results.append({"phone": phone, "success": success})
    return jsonify({"message": "Alerts sent", "results": results})

@main.route("/add_recipient", methods=["POST"])
def add_recipient():
    phone_number = request.form.get("phone_number")
    name = request.form.get("name", "")
    # Validate phone number (+675 format)
    if not phone_number.startswith("+675") or not re.match(r"\+675\d{7,8}$", phone_number):
        return jsonify({"error": "Invalid phone number. Must be +675 followed by 7-8 digits."}), 400
    
    conn = sqlite3.connect("security_alerts.db")
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO recipients (phone_number, name, opt_in) VALUES (?, ?, 1)",
        (phone_number, name)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Recipient added"})

@main.route("/logs")
def view_logs():
    conn = sqlite3.connect("security_alerts.db")
    c = conn.cursor()
    c.execute("SELECT * FROM alert_logs ORDER BY timestamp DESC")
    logs = c.fetchall()
    conn.close()
    return render_template("logs.html", logs=logs)

@main.route("/sms_reply", methods=["POST"])
def sms_reply():
    from_number = request.values.get("From")
    body = request.values.get("Body", "").strip().upper()
    resp = MessagingResponse()
    
    conn = sqlite3.connect("security_alerts.db")
    c = conn.cursor()
    
    c.execute("SELECT opt_in FROM recipients WHERE phone_number = ?", (from_number,))
    recipient = c.fetchone()
    
    if not recipient:
        resp.message("You are not registered. Text START to join.")
        forward_reply(from_number, body)
        conn.close()
        return str(resp)
    
    if body == "STOP":
        c.execute("UPDATE recipients SET opt_in = 0 WHERE phone_number = ?", (from_number,))
        conn.commit()
        resp.message("You have opted out. Text START to rejoin.")
        forward_reply(from_number, body)
    elif body == "START":
        c.execute("UPDATE recipients SET opt_in = 1 WHERE phone_number = ?", (from_number,))
        conn.commit()
        resp.message("You have opted in for alerts.")
        forward_reply(from_number, body)
    elif body == "CONFIRM":
        log_alert(from_number, body, "RECEIVED: CONFIRM")
        resp.message("Acknowledgment received. Stand by for updates.")
        forward_reply(from_number, body)
    elif body == "REPORT":
        log_alert(from_number, body, "RECEIVED: REPORT")
        resp.message(f"Details: Incident ongoing. Contact HQ at {os.getenv('LOCAL_CELL_NUMBER')}.")
        forward_reply(from_number, body)
    else:
        log_alert(from_number, body, "RECEIVED: INVALID")
        resp.message("Invalid response. Reply CONFIRM or REPORT.")
        forward_reply(from_number, body)
    
    conn.close()
    return str(resp)

intelligent-security-alerts/app/templates/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intelligent Security Alert System</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-4 max-w-2xl">
        <h1 class="text-3xl font-bold text-center text-gray-800 mb-6">Intelligent Security Alert System</h1>
        
        <!-- Trigger Alert Form -->
        <div class="bg-white p-6 rounded-lg shadow-md mb-6">
            <h2 class="text-xl font-semibold mb-4">Send Alert</h2>
            <form id="alertForm" action="/trigger_alert" method="POST" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700">Incident Type (optional):</label>
                    <input type="text" name="incident_type" class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Location (optional):</label>
                    <input type="text" name="location" class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Level (optional):</label>
                    <select name="level" class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                        <option value="">Select</option>
                        <option value="RED">RED</option>
                        <option value="YELLOW">YELLOW</option>
                        <option value="BLACK">BLACK</option>
                    </select>
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700">Send Alert</button>
            </form>
        </div>

        <!-- Add Recipient Form -->
        <div class="bg-white p-6 rounded-lg shadow-md mb-6">
            <h2 class="text-xl font-semibold mb-4">Add Recipient (Admin)</h2>
            <form id="recipientForm" action="/add_recipient" method="POST" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700">Phone Number:</label>
                    <input type="text" name="phone_number" required class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Name:</label>
                    <input type="text" name="name" class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700">Add Recipient</button>
            </form>
        </div>

        <!-- Navigation Links -->
        <div class="text-center space-y-2">
            <a href="/logs" class="text-indigo-600 hover:text-indigo-800 font-medium block">View Alert Logs</a>
            <a href="/subscribe" class="text-indigo-600 hover:text-indigo-800 font-medium block">Subscribe to Alerts</a>
        </div>
    </div>
    <script>
        // Handle form submissions with feedback
        document.getElementById("alertForm").addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const response = await fetch("/trigger_alert", {
                method: "POST",
                body: formData
            });
            const result = await response.json();
            alert(result.message);
        });
        document.getElementById("recipientForm").addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const response = await fetch("/add_recipient", {
                method: "POST",
                body: formData
            });
            const result = await response.json();
            alert(result.message);
        });
    </script>
</body>
</html>

intelligent-security-alerts/app/templates/logs.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alert Logs</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-4 max-w-4xl">
        <h1 class="text-3xl font-bold text-center text-gray-800 mb-6">Intelligent Security Alert Logs</h1>
        <div class="bg-white p-6 rounded-lg shadow-md overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Phone Number</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Message</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    {% for log in logs %}
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ log[0] }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ log[1] }}</td>
                        <td class="px-6 py-4 text-sm text-gray-500">{{ log[2] }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ log[3] }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ log[4] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <div class="mt-4 text-center">
            <a href="/" class="text-indigo-600 hover:text-indigo-800 font-medium">Back to Home</a>
        </div>
    </div>
</body>
</html>

intelligent-security-alerts/app/templates/subscribe.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subscribe to Intelligent Security Alerts</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-4 max-w-2xl">
        <h1 class="text-3xl font-bold text-center text-gray-800 mb-6">Subscribe to Intelligent Security Alerts</h1>
        <div class="bg-white p-6 rounded-lg shadow-md">
            <p class="text-gray-600 mb-4">Join our SMS alert system to receive real-time security notifications. You can opt out anytime by replying STOP.</p>
            <form id="subscribeForm" action="/subscribe" method="POST" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700">Phone Number (+675):</label>
                    <input type="text" name="phone_number" required placeholder="+67570001234" class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Name (optional):</label>
                    <input type="text" name="name" class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <label class="flex items-center">
                        <input type="checkbox" name="consent" required class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                        <span class="ml-2 text-sm text-gray-600">I consent to receive SMS alerts from Intelligent Security.</span>
                    </label>
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700">Subscribe</button>
            </form>
        </div>
        <div class="mt-4 text-center">
            <a href="/" class="text-indigo-600 hover:text-indigo-800 font-medium">Back to Home</a>
        </div>
    </div>
    <script>
        document.getElementById("subscribeForm").addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const response = await fetch("/subscribe", {
                method: "POST",
                body: formData
            });
            const result = await response.json();
            if (result.error) {
                alert(result.error);
            } else {
                alert(result.message);
            }
        });
    </script>
</body>
</html>

intelligent-security-alerts/app/static/favicon.ico
[Binary favicon file, not shown; use any 16x16 .ico file or omit]

intelligent-security-alerts/tests/test_routes.py
# Unit tests for routes
import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Intelligent Security Alert System" in response.data

def test_logs(client):
    response = client.get("/logs")
    assert response.status_code == 200
    assert b"Alert Logs" in response.data

def test_subscribe(client):
    response = client.get("/subscribe")
    assert response.status_code == 200
    assert b"Subscribe to Intelligent Security Alerts" in response.data

intelligent-security-alerts/tests/test_alerts.py
# Tests for alert generation
from app.routes import generate_alert

def test_generate_alert():
    alert = generate_alert()
    assert "CODE" in alert or "ALERT" in alert
    assert "IntelligentSec" in alert
    assert "STOP to opt out" in alert

intelligent-security-alerts/.env.example
# Example environment variables for Papua New Guinea (+675)
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+67570001234  # Twilio number with PNG country code
LOCAL_CELL_NUMBER=+67575230910   # Your personal cell number in PNG

intelligent-security-alerts/.gitignore
# Ignore sensitive files
.env
security_alerts.db
__pycache__/
*.pyc
*.db
venv/

intelligent-security-alerts/requirements.txt
flask==3.0.3
twilio==9.3.0
python-dotenv==1.0.1
pytest==8.3.3
gunicorn==22.0.0

intelligent-security-alerts/README.md
# Intelligent Security SMS Alert System (PNG)

A responsive, generative SMS alert system for Intelligent Security in Papua New Guinea, sending coded alerts via a Twilio +675 number and forwarding replies to a local +675 cell number. Includes a public subscription interface for viewers to opt-in to alerts.

## Features
- Sends SMS alerts (e.g., "CODE RED: Breach at Sector A, 1430 hrs. Call +675 7523 0910.") using a Twilio +675 number.
- References your local +675 cell number for contact.
- Forwards replies (e.g., "CONFIRM") to your local number.
- Responsive web interface (Tailwind CSS) for manual triggers, admin recipient management, logs, and public subscription.
- SQLite database for recipients and audit logs.
- API for integration with security systems (e.g., CCTV, alarms).
- Compliant with PNG telecommunications regulations (opt-in/out).

## Prerequisites
- Python 3.12
- Twilio account with a +675 mobile number (Digicel/bmobile)
- GitHub account
- Cloudflare Pages account
- Ngrok (for local webhook testing)

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/intelligent-security-alerts.git
   cd intelligent-security-alerts
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file based on `.env.example`:
   ```
   TWILIO_ACCOUNT_SID=your_account_sid
   TWILIO_AUTH_TOKEN=your_auth_token
   TWILIO_PHONE_NUMBER=+67570001234
   LOCAL_CELL_NUMBER=+67575230910
   ```
4. Purchase a Twilio +675 mobile number (twilio.com/console/phone-numbers).
5. Run locally:
   ```bash
   python run.py
   ```
6. Access at `http://localhost:5000`.
   - Admin: `/` (send alerts, add recipients), `/logs` (view logs).
   - Public: `/subscribe` (opt-in to alerts).
7. For Twilio webhook, use Ngrok:
   ```bash
   ngrok http 5000
   ```
   Set webhook to `http://your-ngrok-url/sms_reply` (POST).

## Deployment
### GitHub
1. Create a repository: `https://github.com/your-username/intelligent-security-alerts`.
2. Push code:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/your-username/intelligent-security-alerts.git
   git push -u origin main
   ```

### Cloudflare Pages
1. Sign up at `pages.cloudflare.com`.
2. Connect GitHub repository.
3. Configure build:
   - Framework: None (manual).
   - Build command: `pip install -r requirements.txt`.
   - Output directory: `/`.
4. Set environment variables in Cloudflare dashboard:
   ```
   TWILIO_ACCOUNT_SID=your_account_sid
   TWILIO_AUTH_TOKEN=your_auth_token
   TWILIO_PHONE_NUMBER=+67570001234
   LOCAL_CELL_NUMBER=+67575230910
   PYTHON_VERSION=3.12
   ```
5. Database:
   - SQLite (`security_alerts.db`) requires persistent storage. Use Cloudflare D1 (beta, free) or a separate server (e.g., AWS EC2).
   - For D1, migrate SQLite schema (contact support for script).
6. Deploy and set Twilio webhook to `https://your-project.pages.dev/sms_reply`.

## Testing
Run tests:
```bash
pytest
```

## Costs (Year 1, PNG-Specific)
- **Twilio**:
  - Mobile number (+675): $2/month = $24/year.
  - SMS (1,000 sent, 500 received, 500 forwarded, 100 confirmation): (1,100 × $0.0485) + (1,000 × $0.0135) = $66.85/month = $802.20/year.
  - A2P registration: $4 one-time + $2/month = $28/year.
  - Total: ~$854.20.
- **Cloudflare Pages**: Free (500,000 requests/month).
- **Infrastructure**:
  - Local: $0.
  - Optional EC2 (for SQLite): $70–$250.
- **Total**: $854.20 (local) or $924.20–$1,104.20 (with EC2).

## License
MIT

intelligent-security-alerts/Procfile
web: gunicorn -w 4 -b 0.0.0.0:$PORT run:app

intelligent-security-alerts/cloudflare.toml
# Cloudflare Pages configuration
[build]
  command = "pip install -r requirements.txt"
  output_directory = "/"

[env]
  PYTHON_VERSION = "3.12"

intelligent-security-alerts/run.py
# Entry point for Flask app
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
```