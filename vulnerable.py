from flask import Flask, request, render_template_string, jsonify
import requests
import logging
import json
from datetime import datetime
import time
import os
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Enhanced logging configuration
if not os.path.exists('logs'):
    os.makedirs('logs')

# File handler for detailed logging
file_handler = RotatingFileHandler(
    'logs/ssrf_attempts.log',
    maxBytes=1024 * 1024,  # 1MB
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.addHandler(file_handler)

# Attack visualization data
attack_attempts = []

def log_attack_attempt(url, success, details):
    timestamp = datetime.now().isoformat()
    attack_attempts.append({
        "timestamp": timestamp,
        "url": url,
        "success": success,
        "details": details
    })
    # Keep only last 10 attempts for visualization
    if len(attack_attempts) > 10:
        attack_attempts.pop(0)

@app.route("/attack-visualization")
def attack_visualization():
    return jsonify(attack_attempts)

@app.route("/latest/meta-data/iam/security-credentials/admin-role")
def fake_aws_credentials():
    credentials = {
        "Code": "Success",
        "LastUpdated": "2024-03-17T11:11:11Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIA_FAKE_KEY_EXAMPLE",
        "SecretAccessKey": "fake_secret_key_example_do_not_use",
        "Token": "fake_session_token_example",
        "Expiration": "2024-12-31T23:59:59Z"
    }
    log_attack_attempt(
        url="/latest/meta-data/iam/security-credentials/admin-role",
        success=True,
        details="AWS metadata endpoint accessed"
    )
    return jsonify(credentials)

@app.route("/internal/data")
def internal_data():
    sensitive_data = {
        "account_number": "123456789",
        "ssn": "123-45-6789",
        "balance": "$10,000",
        "internal_api_key": "sk_live_12345",
        "database_credentials": {
            "host": "internal-db.example.com",
            "username": "admin",
            "password": "super_secret"
        }
    }
    log_attack_attempt(
        url="/internal/data",
        success=True,
        details="Internal sensitive data accessed"
    )
    return jsonify(sensitive_data)

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Enhanced SSRF Vulnerability Demo</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
            .warning { color: red; background: #ffe6e6; padding: 10px; border-radius: 5px; }
            .log-container { background: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 20px; }
            .vulnerable { color: red; }
            .dashboard { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
            .visualization { border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
            pre { white-space: pre-wrap; word-wrap: break-word; }
            #attackPath { width: 100%; height: 300px; }
        </style>
    </head>
    <body>
        <h1>Enhanced SSRF Vulnerability Demo <span class="vulnerable">(Vulnerable Version)</span></h1>
        
        <div class="warning">
            <strong>Warning:</strong> This server is intentionally vulnerable to SSRF attacks for demonstration purposes.
        </div>
        
        <div class="dashboard">
            <div class="visualization">
                <h2>Attack Visualization</h2>
                <canvas id="attackPath"></canvas>
            </div>
            <div class="visualization">
                <h2>Real-time Logs</h2>
                <div id="realtimeLogs" style="height: 300px; overflow-y: scroll;"></div>
            </div>
        </div>

        <h2>Test URLs:</h2>
        <ul>
            <li>http://127.0.0.1:5000/internal/data (Access internal sensitive data)</li>
            <li>http://127.0.0.1:5000/latest/meta-data/iam/security-credentials/admin-role (AWS metadata)</li>
        </ul>

        <form action="/fetch-data" method="post" id="fetchForm">
            <label for="url">Enter URL to fetch:</label><br>
            <input type="text" id="url" name="url" style="width: 400px;" placeholder="http://example.com">
            <button type="submit">Fetch Data</button>
        </form>
        
        <div id="response"></div>

        <script>
        // Initialize attack path visualization
        const ctx = document.getElementById('attackPath').getContext('2d');
        let attackChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attack Attempts',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        // Update visualization
        function updateVisualization() {
            fetch('/attack-visualization')
                .then(response => response.json())
                .then(data => {
                    const labels = data.map(d => {
                        const date = new Date(d.timestamp);
                        return date.toLocaleTimeString();
                    });
                    const values = data.map((d, index) => index + 1);
                    
                    attackChart.data.labels = labels;
                    attackChart.data.datasets[0].data = values;
                    attackChart.update();

                    // Update logs
                    const logsDiv = document.getElementById('realtimeLogs');
                    logsDiv.innerHTML = data.map(d => `
                        <div style="margin-bottom: 10px; padding: 5px; border-bottom: 1px solid #ddd;">
                            <strong>${new Date(d.timestamp).toLocaleTimeString()}</strong><br>
                            URL: ${d.url}<br>
                            Status: ${d.success ? '<span style="color: red;">Successful</span>' : 'Blocked'}<br>
                            Details: ${d.details}
                        </div>
                    `).join('');
                });
        }

        // Update every 2 seconds
        setInterval(updateVisualization, 2000);

        // Handle form submission
        document.getElementById('fetchForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const url = document.getElementById('url').value;
            
            fetch('/fetch-data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `url=${encodeURIComponent(url)}`
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('response').innerHTML = `
                    <h3>Response:</h3>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                `;
                updateVisualization();
            });
        });
        </script>
    </body>
    </html>
    """)

@app.route("/fetch-data", methods=["POST"])
def fetch_data():
    user_url = request.form.get("url", "")
    
    # Enhanced logging
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "url": user_url,
        "client_ip": request.remote_addr,
        "headers": dict(request.headers),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent"),
    }
    
    logger.info(f"SSRF Attempt Details:\n{json.dumps(log_entry, indent=2)}")
    
    try:
        start_time = time.time()
        response = requests.get(user_url, timeout=5)
        response_time = time.time() - start_time
        
        log_entry.update({
            "response_time": f"{response_time:.2f}s",
            "status_code": response.status_code,
            "response_size": len(response.text)
        })
        
        log_attack_attempt(
            url=user_url,
            success=True,
            details=f"Request successful (Status: {response.status_code})"
        )
        
        return jsonify({
            "status": "success",
            "url": user_url,
            "response": response.text,
            "log": log_entry
        })
    except requests.RequestException as e:
        error_log = {
            **log_entry,
            "error": str(e)
        }
        
        logger.error(f"Request Failed:\n{json.dumps(error_log, indent=2)}")
        
        log_attack_attempt(
            url=user_url,
            success=False,
            details=f"Request failed: {str(e)}"
        )
        
        return jsonify({
            "status": "error",
            "url": user_url,
            "error": str(e),
            "log": error_log
        }), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)
