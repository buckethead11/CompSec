from flask import Flask, request, render_template_string, jsonify
import requests
import logging
from datetime import datetime
import json
import ipaddress
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SSRFProtection:
    # [Previous SSRFProtection class code remains exactly the same]
    def __init__(self):
        self.blocked_ips = [
            '127.0.0.1',
            '169.254.169.254',  # AWS metadata
            '0.0.0.0',
            'localhost'
        ]
        self.allowed_domains = [
            'api.example.com',
            'trusted-website.com'
        ]
        self.blocked_ports = [22, 3306, 6379, 27017]  # SSH, MySQL, Redis, MongoDB
    
    def is_internal_ip(self, hostname):
        try:
            ip = ipaddress.ip_address(hostname)
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                str(ip) in self.blocked_ips
            )
        except ValueError:
            return False
    
    def validate_url(self, url):
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP(S) schemes allowed"
            
            # Check hostname
            hostname = parsed.hostname
            if hostname is None:
                return False, "Invalid hostname"
            
            # Check for internal IP
            if self.is_internal_ip(hostname):
                return False, "Internal IP addresses are blocked"
            
            # Check domain whitelist
            if not any(hostname.endswith(domain) for domain in self.allowed_domains):
                return False, "Domain not in whitelist"
            
            # Check port
            port = parsed.port
            if port and port in self.blocked_ports:
                return False, f"Port {port} is blocked"
            
            return True, "URL validated successfully"
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
        
    def analyze_risk_level(self, url):
        """Analyze the risk level of a URL request."""
        risk_factors = []
        risk_level = "low"
        
        parsed = urlparse(url)
        
        if self.is_internal_ip(parsed.hostname):
            risk_factors.append("Internal IP address attempt")
            risk_level = "high"
        
        if parsed.port and parsed.port in self.blocked_ports:
            risk_factors.append(f"Sensitive port {parsed.port}")
            risk_level = "high"
        
        if "metadata" in url.lower():
            risk_factors.append("Potential metadata endpoint access")
            risk_level = "high"
        
        if any(keyword in url.lower() for keyword in ["admin", "internal", "secure", "private"]):
            risk_factors.append("Suspicious keywords detected")
            risk_level = "medium"
        
        return {
            "risk_level": risk_level,
            "risk_factors": risk_factors
        }

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SSRF Protection Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .secure { color: green; }
            .log-container { background: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 20px; }
            pre { white-space: pre-wrap; word-wrap: break-word; }
            .risk-high { color: red; font-weight: bold; }
            .risk-medium { color: orange; font-weight: bold; }
            .risk-low { color: green; }
            .blocked { background-color: #ffebee; padding: 10px; border-radius: 5px; }
            .success { background-color: #e8f5e9; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>SSRF Protection Demo <span class="secure">(Secure Version)</span></h1>
        
        <h2>Security Features:</h2>
        <ul>
            <li>Blocks access to internal IP addresses</li>
            <li>Whitelist-based domain validation</li>
            <li>Blocked sensitive ports</li>
            <li>Protocol restriction (HTTP/HTTPS only)</li>
        </ul>

        <h2>Try These Tests:</h2>
        <ul>
            <li>https://api.example.com/data (Allowed domain)</li>
            <li>http://127.0.0.1:5000/internal/data (Blocked - internal IP)</li>
            <li>http://169.254.169.254/latest/meta-data (Blocked - AWS metadata)</li>
            <li>https://malicious-site.com:22 (Blocked - sensitive port)</li>
        </ul>

        <form id="fetchForm" onsubmit="return false;">
            <label for="url">Enter URL to fetch:</label><br>
            <input type="text" id="url" name="url" style="width: 400px;" placeholder="https://api.example.com/data">
            <button onclick="fetchURL()">Fetch Data</button>
        </form>
        
        <div id="response"></div>
        
        <div class="log-container">
            <h3>Security Log:</h3>
            <pre id="log"></pre>
        </div>

        <script>
        function fetchURL() {
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
                // Update response area
                let responseHtml = '<h3>Response:</h3>';
                
                if (data.status === 'error') {
                    responseHtml += `<div class="blocked">
                        <strong>Request Blocked</strong><br>
                        Reason: ${data.message}<br>`;
                    
                    if (data.risk_analysis) {
                        responseHtml += `
                            Risk Level: <span class="risk-${data.risk_analysis.risk_level}">${data.risk_analysis.risk_level.toUpperCase()}</span><br>
                            Risk Factors: ${data.risk_analysis.risk_factors.join(', ')}<br>`;
                    }
                    
                    responseHtml += '</div>';
                } else {
                    responseHtml += `<div class="success">
                        <strong>Request Successful</strong><br>
                        Response received from: ${data.url}
                    </div>`;
                }
                
                document.getElementById('response').innerHTML = responseHtml;
                
                // Update log area
                document.getElementById('log').innerHTML = JSON.stringify(data.log, null, 2);
            })
            .catch(error => {
                document.getElementById('response').innerHTML = `
                    <div class="blocked">
                        <strong>Error:</strong><br>
                        ${error.message}
                    </div>`;
            });
        }
        </script>
    </body>
    </html>
    """)

@app.route("/fetch-data", methods=["POST"])
def fetch_data():
    user_url = request.form.get("url", "")
    ssrf_protection = SSRFProtection()
    
    # Log the attempt
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "url": user_url,
        "client_ip": request.remote_addr,
        "headers": dict(request.headers)
    }
    
    # Risk analysis
    risk_analysis = ssrf_protection.analyze_risk_level(user_url)
    log_entry["risk_analysis"] = risk_analysis
    
    if risk_analysis["risk_level"] == "high":
        return jsonify({
            "status": "error",
            "message": "High-risk URL detected",
            "risk_analysis": risk_analysis,
            "log": log_entry
        }), 403
    
    # Validate URL
    is_valid, validation_message = ssrf_protection.validate_url(user_url)
    log_entry["validation_result"] = validation_message
    
    logger.info(f"SSRF Protection Log: {json.dumps(log_entry, indent=2)}")
    
    if not is_valid:
        return jsonify({
            "status": "error",
            "message": validation_message,
            "risk_analysis": risk_analysis,
            "log": log_entry
        }), 403
    
    try:
        response = requests.get(user_url, timeout=5)
        return jsonify({
            "status": "success",
            "url": user_url,
            "response": response.text,
            "risk_analysis": risk_analysis,
            "log": log_entry
        })
    except requests.RequestException as e:
        error_response = {
            "status": "error",
            "url": user_url,
            "error": str(e),
            "risk_analysis": risk_analysis,
            "log": log_entry
        }
        return jsonify(error_response), 400

if __name__ == "__main__":
    app.run(debug=True, port=5001)