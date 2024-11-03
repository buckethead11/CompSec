from flask import Flask, request, render_template_string
import requests
import re

app = Flask(__name__)

# Simulated "internal" endpoint with fake sensitive data
@app.route("/internal/data")
def internal_data():
    sensitive_data = {
        "account_number": "123456789",
        "ssn": "123-45-6789",
        "balance": "$10,000"
    }
    return sensitive_data, 200

@app.route("/")
def index():
    return render_template_string(open("index.html").read())

@app.route("/fetch-data", methods=["POST"])
def fetch_data():
    user_url = request.form.get("url")

    # Fix: only allow URLs from trusted domains or specific paths
    allowed_pattern = re.compile(r"https?://(www\.)?trusted-website\.com")

    if not allowed_pattern.match(user_url):
        return "<h2>Error:</h2><pre>Untrusted URL detected! Access denied.</pre>"

    try:
        response = requests.get(user_url)
        return f"<h2>Response from {user_url}:</h2><pre>{response.text}</pre>"
    except requests.RequestException as e:
        return f"<h2>Error:</h2><pre>{e}</pre>"

if __name__ == "__main__":
    app.run(debug=True)
