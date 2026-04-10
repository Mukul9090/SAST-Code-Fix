"""
Intentionally Vulnerable Application
=====================================
DO NOT USE IN PRODUCTION — This file contains deliberate
security vulnerabilities for testing AI remediation.

Vulnerabilities included:
  1. SQL Injection
  2. Command Injection
  3. Cross-Site Scripting (XSS)
  4. Hardcoded Secrets
  5. Path Traversal
  6. Insecure Deserialization
  7. Weak Cryptography (MD5)
  8. SSRF (Server-Side Request Forgery)
  9. Open Redirect
  10. Insecure Random Number Generation
"""

import os
import hashlib
import pickle
import random
import sqlite3
import subprocess
import requests
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════
# 1. HARDCODED SECRETS
# CWE-798: Use of Hard-coded Credentials
# ═══════════════════════════════════════════════════════════════
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "my-jwt-secret-key-do-not-share"


# ═══════════════════════════════════════════════════════════════
# 2. SQL INJECTION
# CWE-89: Improper Neutralization of SQL Input
# ═══════════════════════════════════════════════════════════════
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    return "Login failed"


@app.route("/search")
def search_users():
    name = request.args.get("name", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: f-string SQL injection
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")

    results = cursor.fetchall()
    conn.close()
    return str(results)


# ═══════════════════════════════════════════════════════════════
# 3. COMMAND INJECTION
# CWE-78: OS Command Injection
# ═══════════════════════════════════════════════════════════════
@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    # VULNERABLE: User input directly in shell command
    output = os.popen("ping -c 1 " + host).read()
    return f"<pre>{output}</pre>"


@app.route("/lookup")
def dns_lookup():
    domain = request.args.get("domain", "")

    # VULNERABLE: subprocess with shell=True
    result = subprocess.check_output(
        "nslookup " + domain,
        shell=True,
        text=True
    )
    return result


# ═══════════════════════════════════════════════════════════════
# 4. CROSS-SITE SCRIPTING (XSS)
# CWE-79: Improper Neutralization of Input During Web Page Gen
# ═══════════════════════════════════════════════════════════════
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")

    # VULNERABLE: Reflected XSS — user input rendered directly in HTML
    return f"<h1>Hello, {name}!</h1>"


@app.route("/profile")
def profile():
    bio = request.args.get("bio", "")

    # VULNERABLE: Template injection / XSS via render_template_string
    template = f"<div class='bio'>{bio}</div>"
    return render_template_string(template)


@app.route("/comment", methods=["POST"])
def comment():
    user_comment = request.form.get("comment", "")

    # VULNERABLE: Stored XSS — no sanitization
    html = f"""
    <html>
    <body>
        <h2>Your comment:</h2>
        <div>{user_comment}</div>
    </body>
    </html>
    """
    return html


# ═══════════════════════════════════════════════════════════════
# 5. PATH TRAVERSAL
# CWE-22: Improper Limitation of a Pathname
# ═══════════════════════════════════════════════════════════════
@app.route("/download")
def download_file():
    filename = request.args.get("file", "")

    # VULNERABLE: No path validation — user can access any file
    filepath = os.path.join("/var/www/files", filename)

    with open(filepath, "r") as f:
        content = f.read()

    return content


@app.route("/read-log")
def read_log():
    log_name = request.args.get("name", "app.log")

    # VULNERABLE: Direct file access with user-controlled path
    with open("/var/log/" + log_name) as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════
# 6. INSECURE DESERIALIZATION
# CWE-502: Deserialization of Untrusted Data
# ═══════════════════════════════════════════════════════════════
@app.route("/load-session", methods=["POST"])
def load_session():
    session_data = request.form.get("data", "")

    # VULNERABLE: Pickle deserialization of user-controlled data
    user_session = pickle.loads(bytes.fromhex(session_data))

    return f"Welcome back, {user_session.get('username', 'unknown')}"


@app.route("/import-config", methods=["POST"])
def import_config():
    config_data = request.get_data()

    # VULNERABLE: eval() on user input
    config = eval(config_data)

    return f"Config loaded: {config}"


# ═══════════════════════════════════════════════════════════════
# 7. WEAK CRYPTOGRAPHY
# CWE-327: Use of a Broken Crypto Algorithm
# CWE-328: Use of Weak Hash
# ═══════════════════════════════════════════════════════════════
def hash_password(password):
    # VULNERABLE: MD5 is cryptographically broken for passwords
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    # VULNERABLE: MD5 comparison, no salt
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # VULNERABLE: Storing MD5 hashed password
    password_hash = hash_password(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password_hash)
    )
    conn.commit()
    conn.close()

    return "User registered"


# ═══════════════════════════════════════════════════════════════
# 8. SERVER-SIDE REQUEST FORGERY (SSRF)
# CWE-918: Server-Side Request Forgery
# ═══════════════════════════════════════════════════════════════
@app.route("/fetch-url")
def fetch_url():
    url = request.args.get("url", "")

    # VULNERABLE: No URL validation — can access internal services
    response = requests.get(url)

    return response.text


@app.route("/proxy")
def proxy():
    target = request.args.get("target", "")

    # VULNERABLE: SSRF — user controls the request destination
    data = requests.get(target, timeout=5)

    return data.content


# ═══════════════════════════════════════════════════════════════
# 9. OPEN REDIRECT
# CWE-601: URL Redirection to Untrusted Site
# ═══════════════════════════════════════════════════════════════
@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next", "/")

    # VULNERABLE: Unvalidated redirect — phishing vector
    return redirect(next_url)


@app.route("/goto")
def goto():
    url = request.args.get("url", "/")

    # VULNERABLE: Open redirect
    return redirect(url)


# ═══════════════════════════════════════════════════════════════
# 10. INSECURE RANDOM NUMBER GENERATION
# CWE-330: Use of Insufficiently Random Values
# ═══════════════════════════════════════════════════════════════
def generate_session_token():
    # VULNERABLE: random module is not cryptographically secure
    token = "".join([str(random.randint(0, 9)) for _ in range(32)])
    return token


def generate_reset_token(user_id):
    # VULNERABLE: Predictable token generation
    token = hashlib.md5(f"{user_id}{random.randint(1, 1000)}".encode()).hexdigest()
    return token


@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form["email"]
    token = generate_reset_token(email)

    # In real app, this would be emailed
    return f"Reset token: {token}"


# ═══════════════════════════════════════════════════════════════
# 11. BONUS: YAML DESERIALIZATION
# CWE-502: Deserialization of Untrusted Data
# ═══════════════════════════════════════════════════════════════
import yaml

@app.route("/parse-yaml", methods=["POST"])
def parse_yaml():
    user_yaml = request.get_data(as_text=True)

    # VULNERABLE: yaml.load without SafeLoader allows code execution
    data = yaml.load(user_yaml)

    return str(data)


# ═══════════════════════════════════════════════════════════════
# 12. BONUS: DEBUG MODE IN PRODUCTION
# CWE-489: Active Debug Code
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # VULNERABLE: Debug mode exposes interactive debugger
    app.run(host="0.0.0.0", port=5000, debug=True)
