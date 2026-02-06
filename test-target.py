#!/usr/bin/env python3
"""
Simple test target with fake credentials on the page.
Run this to test DNS rebinding attacks.

Usage: python3 test-target.py [port]
Default port: 8443
"""

import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443

HTML = '''<!DOCTYPE html>
<html>
<head><title>Internal Admin Panel</title></head>
<body style="font-family: sans-serif; padding: 40px; background: #1a1a2e; color: #eee;">
    <h1>🔐 Internal Admin Panel</h1>
    <p>Welcome to the super secret admin panel!</p>
    
    <h2>Database Credentials</h2>
    <pre style="background: #0d1117; padding: 15px; border-radius: 8px;">
DB_HOST=prod-db.internal.corp
DB_USER=admin
DB_PASS=SuperSecret123!
DB_NAME=customers
    </pre>
    
    <h2>API Keys</h2>
    <pre style="background: #0d1117; padding: 15px; border-radius: 8px;">
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SK=sk_live_51ABC123DEF456...
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
    </pre>
    
    <h2>Internal Endpoints</h2>
    <ul>
        <li><a href="/api/users">/api/users</a> - User database</li>
        <li><a href="/api/keys">/api/keys</a> - API key management</li>
        <li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
    </ul>
    
    <p style="color: #666; margin-top: 40px;">
        Server: internal-admin.corp:8443<br>
        Version: 2.3.1<br>
        Environment: PRODUCTION
    </p>
</body>
</html>
'''

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(HTML))
        self.end_headers()
        self.wfile.write(HTML.encode())
    
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} - {format % args}")

print(f'''
╔═══════════════════════════════════════════════════════════════════╗
║                    Test Target Server (HTTP)                      ║
╚═══════════════════════════════════════════════════════════════════╝

  Listening on: http://0.0.0.0:{PORT}
  
  This server has fake credentials on the page for testing
  DNS rebinding attacks.
  
  Test URLs:
    http://localhost:{PORT}/
    http://127.0.0.1:{PORT}/
  
  Press Ctrl+C to stop.
''')

server = http.server.HTTPServer(('0.0.0.0', PORT), Handler)

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\nShutting down...")
