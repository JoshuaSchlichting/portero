#!/usr/bin/env python3
"""
Simple test backend server for testing Portero reverse proxy.

This server:
- Runs on port 8081
- Returns JSON responses with request info
- Shows which backend handled the request
- Useful for testing load balancing and proxying
"""

import http.server
import json
import os
import socketserver
import sys
from datetime import datetime

PORT = 8081
BACKEND_ID = os.environ.get("BACKEND_ID", "backend-1")


class TestBackendHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        response = {
            "backend_id": BACKEND_ID,
            "path": self.path,
            "method": "GET",
            "headers": dict(self.headers),
            "timestamp": datetime.now().isoformat(),
            "message": f"Hello from {BACKEND_ID}!",
        }

        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            post_json = json.loads(post_data.decode()) if post_data else {}
        except:
            post_json = {"raw_data": post_data.decode() if post_data else ""}

        response = {
            "backend_id": BACKEND_ID,
            "path": self.path,
            "method": "POST",
            "headers": dict(self.headers),
            "post_data": post_json,
            "timestamp": datetime.now().isoformat(),
            "message": f"POST received by {BACKEND_ID}!",
        }

        self.wfile.write(json.dumps(response, indent=2).encode())

    def log_message(self, format, *args):
        print(f"[{BACKEND_ID}] {datetime.now().strftime('%H:%M:%S')} - {format % args}")


if __name__ == "__main__":
    try:
        with socketserver.TCPServer(("", PORT), TestBackendHandler) as httpd:
            print(f"Test backend '{BACKEND_ID}' serving on port {PORT}")
            print(f"Visit: http://localhost:{PORT}")
            print("Press Ctrl+C to stop")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{BACKEND_ID} shutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
