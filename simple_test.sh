#!/bin/bash

# Simple manual test for Portero
# Run this to test basic functionality after building

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
PORTERO_BIN="./target/release/portero"
TEST_CERTS_DIR="/tmp/portero-test/certs"
BACKEND_PORT=8081
PROXY_PORT=8443
REGISTER_PORT=8080
REGISTER_SECRET="test-secret-123"
JWT_HMAC_KEY="test-hmac-key-456"

# Check if portero binary exists
if [ ! -f "$PORTERO_BIN" ]; then
    log_error "Portero binary not found. Run: cargo build --release"
    exit 1
fi

log_info "Setting up test environment..."

# Clean up any existing test setup
rm -rf /tmp/portero-test
mkdir -p $TEST_CERTS_DIR/{localhost,example.test}

# Create test certificates
log_info "Creating test certificates..."
openssl req -x509 -newkey rsa:2048 \
    -keyout $TEST_CERTS_DIR/localhost/privkey.pem \
    -out $TEST_CERTS_DIR/localhost/cert.pem \
    -days 30 -nodes -subj "/CN=localhost" \
    &>/dev/null

openssl req -x509 -newkey rsa:2048 \
    -keyout $TEST_CERTS_DIR/example.test/privkey.pem \
    -out $TEST_CERTS_DIR/example.test/cert.pem \
    -days 30 -nodes -subj "/CN=example.test" \
    &>/dev/null

log_success "Test certificates created in $TEST_CERTS_DIR"

# Create test backend server script
cat > /tmp/test_backend.py << 'EOF'
#!/usr/bin/env python3
import http.server
import json
import socketserver
import sys
from datetime import datetime

PORT = 8081

class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        response = {
            "message": "Hello from test backend!",
            "path": self.path,
            "method": "GET",
            "timestamp": datetime.now().isoformat(),
            "headers": dict(self.headers)
        }

        self.wfile.write(json.dumps(response, indent=2).encode())

    def log_message(self, format, *args):
        print(f"[BACKEND] {datetime.now().strftime('%H:%M:%S')} - {format % args}")

if __name__ == "__main__":
    try:
        with socketserver.TCPServer(("", PORT), TestHandler) as httpd:
            print(f"Test backend serving on port {PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBackend shutting down...")
        sys.exit(0)
EOF

chmod +x /tmp/test_backend.py

log_info "Starting test backend server on port $BACKEND_PORT..."
python3 /tmp/test_backend.py &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 2

# Test backend is working
if curl -s http://localhost:$BACKEND_PORT/ >/dev/null; then
    log_success "Backend server started (PID: $BACKEND_PID)"
else
    log_error "Backend server failed to start"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    kill $BACKEND_PID 2>/dev/null || true
    rm -rf /tmp/portero-test /tmp/test_backend.py
    log_info "Cleanup complete"
}

trap cleanup EXIT INT TERM

log_info "Test setup complete!"
echo
log_info "Now run Portero in another terminal:"
echo "  $PORTERO_BIN \\"
echo "    --listen-addr 0.0.0.0:$PROXY_PORT \\"
echo "    --register-addr 127.0.0.1:$REGISTER_PORT \\"
echo "    --tls-cert-dir $TEST_CERTS_DIR \\"
echo "    --register-secret $REGISTER_SECRET \\"
echo "    --jwt-hmac-key $JWT_HMAC_KEY"
echo
log_info "Then test with these commands:"
echo
echo "# Test backend registration (generate JWT token and register):"
echo "JWT_TOKEN=\$(python3 -c \""
echo "import hmac, hashlib, json, base64, time"
echo "def b64(data): return base64.urlsafe_b64encode(data).decode().rstrip('=')"
echo "header = b64(json.dumps({'typ':'JWT','alg':'HS256'}).encode())"
echo "payload = b64(json.dumps({'service_name':'localhost','exp':int(time.time())+3600}).encode())"
echo "msg = f'{header}.{payload}'"
echo "sig = b64(hmac.new(b'$JWT_HMAC_KEY', msg.encode(), hashlib.sha256).digest())"
echo "print(f'{msg}.{sig}')"
echo "\")"
echo
echo "curl -H 'Content-Type: application/json' \\"
echo "     -H 'X-Register-Secret: $REGISTER_SECRET' \\"
echo "     -H \"Authorization: Bearer \$JWT_TOKEN\" \\"
echo "     -d '{\"service_name\":\"localhost\",\"host\":\"127.0.0.1\",\"port\":$BACKEND_PORT,\"ttl_seconds\":3600}' \\"
echo "     http://localhost:$REGISTER_PORT/register"
echo
echo "# Test HTTPS requests with SNI:"
echo "curl -k --resolve localhost:$PROXY_PORT:127.0.0.1 https://localhost:$PROXY_PORT/"
echo "curl -k --resolve example.test:$PROXY_PORT:127.0.0.1 https://example.test:$PROXY_PORT/"
echo
echo "# Test certificate SNI:"
echo "echo | openssl s_client -servername localhost -connect localhost:$PROXY_PORT 2>/dev/null | openssl x509 -noout -subject"
echo "echo | openssl s_client -servername example.test -connect localhost:$PROXY_PORT 2>/dev/null | openssl x509 -noout -subject"
echo
echo "# Test HTTP/2:"
echo "curl -k --http2 -I --resolve localhost:$PROXY_PORT:127.0.0.1 https://localhost:$PROXY_PORT/"
echo
log_info "Backend server is running. Press Ctrl+C to stop and cleanup."

# Keep backend running
wait $BACKEND_PID
