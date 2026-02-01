#!/bin/bash
set -e

# Test script for Portero reverse proxy
# Tests multi-domain SNI, backend registration, JWT auth, and HTTP/2

PORTERO_BIN="./target/release/portero"
TEST_CERTS_DIR="/tmp/portero-test/certs"
BACKEND_PORT=8081
PROXY_PORT=8443
REGISTER_PORT=8080
REGISTER_SECRET="test-secret-123"
JWT_HMAC_KEY="test-hmac-key-456"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test processes..."

    # Kill background processes
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        wait $BACKEND_PID 2>/dev/null || true
    fi

    if [ ! -z "$PORTERO_PID" ]; then
        kill $PORTERO_PID 2>/dev/null || true
        wait $PORTERO_PID 2>/dev/null || true
    fi

    # Clean up test certificates
    rm -rf /tmp/portero-test

    log_info "Cleanup complete"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [ ! -f "$PORTERO_BIN" ]; then
        log_error "Portero binary not found at $PORTERO_BIN"
        log_info "Run: cargo build --release"
        exit 1
    fi

    if ! command -v python3 &> /dev/null; then
        log_error "python3 is required for the test backend"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_error "curl is required for testing"
        exit 1
    fi

    if ! command -v openssl &> /dev/null; then
        log_error "openssl is required for certificate generation"
        exit 1
    fi

    log_success "All prerequisites satisfied"
}

# Create test certificates
create_test_certs() {
    log_info "Creating test certificates..."

    # Clean up any existing test certs
    rm -rf $TEST_CERTS_DIR
    mkdir -p $TEST_CERTS_DIR/{localhost,example.test}

    # Create localhost certificate
    openssl req -x509 -newkey rsa:2048 \
        -keyout $TEST_CERTS_DIR/localhost/privkey.pem \
        -out $TEST_CERTS_DIR/localhost/cert.pem \
        -days 30 -nodes -subj "/CN=localhost" \
        &>/dev/null

    # Create example.test certificate
    openssl req -x509 -newkey rsa:2048 \
        -keyout $TEST_CERTS_DIR/example.test/privkey.pem \
        -out $TEST_CERTS_DIR/example.test/cert.pem \
        -days 30 -nodes -subj "/CN=example.test" \
        &>/dev/null

    log_success "Test certificates created in $TEST_CERTS_DIR"
}

# Start test backend server
start_backend() {
    log_info "Starting test backend server on port $BACKEND_PORT..."

    python3 test_backend.py &
    BACKEND_PID=$!

    # Wait for backend to start
    sleep 2

    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        log_error "Failed to start backend server"
        exit 1
    fi

    # Test backend is responding
    if curl -s http://localhost:$BACKEND_PORT/ >/dev/null; then
        log_success "Backend server started (PID: $BACKEND_PID)"
    else
        log_error "Backend server not responding"
        exit 1
    fi
}

# Start Portero proxy
start_portero() {
    log_info "Starting Portero proxy..."

    $PORTERO_BIN \
        --listen-addr "0.0.0.0:$PROXY_PORT" \
        --register-addr "127.0.0.1:$REGISTER_PORT" \
        --tls-cert-dir "$TEST_CERTS_DIR" \
        --register-secret "$REGISTER_SECRET" \
        --jwt-hmac-key "$JWT_HMAC_KEY" &

    PORTERO_PID=$!

    # Wait for Portero to start
    sleep 3

    if ! kill -0 $PORTERO_PID 2>/dev/null; then
        log_error "Failed to start Portero proxy"
        exit 1
    fi

    log_success "Portero proxy started (PID: $PORTERO_PID)"
}

# Generate JWT token for registration
generate_jwt() {
    local service_name="$1"
    local exp=$(($(date +%s) + 3600))  # 1 hour from now

    # Simple JWT generation using Python
    python3 -c "
import hmac
import hashlib
import json
import base64
import time

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

header = {'typ': 'JWT', 'alg': 'HS256'}
payload = {
    'service_name': '$service_name',
    'exp': $exp,
    'iat': int(time.time())
}

header_b64 = base64url_encode(json.dumps(header).encode())
payload_b64 = base64url_encode(json.dumps(payload).encode())
message = f'{header_b64}.{payload_b64}'

signature = hmac.new(
    b'$JWT_HMAC_KEY',
    message.encode(),
    hashlib.sha256
).digest()
signature_b64 = base64url_encode(signature)

print(f'{message}.{signature_b64}')
"
}

# Register backend with Portero
register_backend() {
    local service_name="$1"
    local host="$2"
    local port="$3"

    log_info "Registering backend: $service_name -> $host:$port"

    local jwt_token=$(generate_jwt "$service_name")

    local response=$(curl -s -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "X-Register-Secret: $REGISTER_SECRET" \
        -H "Authorization: Bearer $jwt_token" \
        -d "{\"service_name\":\"$service_name\",\"host\":\"$host\",\"port\":$port,\"ttl_seconds\":3600}" \
        http://localhost:$REGISTER_PORT/register)

    local http_code="${response: -3}"
    local body="${response%???}"

    if [ "$http_code" = "200" ]; then
        log_success "Backend registered successfully"
        return 0
    else
        log_error "Failed to register backend (HTTP $http_code): $body"
        return 1
    fi
}

# Test TLS connection and SNI
test_tls_sni() {
    local hostname="$1"

    log_info "Testing TLS/SNI for $hostname..."

    # Test TLS connection and certificate
    local cert_info=$(echo | openssl s_client -servername "$hostname" -connect localhost:$PROXY_PORT 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)

    if echo "$cert_info" | grep -q "CN = $hostname" || echo "$cert_info" | grep -q "CN=$hostname"; then
        log_success "TLS/SNI working for $hostname - correct certificate served"
        return 0
    else
        log_error "TLS/SNI failed for $hostname - wrong certificate: $cert_info"
        return 1
    fi
}

# Test HTTP request through proxy
test_http_request() {
    local hostname="$1"
    local path="${2:-/}"

    log_info "Testing HTTP request: $hostname$path"

    local response=$(curl -k -s -H "Host: $hostname" \
        --resolve "$hostname:$PROXY_PORT:127.0.0.1" \
        "https://$hostname:$PROXY_PORT$path" 2>/dev/null)

    if echo "$response" | grep -q "backend_id"; then
        log_success "HTTP request successful for $hostname$path"
        echo "$response" | jq . 2>/dev/null || echo "$response"
        return 0
    else
        log_error "HTTP request failed for $hostname$path: $response"
        return 1
    fi
}

# Test HTTP/2
test_http2() {
    local hostname="$1"

    log_info "Testing HTTP/2 support for $hostname..."

    local protocol=$(curl -k -s -w "%{http_version}" -o /dev/null \
        --http2 -H "Host: $hostname" \
        --resolve "$hostname:$PROXY_PORT:127.0.0.1" \
        "https://$hostname:$PROXY_PORT/")

    if [ "$protocol" = "2" ]; then
        log_success "HTTP/2 working for $hostname"
        return 0
    else
        log_warn "HTTP/2 not used for $hostname (got HTTP/$protocol)"
        return 1
    fi
}

# Main test sequence
run_tests() {
    log_info "Starting Portero test suite..."

    # Setup
    check_prerequisites
    create_test_certs
    start_backend
    start_portero

    # Register backends
    register_backend "localhost" "127.0.0.1" $BACKEND_PORT
    register_backend "example.test" "127.0.0.1" $BACKEND_PORT

    # Give time for registration to take effect
    sleep 1

    # Test TLS/SNI
    test_tls_sni "localhost"
    test_tls_sni "example.test"

    # Test HTTP requests
    test_http_request "localhost"
    test_http_request "example.test"
    test_http_request "localhost" "/test-path"

    # Test HTTP/2 (optional - may not work in all environments)
    if command -v curl --help | grep -q "http2"; then
        test_http2 "localhost"
        test_http2 "example.test"
    else
        log_warn "Skipping HTTP/2 test - curl doesn't support --http2"
    fi

    log_success "All tests completed!"

    # Show final status
    echo
    log_info "Test Summary:"
    echo "- Backend server: http://localhost:$BACKEND_PORT (PID: $BACKEND_PID)"
    echo "- Portero proxy: https://localhost:$PROXY_PORT (PID: $PORTERO_PID)"
    echo "- Registration API: http://localhost:$REGISTER_PORT"
    echo "- Certificates: $TEST_CERTS_DIR"
    echo
    log_info "Manual testing commands:"
    echo "  curl -k --resolve localhost:$PROXY_PORT:127.0.0.1 https://localhost:$PROXY_PORT/"
    echo "  curl -k --resolve example.test:$PROXY_PORT:127.0.0.1 https://example.test:$PROXY_PORT/"
    echo
    log_info "Press Ctrl+C to stop servers and clean up"

    # Keep running for manual testing
    wait
}

# Run the test suite
run_tests
