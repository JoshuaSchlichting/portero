# Portero Examples

This directory contains example configurations and test utilities for Portero.

## docker-compose.yml

A complete local testing stack that demonstrates:
- Portero reverse proxy with TLS termination
- Multiple HTTP backends with round-robin load balancing
- HTTPS backend with upstream TLS support
- Portero agents for automatic backend registration

### Usage

```bash
# From the examples directory
cd examples

# Build the images (from parent directory)
cd ..
docker build -t portero:latest .
docker build -t mock-backend:latest examples/mock-backend/
docker build -t portero-agent:latest ../portero-agent/

# Start the stack
cd examples
docker-compose up -d

# Test HTTP round-robin (example.com)
for i in {1..4}; do
  curl -k --resolve example.com:443:127.0.0.1 https://example.com/
done

# Test HTTPS backend (secure.example.com)
curl -k --resolve secure.example.com:443:127.0.0.1 https://secure.example.com/

# View metrics
curl http://127.0.0.1:18080/metrics

# View logs
docker-compose logs -f

# Cleanup
docker-compose down
```

### What's Running

- **portero** (172.20.0.10): Main reverse proxy
  - Port 443: TLS listener
  - Port 18080: Registration API
  - Port 8080: Optional HTTP listener

- **mock-backend** (172.20.0.2): HTTP backend #1
  - Registered as `example.com`
  - Port 8081 (host): Direct backend access

- **mock-backend-2** (172.20.0.3): HTTP backend #2
  - Registered as `example.com`
  - Port 8082 (host): Direct backend access

- **mock-backend-https** (172.20.0.5): HTTPS backend
  - Registered as `secure.example.com`
  - Uses self-signed certificate
  - Demonstrates upstream TLS

- **portero-agent**, **portero-agent-2**, **portero-agent-https**: Registration agents
  - Automatically register backends with Portero
  - Renew registrations periodically

## mock-backend

A simple Rust HTTP server used for testing Portero's load balancing and routing.

### Features

- Returns hostname in response for easy round-robin verification
- Configurable listen address via `MOCK_BACKEND_ADDR`
- Minimal dependencies (hyper, tokio)

### Building

```bash
cd mock-backend
cargo build --release
# Or with Docker
docker build -t mock-backend:latest .
```

### Running

```bash
# Listen on all IPv6 interfaces
MOCK_BACKEND_ADDR="[::]:8080" ./target/release/mock-backend

# Listen on IPv4
MOCK_BACKEND_ADDR="0.0.0.0:8080" ./target/release/mock-backend
```

## Notes

- **Certificates**: The docker-compose setup expects self-signed certificates in `../certs/`. Generate them with:
  ```bash
  cd ..
  mkdir -p certs/example.com certs/secure.example.com
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/example.com/privkey.pem \
    -out certs/example.com/cert.pem \
    -days 365 -subj "/CN=example.com"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/secure.example.com/privkey.pem \
    -out certs/secure.example.com/cert.pem \
    -days 365 -subj "/CN=secure.example.com"
  chmod 644 certs/*/privkey.pem
  ```

- **Static IPs**: The docker-compose file uses static IPs (172.20.0.x) to ensure consistent backend registration.

- **Development**: These examples are for local testing and development only. For production deployments, see the main documentation.