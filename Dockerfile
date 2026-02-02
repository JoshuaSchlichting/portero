# syntax=docker/dockerfile:1

# ---------------------------
# Build stage
# ---------------------------
FROM rust:1.93-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    build-essential \
    git \
    ca-certificates \
    cmake \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY README.md ./README.md

# Build with optimizations
RUN cargo build --release

# ---------------------------
# Runtime stage
# ---------------------------
FROM debian:12-slim AS runtime

# Install runtime dependencies (certs for TLS, minimal tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -u 10001 -m -s /usr/sbin/nologin portero

# App directory
WORKDIR /opt/portero

# Copy binary from builder
COPY --from=builder /app/target/release/portero /usr/local/bin/portero

# TLS cert directory (mounted via volume in deployments)
# Expect structure:
# /etc/portero/certs/<default_sni>/cert.pem
# /etc/portero/certs/<default_sni>/privkey.pem
RUN mkdir -p /etc/portero/certs
VOLUME ["/etc/portero/certs"]

# Expose proxy TLS/HTTP listener and registration API
EXPOSE 443
EXPOSE 8080
EXPOSE 18080

# Environment defaults
ENV PORTERO_LOG=info

# Switch to non-root
USER portero

# Entrypoint: configurable via environment; defaults provided for local runs
# Override via:
#   docker run ... \
#     -e LISTEN_ADDR=0.0.0.0:443 \
#     -e REGISTER_ADDR=0.0.0.0:18080 \
#     -e TLS_CERT_DIR=/etc/portero/certs \
#     -e REGISTER_SECRET=changeme \
#     -e JWT_HMAC_KEY=changeme \
#     -p 443:443 -p 18080:18080 \
#     <image>
ENV LISTEN_ADDR=0.0.0.0:443
ENV REGISTER_ADDR=0.0.0.0:18080
ENV TLS_CERT_DIR=/etc/portero/certs
ENV REGISTER_SECRET=changeme
ENV JWT_HMAC_KEY=changeme

CMD ["/usr/local/bin/portero", \
    "--listen-addr", "0.0.0.0:443", \
    "--register-addr", "0.0.0.0:18080", \
    "--tls-cert-dir", "/etc/portero/certs", \
    "--register-secret", "changeme", \
    "--jwt-hmac-key", "changeme" \
    ]
