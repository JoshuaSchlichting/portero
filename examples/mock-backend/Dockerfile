# syntax=docker/dockerfile:1

# ---------------------------
# Build stage
# ---------------------------
FROM rust:1.93-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies first (copy manifest and source)
COPY Cargo.toml ./
COPY src ./src

# Build release binary
RUN cargo build --release

# ---------------------------
# Runtime stage
# ---------------------------
FROM debian:12-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -u 10011 -m -s /usr/sbin/nologin mockbackend

WORKDIR /opt/mock-backend

# Copy binary from builder
COPY --from=builder /app/target/release/mock-backend /usr/local/bin/mock-backend

# Default environment (overridable)
ENV MOCK_BACKEND_LOG=info
# Default bind address (IPv6 loopback: ::1:8080). Override via environment if needed.
ENV MOCK_BACKEND_ADDR=[::1]:8080

# Expose backend port (host publishing handled in docker-compose)
EXPOSE 8080

# Run as non-root
USER mockbackend

# Entrypoint/command: configurable via environment
CMD ["/usr/local/bin/mock-backend"]
