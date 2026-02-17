# Portero

## Nightly Docker image (GHCR)

For early testing, you can pull and run the latest nightly container image from GitHub Container Registry (GHCR).

Pull the nightly image:

- `docker pull ghcr.io/JoshuaSchlichting/portero:nightly`

Run it (recommended for Linux performance testing: host networking):

- `docker run --rm --network host ghcr.io/JoshuaSchlichting/portero:nightly --help`

Notes:
- Replace `JoshuaSchlichting/portero` with your GitHub repository (for example: `ghcr.io/joshuaschlichting/portero:nightly`).
- If the image is private, you must authenticate first:
  - `echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin`
- The `nightly` tag is intentionally moving and will be overwritten on each push to the default branch.


Portero is a reverse proxy written in Rust on top of Cloudflare’s Pingora framework. It terminates TLS, supports HTTP/1.1 and HTTP/2 (via ALPN), proxies to upstream backends over TLS with SNI, and provides a simple registration API to dynamically add backends at runtime.
Status: Pre-1.0 (experimental) — not production-ready until 1.0.

Key features
- TLS termination with multi-domain SNI on a single listener (BoringSSL/OpenSSL backend).
- Cert hot-reload without restarts: PEMs are parsed into X509/PKey objects and cached; the handshake uses cached objects (no per-handshake file I/O).
- HTTP/1.1 and HTTP/2 (ALPN prefers h2, falls back to h1).
- Dynamic backend registration with a small internal API, authenticated by a shared secret and a JWT (HS256).
- Round-robin load balancing across registered backends per host/service.

## TLS certificates

Portero scans a directory for per-domain certificate folders:
- Recommended path: `/etc/portero/certs`
- Layout:
  - `/etc/portero/certs/<sni>/cert.pem`
  - `/etc/portero/certs/<sni>/privkey.pem`

Notes
- The first discovered domain becomes the default SNI fallback.
- The process periodically (default ~30s) rescans the directory:
  - Reads PEMs, parses them into X509 chains and private keys.
  - Detects changes via mtime and content hash.
  - Swaps an in-memory cache atomically.
- During the TLS handshake, SNI callbacks pick the correct cached cert/key for the requested hostname.

## Registration API (auth with shared secret + JWT)

A small internal HTTP endpoint is used to register backends dynamically:

- Endpoint: `POST /register`
- Auth:
  - Header `X-Register-Secret` must match the configured shared secret.
  - Header `Authorization: Bearer <JWT>` must be a valid HS256 token signed with the configured HMAC key.
  - The JWT must include `service_name` and a valid `exp`. The `service_name` in the token must match the request payload.
- Payload (JSON):
  - `service_name` (string)
  - `host` (IPv6 address without brackets)
  - `port` (u16)
  - `ttl_seconds` (u64)
  - `use_tls` (bool) — whether to use HTTPS for upstream connections

Behavior
- On success, the backend is inserted/updated and will be served for its `service_name` (by Host).
- Round-robin is used among active backends.
- Expired entries are purged automatically.

Why both secret and JWT?
- Defense-in-depth. The shared secret is a coarse access gate. The JWT provides per-service identity with an expiry and can be validated independently (HS256).

## Upstream proxying

- Requests are proxied upstream either over TLS (HTTPS) or plain HTTP, based on the per-backend `use_tls` flag.
- When using TLS, upstream SNI is set to the incoming Host header.
- HTTP/2/H1 to clients is handled via ALPN; upstream behavior is configured per `HttpPeer`.

## Build and run

This project uses upstream Pingora from GitHub with the BoringSSL backend enabled.

- Dependencies:
  - Requires `cmake` for building BoringSSL (install via package manager)
- Build:
  - `cargo build` (debug) or `cargo build --release`
- Run (example):
  - Binary flags:
    - `--listen-addr 0.0.0.0:443` (TLS) or `--listen-addr 0.0.0.0:8080` (plain HTTP for local testing)
    - `--register-addr 127.0.0.1:18080`
    - `--tls-cert-dir /etc/portero/certs`
    - `--register-secret <secret>`
    - `--jwt-hmac-key <hs256-key>`
  - Example:
    - `./target/debug/portero --listen-addr 0.0.0.0:443 --register-addr 127.0.0.1:18080 --tls-cert-dir /etc/portero/certs --register-secret changeme --jwt-hmac-key changeme`

Quick test
- Prepare certs for two domains:
  - `~/.loadmaster/certs/example.com/{cert.pem,privkey.pem}`
  - `~/.loadmaster/certs/example.org/{cert.pem,privkey.pem}`
- Start Portero, then test:
  - `curl --resolve example.com:443:127.0.0.1 https://example.com/ -v`
  - `curl --resolve example.org:443:127.0.0.1 https://example.org/ -v`
- Expect: each domain serves its own certificate and negotiates h2 when supported.

## Repository structure

- `src/main.rs`: CLI, logging, service wiring (registry, TLS, proxy, registration API).
- `src/tls/`
  - `cert_cache.rs`: in-memory cert store, hot-reload task, PEM parsing to X509/PKey.
  - `sni_callbacks.rs`: TLS SNI callback that assigns cert/key from the cache to the handshake.
  - `mod.rs`: exports and helper to build `TlsSettings` with callbacks (ALPN enabled).
- `src/registry/`
  - `models.rs`: `Backend`, `Registry` (round-robin, purge).
  - `mod.rs`: re-exports.

## Operational notes

- Cert hot-reload: place/replace `cert.pem` and `privkey.pem` in the per-domain directories; new handshakes will use the updated materials after the next scan.
- Authentication: keep the registration secret and HMAC key secure (environment or secret store). Rotate JWT HMAC as needed; tokens must be HS256.
- Observability: tracing logs can be extended to emit SNI selection decisions and cache hits/misses.
- Listener: single TLS listener with multi-domain SNI; no per-handshake file I/O.

## Limitations / future work

- Registration API is intentionally minimal; add rate limiting or mTLS as needed.
- Consider additional JWT claims validation (aud/iss) for stricter environments.
- Add more metrics around TLS handshakes, cert reloads, and registry activity.
