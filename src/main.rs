use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use clap::Parser;
use env_logger;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::{error, info, warn};
use pingora_core::listeners::TlsAccept;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::ErrorType;
use pingora_proxy::http_proxy_service;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::interval;

use hyper::service::{make_service_fn, service_fn};
use hyper::Server as HyperServer;
use hyper::{Body, Method, Request, Response, StatusCode};
mod registry;
mod tls;
use crate::registry::{Backend, Registry};
use crate::tls::{run_cert_refresh_task, tls_settings_with_callbacks, SniCallbacks, TlsCertStore};

// TLS certificate store and periodic refresh scaffolding for single SNI-enabled listener.

/// NOTE:
/// This file provides a minimal skeleton for a Pingora-based reverse proxy service
/// with dynamic backend registration. It sets up CLI, shared in-memory state with TTLs,
/// background expiration, and placeholders for Pingora HTTP proxy and registration API.
///
/// Pingora integration points are annotated with comments describing the expected hooks.
/// You should fill in the Pingora specifics according to your environment and cert layout.
///
/// This skeleton prefers explicit types, uses async Rust with Tokio, and keeps logic simple.

/// CLI for the Portero reverse proxy.
#[derive(Debug, Parser)]
#[command(
    name = "portero",
    version,
    about = "Pingora-based reverse proxy with dynamic backend registration"
)]
struct Cli {
    /// Public proxy listen address (terminates TLS and proxies traffic)
    #[arg(long)]
    listen_addr: String,

    /// Internal registration API listen address
    #[arg(long)]
    register_addr: String,

    /// Directory containing TLS certificates and private keys
    #[arg(long)]
    tls_cert_dir: String,

    /// Shared secret required for /register
    #[arg(long)]
    register_secret: String,

    /// JWT HMAC key for validating registration requests (HS256)
    #[arg(long)]
    jwt_hmac_key: String,

    /// Disable TLS and run plain HTTP proxy (for testing/development)
    #[arg(long, default_value_t = false)]
    no_tls: bool,

    /// HTTP listen address for ACME challenges and HTTPS redirects (e.g., "0.0.0.0:80")
    #[arg(long)]
    http_addr: Option<String>,

    /// Upstream address for ACME HTTP-01 challenges (e.g., "loadmaster:5002")
    #[arg(long)]
    acme_upstream: Option<String>,
}

/// Claims expected in the JWT used for registration auth.
#[derive(Debug, Serialize, Deserialize)]
struct RegisterClaims {
    /// The service_name the registering backend claims
    service_name: String,
    /// Standard expiration claim (required)
    exp: usize,
    /// Optional issued-at
    iat: Option<usize>,
    /// Optional audience
    aud: Option<String>,
    /// Optional issuer
    iss: Option<String>,
}

/// Backend endpoint for a service.
// Moved to module: see `registry::models::Backend`

// Moved to module: see `registry::models::Backend` methods `socket_addr` and `is_expired`

/// Runtime state for routing and registration.
// Moved to module: see `registry::models::Registry`

/// Shared application state held behind Arc<RwLock<...>>.
#[derive(Clone)]
struct AppState {
    registry: Arc<RwLock<Registry>>,
    register_secret: Arc<String>,
    jwt_hmac_key: Arc<String>,
}

impl AppState {
    fn new(register_secret: String, jwt_hmac_key: String) -> Self {
        Self {
            registry: Arc::new(RwLock::new(Registry::default())),
            register_secret: Arc::new(register_secret),
            jwt_hmac_key: Arc::new(jwt_hmac_key),
        }
    }
}

/// Registration payload (JSON)
#[derive(Debug, Deserialize)]
struct RegisterPayload {
    service_name: String,
    host: String, // IPv6 address (no brackets)
    port: u16,
    ttl_seconds: u64,
    use_tls: bool,
}

/// Validate registration auth via shared secret and JWT (HS256).
fn validate_registration_auth(
    expected_secret: &str,
    provided_secret: Option<&str>,
    jwt_hmac_key: &str,
    bearer_token: Option<&str>,
    expected_service_name: &str,
) -> Result<()> {
    // Shared secret validation
    let secret = provided_secret.ok_or_else(|| anyhow!("missing shared secret header"))?;
    if subtle_constant_time_eq(secret.as_bytes(), expected_secret.as_bytes()) == false {
        return Err(anyhow!("invalid shared secret"));
    }

    // JWT validation
    let token = bearer_token.ok_or_else(|| anyhow!("missing bearer token"))?;
    // Accept only HS256 algorithm
    let header = decode_header(token).context("invalid JWT header")?;
    if header.alg != Algorithm::HS256 {
        return Err(anyhow!("unsupported JWT algorithm"));
    }
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<RegisterClaims>(
        token,
        &DecodingKey::from_secret(jwt_hmac_key.as_bytes()),
        &validation,
    )
    .context("JWT validation failed")?;

    if token_data.claims.service_name != expected_service_name {
        return Err(anyhow!("JWT service_name mismatch"));
    }

    Ok(())
}

/// Constant-time equality for secrets.
fn subtle_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Handle POST /register requests.
/// This is a skeleton handler showing validation and registry update.
/// In a Pingora HTTP server, this would be invoked by a request routing hook.
async fn handle_register(
    state: &AppState,
    content_type: Option<&str>,
    secret_header: Option<&str>,
    bearer_token: Option<&str>,
    body: &[u8],
) -> Result<http::Response<Vec<u8>>> {
    // Validate content type
    if content_type.map(|ct| ct.to_ascii_lowercase()).as_deref() != Some("application/json") {
        let resp = http::Response::builder()
            .status(http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .body(b"Content-Type must be application/json".to_vec())
            .unwrap();
        return Ok(resp);
    }

    // Parse JSON
    let payload: RegisterPayload =
        serde_json::from_slice(body).context("invalid JSON payload for /register")?;

    // Auth
    if let Err(e) = validate_registration_auth(
        &state.register_secret,
        secret_header,
        &state.jwt_hmac_key,
        bearer_token,
        &payload.service_name,
    ) {
        let status = match e.to_string().as_str() {
            "missing shared secret header" | "missing bearer token" => {
                http::StatusCode::UNAUTHORIZED
            }
            "invalid shared secret" | "unsupported JWT algorithm" | "JWT service_name mismatch" => {
                http::StatusCode::FORBIDDEN
            }
            _ => http::StatusCode::UNAUTHORIZED,
        };

        let resp = http::Response::builder()
            .status(status)
            .body(format!("auth failed: {e}").into_bytes())
            .unwrap();
        return Ok(resp);
    }

    // Validate IP address format (IPv4 or IPv6)
    let addr: IpAddr = payload
        .host
        .parse()
        .context("host must be a valid IP address")?;

    // Update registry
    {
        let mut reg = state.registry.write().await;
        let backend = Backend {
            addr,
            port: payload.port,
            use_tls: payload.use_tls,
            // expires_at is computed inside upsert_backend; placeholder value here
            expires_at: Instant::now(),
        };
        reg.upsert_backend(
            &payload.service_name, // primary routing by Host header, but associate service_name
            &payload.service_name,
            backend,
            Duration::from_secs(payload.ttl_seconds),
        );
    }

    let resp = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(b"registered".to_vec())
        .unwrap();
    Ok(resp)
}

/// Background task that periodically purges expired backends.
async fn run_expiration_task(state: AppState) {
    let mut tick = interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let mut reg = state.registry.write().await;
        reg.purge_expired();
    }
}

/// Placeholder Pingora proxy service integration.
///
/// In Pingora's HTTP proxy framework, you typically:
/// - Implement a service struct and necessary hooks for request routing.
/// - Use Host header to select upstream backends.
/// - Implement connect logic to the chosen backend with fail-fast behavior.
/// - Configure TLS termination on the front listener using provided certs.
///
/// This skeleton outlines the structure. Fill in with actual Pingora APIs.
///
/// Example flow inside the proxy handler:
/// - Extract Host header.
/// - Lookup service_name mapping for the Host.
/// - Round-robin select a backend from registry.
/// - Attempt to connect; on failure, try next backend quickly.
/// - Proxy HTTP/1.1 or HTTP/2 depending on client protocol.
///
/// NOTE: Pingora concrete APIs may change; consult Pingora docs/examples.
mod proxy_skeleton {
    use super::*;

    /// Choose a backend by host header and service_name equal to host.
    pub async fn choose_backend(state: &AppState, host: &str) -> Option<SocketAddr> {
        let mut reg = state.registry.write().await;
        // For simplicity, map Host -> service_name equal to Host.
        reg.next_backend(host, host).map(|b| b.socket_addr())
    }
}

/// HTTP server for port 80 that:
/// - Forwards /.well-known/acme-challenge/* requests to the ACME upstream (e.g., loadmaster)
/// - Redirects all other requests to HTTPS
async fn run_http_redirect_server(http_addr: String, acme_upstream: Option<String>) -> Result<()> {
    info!("HTTP redirect server listening on {}", http_addr);
    if let Some(ref upstream) = acme_upstream {
        info!("ACME challenges will be forwarded to {}", upstream);
    }

    let acme_upstream = Arc::new(acme_upstream);

    let make_svc = {
        let acme_upstream = acme_upstream.clone();
        make_service_fn(move |_conn| {
            let acme_upstream = acme_upstream.clone();
            async move {
                Ok::<_, anyhow::Error>(service_fn(move |req: Request<Body>| {
                    let acme_upstream = acme_upstream.clone();
                    async move {
                        let path = req.uri().path();

                        // Check if this is an ACME challenge request
                        if path.starts_with("/.well-known/acme-challenge/") {
                            if let Some(ref upstream) = *acme_upstream {
                                // Forward to ACME upstream
                                match forward_acme_challenge(req, upstream).await {
                                    Ok(resp) => return Ok::<_, anyhow::Error>(resp),
                                    Err(e) => {
                                        error!("Failed to forward ACME challenge: {}", e);
                                        let resp = Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .body(Body::from(format!("ACME proxy error: {}", e)))
                                            .unwrap();
                                        return Ok(resp);
                                    }
                                }
                            } else {
                                // No ACME upstream configured
                                let resp = Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("ACME upstream not configured"))
                                    .unwrap();
                                return Ok(resp);
                            }
                        }

                        // Redirect to HTTPS
                        let host = req
                            .headers()
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .map(|h| h.split(':').next().unwrap_or(h)) // Strip port if present
                            .unwrap_or("localhost");

                        let uri = req.uri();
                        let path_and_query =
                            uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

                        let https_url = format!("https://{}{}", host, path_and_query);

                        info!("Redirecting HTTP request to {}", https_url);

                        let resp = Response::builder()
                            .status(StatusCode::MOVED_PERMANENTLY)
                            .header("Location", https_url)
                            .body(Body::from("Redirecting to HTTPS"))
                            .unwrap();

                        Ok::<_, anyhow::Error>(resp)
                    }
                }))
            }
        })
    };

    let server = HyperServer::bind(&http_addr.parse()?).serve(make_svc);
    server
        .await
        .map_err(|e| anyhow!("HTTP redirect server error: {e}"))?;
    Ok(())
}

/// Forward an ACME challenge request to the upstream server
async fn forward_acme_challenge(req: Request<Body>, upstream: &str) -> Result<Response<Body>> {
    use hyper::Client;

    let client = Client::new();

    let original_host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let upstream_uri: hyper::Uri = format!("http://{}{}", upstream, path_and_query)
        .parse()
        .context("invalid upstream URI")?;

    info!("Forwarding ACME challenge to {}", upstream_uri);

    let (parts, body) = req.into_parts();

    let mut upstream_req = Request::builder().method(parts.method).uri(upstream_uri);

    for (key, value) in parts.headers.iter() {
        if key != "host" {
            upstream_req = upstream_req.header(key, value);
        }
    }

    if let Some(host) = original_host {
        upstream_req = upstream_req.header("Host", host);
    }

    let upstream_req = upstream_req
        .body(body)
        .context("failed to build upstream request")?;

    let resp = client
        .request(upstream_req)
        .await
        .context("failed to forward request to ACME upstream")?;

    Ok(resp)
}

/// Placeholder registration HTTP server skeleton.
///
/// In practice, you would run a lightweight HTTP server for /register on `register_addr`.
/// If you prefer to use Pingora itself for this, set up a separate listener or route path.
///
/// This function demonstrates request parsing and handler invocation signature.
/// Replace it with Pingora's HTTP server or your chosen HTTP server.
async fn run_registration_api(state: AppState, register_addr: String) -> Result<()> {
    info!("Registration API listening on {}", register_addr);

    let make_svc = {
        let state = state.clone();
        make_service_fn(move |_conn| {
            let state = state.clone();
            async move {
                Ok::<_, anyhow::Error>(service_fn(move |req: Request<Body>| {
                    let state = state.clone();
                    async move {
                        if req.method() == Method::GET && req.uri().path() == "/health" {
                            // Simple health check: returns 200 OK
                            let resp = Response::new(Body::from("ok"));
                            Ok::<_, anyhow::Error>(resp)
                        } else if req.method() == Method::GET && req.uri().path() == "/metrics" {
                            // Basic Prometheus-style metrics for registry
                            let reg = state.registry.read().await;
                            let mut host_count = 0usize;
                            let mut service_count = 0usize;
                            let mut backend_count = 0usize;
                            for (_host, services) in reg.hosts.iter() {
                                host_count += 1;
                                for (_svc, queue) in services.iter() {
                                    service_count += 1;
                                    backend_count += queue.len();
                                }
                            }
                            let metrics = format!(
                                "portero_registry_hosts {}\nportero_registry_services {}\nportero_registry_backends {}\n",
                                host_count, service_count, backend_count
                            );
                            let resp = Response::new(Body::from(metrics));
                            Ok::<_, anyhow::Error>(resp)
                        } else if req.method() == Method::POST && req.uri().path() == "/register" {
                            // Extract headers
                            let (parts, body_stream) = req.into_parts();
                            let headers = parts.headers;

                            let content_type = headers
                                .get(http::header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok());
                            let secret_header = headers
                                .get("X-Register-Secret")
                                .and_then(|v| v.to_str().ok());
                            let bearer_token = headers
                                .get(http::header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.trim()));

                            // Read body
                            let whole = hyper::body::to_bytes(body_stream)
                                .await
                                .map_err(|e| anyhow!("failed to read request body: {e}"))?;
                            let resp = handle_register(
                                &state,
                                content_type,
                                secret_header,
                                bearer_token,
                                &whole,
                            )
                            .await
                            .unwrap_or_else(|e| {
                                http::Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(format!("error: {e}").into_bytes())
                                    .unwrap()
                            });

                            let (parts, body) = resp.into_parts();
                            let response = Response::from_parts(parts, Body::from(body));
                            Ok::<_, anyhow::Error>(response)
                        } else {
                            let mut resp = Response::new(Body::from("not found"));
                            *resp.status_mut() = StatusCode::NOT_FOUND;
                            Ok::<_, anyhow::Error>(resp)
                        }
                    }
                }))
            }
        })
    };

    let server = HyperServer::bind(&register_addr.parse()?).serve(make_svc);
    server
        .await
        .map_err(|e| anyhow!("registration server error: {e}"))?;
    Ok(())
}

/// Configure TLS for Pingora front listener from the provided cert directory.
///
/// Pingora generally supports loading multiple certs and private keys, SNI, etc.
/// Here we only outline the intention; the exact loading depends on your cert layout.
///
/// TODO: Implement reading PEM files from tls_cert_dir and wiring them into Pingora's TLS config.
/* configure_pingora_tls removed: rustls-specific helper is no longer needed with BoringSSL/OpenSSL.
TLS listener configuration now uses TlsSettings::intermediate with PEM paths directly. */

/// Start the Pingora-based proxy service.
///
/// TODO: Instantiate Pingora server, configure TLS listener at `listen_addr`,
/// and register the HTTP proxy service using hooks described above.
fn run_pingora_proxy(
    state: AppState,
    listen_addr: String,
    tls_cert_dir: String,
    register_addr: String,
    no_tls: bool,
    http_addr: Option<String>,
    acme_upstream: Option<String>,
) -> Result<()> {
    info!("Proxy listening (TCP) on {}", listen_addr);

    // Create Tokio runtime for Pingora to use
    let mut my_opt = pingora_core::server::configuration::Opt::default();
    my_opt.upgrade = false;
    my_opt.daemon = false;
    my_opt.nocapture = false;
    my_opt.test = false;
    my_opt.conf = None;

    // Initialize Pingora server with runtime
    let mut server = Server::new(Some(my_opt)).context("create Pingora server")?;

    // Define PorteroProxy implementing ProxyHttp with round-robin backend selection
    struct PorteroProxy {
        state: AppState,
    }

    /// Per-request context for logging and metrics
    struct RequestCtx {
        start_time: Instant,
    }

    #[async_trait]
    impl ProxyHttp for PorteroProxy {
        type CTX = RequestCtx;

        fn new_ctx(&self) -> Self::CTX {
            RequestCtx {
                start_time: Instant::now(),
            }
        }

        async fn upstream_peer(
            &self,
            session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> pingora_core::Result<Box<HttpPeer>> {
            // Get Host from the Host header (HTTP/1.1) or :authority pseudo-header (HTTP/2)
            // The URI's host() is only set for absolute URIs, not typical relative requests
            let host = session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h)) // Strip port if present
                .unwrap_or_default()
                .to_string();

            let mut reg = self.state.registry.write().await;
            let backend = match reg.next_backend(&host, &host) {
                Some(b) => b,
                None => {
                    return Err(pingora_core::Error::explain(
                        ErrorType::InternalError,
                        "no backend for host",
                    )
                    .into());
                }
            };

            // Upstream may use TLS (HTTPS) to IPv6 backend with SNI set to Host, based on registration
            let mut peer = Box::new(HttpPeer::new(
                backend.socket_addr(),
                backend.use_tls,
                host.clone(),
            ));

            // Disable certificate verification for upstream TLS connections (self-signed certs)
            if backend.use_tls {
                peer.options.verify_cert = false;
            }

            Ok(peer)
        }

        async fn upstream_request_filter(
            &self,
            session: &mut Session,
            upstream_request: &mut pingora_http::RequestHeader,
            _ctx: &mut Self::CTX,
        ) -> pingora_core::Result<()> {
            // Ensure Host header is present upstream if client provided one
            if let Some(host_val) = session.req_header().headers.get("host") {
                // Insert or overwrite Host header upstream
                if let Ok(host_str) = host_val.to_str() {
                    upstream_request.insert_header("Host", host_str).ok();
                }
            }
            Ok(())
        }

        async fn logging(
            &self,
            session: &mut Session,
            e: Option<&pingora_core::Error>,
            ctx: &mut Self::CTX,
        ) {
            let elapsed = ctx.start_time.elapsed();
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();
            let host = session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");

            // Get response status if available
            let status = session
                .response_written()
                .map(|resp| resp.status.as_u16())
                .unwrap_or(0);

            // Get client address
            let client_addr = session
                .client_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "-".to_string());

            if let Some(err) = e {
                warn!(
                    "{} - {} {} {} - {} - {:?} - error: {}",
                    client_addr, method, host, path, status, elapsed, err
                );
            } else {
                info!(
                    "{} - {} {} {} - {} - {:?}",
                    client_addr, method, host, path, status, elapsed
                );
            }
        }
    }

    // Create the proxy service and add a TCP listener
    let mut proxy = http_proxy_service(
        &server.configuration,
        PorteroProxy {
            state: state.clone(),
        },
    );
    // Initialize TLS cert store
    let cert_store = Arc::new(RwLock::new(
        TlsCertStore::load_from_dir(&tls_cert_dir).unwrap_or_default(),
    ));

    // Add a TLS listener using callbacks for SNI selection with default cert fallback
    let default_sni = {
        // Get the default SNI from the loaded cert store
        let store = TlsCertStore::load_from_dir(&tls_cert_dir).unwrap_or_default();
        store.default_sni.clone()
    };

    if no_tls {
        // Plain HTTP mode - add TCP listener without TLS
        proxy.add_tcp(&listen_addr);
        info!("Plain HTTP listener added on {}", listen_addr);
    } else if let Some(sni) = default_sni {
        let cert_path = std::path::Path::new(&tls_cert_dir)
            .join(&sni)
            .join("cert.pem");
        let key_path = std::path::Path::new(&tls_cert_dir)
            .join(&sni)
            .join("privkey.pem");
        if cert_path.is_file() && key_path.is_file() {
            // Use intermediate settings with default cert as a fallback until callbacks are implemented
            let callbacks: Box<dyn TlsAccept + Send + Sync> = Box::new(SniCallbacks {
                cache: cert_store.clone(),
                default_sni: sni.clone(),
            });
            let tls_settings = tls_settings_with_callbacks(callbacks)?;
            // Bind a single TLS listener on the same address; Pingora will serve TLS on this port
            proxy.add_tls_with_settings(&listen_addr, None, tls_settings);
            info!("TLS listener added with callbacks and default SNI {}", sni);
        } else {
            warn!(
                "Default SNI {} missing cert.pem or privkey.pem under {}",
                sni, tls_cert_dir
            );
        }
    } else {
        warn!(
            "No TLS certs found under {}, TLS listener not added",
            tls_cert_dir
        );
    }

    // Add service
    server.add_service(proxy);

    // Bootstrap the server - this sets up the runtime
    server.bootstrap();

    // Now we have a runtime available, spawn background tasks
    let cert_refresh_store = cert_store.clone();
    let cert_refresh_dir = tls_cert_dir.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            run_cert_refresh_task(
                cert_refresh_store,
                cert_refresh_dir,
                Duration::from_secs(30),
            )
            .await;
        });
    });

    let exp_state = state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            run_expiration_task(exp_state).await;
        });
    });

    let reg_state = state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            if let Err(e) = run_registration_api(reg_state, register_addr).await {
                error!("registration API error: {e:?}");
            }
        });
    });

    // Start HTTP redirect server if configured
    if let Some(http_addr) = http_addr {
        let acme_upstream = acme_upstream.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                if let Err(e) = run_http_redirect_server(http_addr, acme_upstream).await {
                    error!("HTTP redirect server error: {e:?}");
                }
            });
        });
    }

    // Run the server
    server.run_forever()
}

fn main() -> Result<()> {
    // Logging
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("PORTERO_LOG", "info"))
        .init();

    // CLI
    let cli = Cli::parse();

    // Build shared state
    let state = AppState::new(cli.register_secret.clone(), cli.jwt_hmac_key.clone());

    // Run Pingora proxy (this will handle its own runtime and block)
    run_pingora_proxy(
        state,
        cli.listen_addr.clone(),
        cli.tls_cert_dir.clone(),
        cli.register_addr.clone(),
        cli.no_tls,
        cli.http_addr.clone(),
        cli.acme_upstream.clone(),
    )
}
