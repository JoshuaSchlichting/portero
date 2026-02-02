#![allow(dead_code)]

use std::io::Read;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::sleep;

/// Integration test scaffolding for exercising registration and routing with `use_tls` true/false.
///
/// Notes:
/// - The Portero project currently builds a binary (no public library API),
///   so we launch the `portero` binary in a child process for end-to-end tests.
/// - We spin up minimal mock backends:
///   - HTTP backend (hyper)
///   - HTTPS backend: TODO (requires cert/key generation and TLS server wiring).
/// - Tests are marked `#[ignore]` initially to avoid failing the test suite until TLS scaffolding is complete.
/// - These tests assume the `portero` binary is built at `target/debug/portero`.
///
/// Running:
///   cargo test --test integration_http_https -- --ignored
///
/// Future improvements:
/// - Generate ephemeral self-signed certs for the HTTPS backend and mount in a temp dir.
/// - Configure Portero’s TLS listener with default certs and SNI.
/// - Replace println! logging in binary with structured logging and capture logs for assertions.

#[tokio::test]
async fn test_register_and_route_http_backend() {
    // 1) Start an HTTP backend
    let http_addr = spawn_http_backend().await;

    // 2) Start Portero proxy and registration API
    let listen_addr = "127.0.0.1:8080"; // HTTP listener (Pingora TCP listener added for tests)
    let register_addr = "127.0.0.1:18080";
    let tls_cert_dir = "./tests/data/certs"; // TODO: populate with default SNI certs for the proxy
    let (mut portero_child, _cleanup_token) =
        spawn_portero(listen_addr, register_addr, tls_cert_dir).await;

    // 3) Wait for registration API to be ready
    wait_for_port(register_addr).await;

    // 4) Register HTTP backend with use_tls=false
    let payload = json!({
        "service_name": "example.com",
        "host": "::1",                 // Mock: Portero expects IPv6; the actual routing test will be limited
        "port": http_addr.port(),
        "ttl_seconds": 30,
        "use_tls": false
    });
    let resp = http_post_json(&format!("http://{register_addr}/register"), payload).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 5) Send a client HTTP request through Portero to hit the HTTP backend
    let proxy_ready = wait_for_port(listen_addr).await;
    assert!(proxy_ready);
    let body = http_get_with_host(&format!("http://{listen_addr}/"), "example.com").await;
    assert_eq!(body, "hello from http backend");

    // Cleanup: terminate Portero
    let _ = portero_child.kill();
}

#[tokio::test]
#[ignore]
async fn test_register_and_route_https_backend() {
    // TODO: Implement HTTPS backend with self-signed cert and rustls/boring setup.
    // For now, this test outlines the steps and is ignored.

    // 1) Start an HTTPS backend (TODO)
    // let https_addr = spawn_https_backend().await;

    // 2) Start Portero proxy and registration API
    let listen_addr = "127.0.0.1:8443";
    let register_addr = "127.0.0.1:18080";
    let tls_cert_dir = "./tests/data/certs"; // TODO: populate with default SNI certs for the proxy
    let (mut portero_child, _cleanup_token) =
        spawn_portero(listen_addr, register_addr, tls_cert_dir).await;

    // 3) Wait for registration API to be ready
    wait_for_port(register_addr).await;

    // 4) Register HTTPS backend with use_tls=true
    // let payload = json!({
    //     "service_name": "secure.example.com",
    //     "host": "::1",
    //     "port": https_addr.port(),
    //     "ttl_seconds": 30,
    //     "use_tls": true
    // });
    // let resp = http_post_json(&format!("http://{register_addr}/register"), payload).await;
    // assert_eq!(resp.status(), StatusCode::OK);

    // 5) Perform client HTTPS request to proxy with SNI "secure.example.com" and assert backend content (TODO).

    // Cleanup
    let _ = portero_child.kill();
}

/// Spawn a minimal HTTP backend that returns 200 OK for GET / and echoes method/path for others.
async fn spawn_http_backend() -> SocketAddr {
    let make_svc = make_service_fn(move |_conn| async move {
        Ok::<_, hyper::Error>(service_fn(|req: Request<Body>| async move {
            if req.method() == Method::GET && req.uri().path() == "/" {
                Ok::<_, hyper::Error>(Response::new(Body::from("hello from http backend")))
            } else {
                let body = format!("{} {}", req.method(), req.uri().path());
                Ok::<_, hyper::Error>(Response::new(Body::from(body)))
            }
        }))
    });

    // Bind on localhost IPv6 (::1) ephemeral port to match Portero's upstream IPv6 routing
    let addr: SocketAddr = "[::1]:0".parse().expect("parse ipv6 addr");
    let server = Server::try_bind(&addr).expect("bind http backend");
    let local_addr = server.local_addr();

    tokio::spawn(async move {
        if let Err(e) = server.serve(make_svc).await {
            eprintln!("HTTP backend server error: {e:?}");
        }
    });

    // Wait briefly for server to start
    sleep(Duration::from_millis(100)).await;

    local_addr
}

/// Launch the `portero` binary with the provided listen and register addresses.
/// Returns the child process and a placeholder cleanup token (for future resource cleanup).
async fn spawn_portero(listen_addr: &str, register_addr: &str, tls_cert_dir: &str) -> (Child, ()) {
    // Build command: target/debug/portero --listen-addr ... --register-addr ... --tls-cert-dir ...
    //                --register-secret secret --jwt-hmac-key key
    // Provide dummy secret/key; tests only need registration path success.
    let mut child = Command::new("./target/debug/portero")
        .arg("--listen-addr")
        .arg(listen_addr)
        .arg("--register-addr")
        .arg(register_addr)
        .arg("--tls-cert-dir")
        .arg(tls_cert_dir)
        .arg("--register-secret")
        .arg("test-secret")
        .arg("--jwt-hmac-key")
        .arg("test-hmac-key")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn portero");

    // Optionally read some stderr to detect early failure (non-blocking best-effort).
    if let Some(mut stderr) = child.stderr.take() {
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 1024];
            // Read a small chunk then drop; this avoids blocking on full pipes.
            let _ = stderr.read(&mut buf);
        });
    }

    (child, ())
}

/// Wait for a TCP port (host:port) to become connectable.
/// Returns true when ready; false on timeout.
async fn wait_for_port(addr: &str) -> bool {
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return true,
            Err(_) => {
                if start.elapsed() > timeout {
                    return false;
                }
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Make a JSON POST request using hyper to a local endpoint.
async fn http_post_json(url: &str, payload: serde_json::Value) -> Response<Body> {
    // Create a valid HS256 JWT with matching service_name and exp
    let service_name = payload
        .get("service_name")
        .and_then(|v| v.as_str())
        .unwrap_or("example.com");
    let exp = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600) as usize;
    let claims = serde_json::json!({
        "service_name": service_name,
        "exp": exp
    });
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret("test-hmac-key".as_bytes()),
    )
    .expect("encode jwt");

    let client = hyper::Client::new();
    let body = Body::from(serde_json::to_vec(&payload).expect("serialize payload"));
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("Content-Type", "application/json")
        .header("X-Register-Secret", "test-secret")
        .header("Authorization", format!("Bearer {token}"))
        .body(body)
        .expect("build request");

    client.request(req).await.expect("http post json")
}

/// Make a GET request to the proxy with a specific Host header and return response body as String.
async fn http_get_with_host(url: &str, host: &str) -> String {
    let client = hyper::Client::new();
    let req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .header("Host", host)
        .body(Body::empty())
        .expect("build request");
    let resp = client.request(req).await.expect("http get");
    let bytes = hyper::body::to_bytes(resp.into_body())
        .await
        .expect("read body");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}
