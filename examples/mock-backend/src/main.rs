use std::net::SocketAddr;

use env_logger;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use log::{error, info};

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("MOCK_BACKEND_NAME"))
        .unwrap_or_else(|_| String::from("unknown"))
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("MOCK_BACKEND_LOG", "info"))
        .init();

    // Bind address: default to IPv6 loopback ::1:8080, overridable via env var
    // Example: MOCK_BACKEND_ADDR="[::]:8080" or "0.0.0.0:8080"
    let addr: SocketAddr = std::env::var("MOCK_BACKEND_ADDR")
        .unwrap_or_else(|_| String::from("[::1]:8080"))
        .parse()
        .expect("MOCK_BACKEND_ADDR must be a valid SocketAddr");

    let hostname = get_hostname();
    info!(
        "mock-backend listening on {} (hostname: {})",
        addr, hostname
    );

    // Create a simple service:
    // - GET / -> "hello from mock backend (hostname)"
    // - anything else -> echoes method and path
    let make_svc = make_service_fn(move |_conn| {
        let hostname = hostname.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let hostname = hostname.clone();
                async move {
                    if req.method() == Method::GET && req.uri().path() == "/" {
                        let response = format!("hello from mock backend ({})", hostname);
                        Ok::<_, hyper::Error>(Response::new(Body::from(response)))
                    } else {
                        let body = format!("{} {}", req.method(), req.uri().path());
                        Ok::<_, hyper::Error>(Response::new(Body::from(body)))
                    }
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        error!("mock-backend server error: {e:?}");
    }
}
