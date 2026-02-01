use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// A backend endpoint for a service.
///
/// - `addr_v6`: IPv6 address of the backend (no brackets)
/// - `port`: TCP port on which the backend listens
/// - `expires_at`: time when this registration expires; used for TTL and purging
#[derive(Debug, Clone)]
pub struct Backend {
    pub addr_v6: Ipv6Addr,
    pub port: u16,
    pub expires_at: Instant,
}

impl Backend {
    /// Construct a `SocketAddr` for connecting to this backend.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr_v6.into(), self.port)
    }

    /// Return true if the backend registration has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Runtime registry for routing and registration.
/// Maps `host -> service_name -> round-robin queue of backends`.
#[derive(Debug, Default)]
pub struct Registry {
    pub hosts: HashMap<String, HashMap<String, VecDeque<Backend>>>,
}

impl Registry {
    /// Insert or update a backend registration for a given host and service.
    /// The backend will be set to expire after `ttl` duration from now.
    pub fn upsert_backend(
        &mut self,
        host: &str,
        service_name: &str,
        backend: Backend,
        ttl: Duration,
    ) {
        let expires_at = Instant::now() + ttl;
        let backend = Backend {
            addr_v6: backend.addr_v6,
            port: backend.port,
            expires_at,
        };
        let services = self.hosts.entry(host.to_string()).or_default();
        let queue = services.entry(service_name.to_string()).or_default();
        queue.push_back(backend);
    }

    /// Fetch the next backend in round-robin order for the given host and service.
    /// Expired backends are skipped and removed from the front.
    pub fn next_backend(&mut self, host: &str, service_name: &str) -> Option<Backend> {
        let services = self.hosts.get_mut(host)?;
        let queue = services.get_mut(service_name)?;
        while let Some(b) = queue.pop_front() {
            if !b.is_expired() {
                queue.push_back(b.clone());
                return Some(b);
            }
            // else: expired, don't reinsert
        }
        None
    }

    /// Remove all expired backends from all queues.
    pub fn purge_expired(&mut self) {
        for services in self.hosts.values_mut() {
            for queue in services.values_mut() {
                queue.retain(|b| !b.is_expired());
            }
        }
    }
}
