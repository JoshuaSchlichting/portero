use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Backend {
    pub addr: IpAddr,
    pub port: u16,
    pub use_tls: bool,
    pub expires_at: Instant,
    pub instance_id: Option<String>,
}

impl Backend {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

#[derive(Debug, Default)]
pub struct Registry {
    pub hosts: HashMap<String, HashMap<String, VecDeque<Backend>>>,
}

impl Registry {
    pub fn upsert_backend(
        &mut self,
        host: &str,
        service_name: &str,
        backend: Backend,
        ttl: Duration,
    ) {
        let expires_at = Instant::now() + ttl;
        let new_backend = Backend {
            addr: backend.addr,
            port: backend.port,
            use_tls: backend.use_tls,
            expires_at,
            instance_id: backend.instance_id.clone(),
        };
        let services = self.hosts.entry(host.to_string()).or_default();
        let queue = services.entry(service_name.to_string()).or_default();

        let existing = if let Some(ref id) = new_backend.instance_id {
            queue
                .iter_mut()
                .find(|b| b.instance_id.as_deref() == Some(id))
        } else {
            queue
                .iter_mut()
                .find(|b| b.addr == new_backend.addr && b.port == new_backend.port)
        };

        if let Some(existing) = existing {
            existing.addr = new_backend.addr;
            existing.port = new_backend.port;
            existing.use_tls = new_backend.use_tls;
            existing.expires_at = new_backend.expires_at;
            existing.instance_id = new_backend.instance_id;
        } else {
            queue.push_back(new_backend);
        }
    }

    pub fn next_backend(&mut self, host: &str, service_name: &str) -> Option<Backend> {
        let services = self.hosts.get_mut(host)?;
        let queue = services.get_mut(service_name)?;
        while let Some(b) = queue.pop_front() {
            if !b.is_expired() {
                queue.push_back(b.clone());
                return Some(b);
            }
        }
        None
    }

    pub fn remove_backend(&mut self, host: &str, service_name: &str, addr: SocketAddr) {
        if let Some(services) = self.hosts.get_mut(host) {
            if let Some(queue) = services.get_mut(service_name) {
                queue.retain(|b| b.socket_addr() != addr);
            }
        }
    }

    pub fn purge_expired(&mut self) {
        for services in self.hosts.values_mut() {
            for queue in services.values_mut() {
                queue.retain(|b| !b.is_expired());
            }
        }
    }

    pub fn backends_for_service(
        &self,
        host: &str,
        service_name: &str,
    ) -> Vec<(String, String, SocketAddr)> {
        let mut list = Vec::new();
        if let Some(services) = self.hosts.get(host) {
            if let Some(queue) = services.get(service_name) {
                for backend in queue.iter() {
                    list.push((
                        host.to_string(),
                        service_name.to_string(),
                        backend.socket_addr(),
                    ));
                }
            }
        }
        list
    }
}
