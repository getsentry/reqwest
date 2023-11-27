//! DNS resolution via the [trust_dns_resolver](https://github.com/bluejekyll/trust-dns) crate

use hyper::client::connect::dns::Name;
use once_cell::sync::OnceCell;
pub use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::{lookup_ip::LookupIpIntoIter, system_conf, TokioAsyncResolver};

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use super::{Addrs, Resolve, Resolving};

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Clone)]
pub(crate) struct TrustDnsResolver {
    /// Since we might not have been called in the context of a
    /// Tokio Runtime in initialization, so we must delay the actual
    /// construction of the resolver.
    state: Arc<OnceCell<TokioAsyncResolver>>,
    filter: fn(std::net::IpAddr) -> bool,
}

struct SocketAddrs {
    iter: LookupIpIntoIter,
    filter: fn(std::net::IpAddr) -> bool,
}

impl TrustDnsResolver {
    pub fn new(filter: fn(std::net::IpAddr) -> bool) -> Self {
        TrustDnsResolver {
            state: Default::default(),
            filter,
        }
    }
}

impl Resolve for TrustDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let filter = resolver.filter;
            let resolver = resolver.state.get_or_try_init(new_resolver)?;

            let lookup = resolver.lookup_ip(name.as_str()).await?;
            if !lookup.iter().any(filter) {
                let e = trust_dns_resolver::error::ResolveError::from("destination is restricted");
                return Err(e.into());
            }

            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
                filter,
            });
            Ok(addrs)
        })
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let ip_addr = self.iter.next()?;
            if (self.filter)(ip_addr) {
                return Some(SocketAddr::new(ip_addr, 0));
            }
        }
    }
}

/// Create a new resolver with the default configuration,
/// which reads from `/etc/resolve.conf`.
fn new_resolver() -> io::Result<TokioAsyncResolver> {
    let (config, opts) = system_conf::read_system_conf().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("error reading DNS system conf: {}", e),
        )
    })?;
    Ok(TokioAsyncResolver::tokio(config, opts))
}
