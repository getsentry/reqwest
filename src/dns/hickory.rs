//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate

use hickory_resolver::{
    config::LookupIpStrategy, error::ResolveError, lookup_ip::LookupIpIntoIter, system_conf,
    TokioAsyncResolver,
};
use once_cell::sync::OnceCell;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use super::{Addrs, Name, Resolve, Resolving};

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Clone)]
pub(crate) struct HickoryDnsResolver {
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

impl HickoryDnsResolver {
    pub fn new(filter: fn(std::net::IpAddr) -> bool) -> Self {
        Self {
            state: Default::default(),
            filter,
        }
    }
}

#[derive(Debug)]
struct HickoryDnsSystemConfError(ResolveError);

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let filter = resolver.filter;
            let resolver = resolver.state.get_or_try_init(new_resolver)?;

            let lookup = resolver.lookup_ip(name.as_str()).await?;
            if !lookup.iter().any(filter) {
                let e = hickory_resolver::error::ResolveError::from("destination is restricted");
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
/// which reads from `/etc/resolve.conf`. The options are
/// overridden to look up for both IPv4 and IPv6 addresses
/// to work with "happy eyeballs" algorithm.
fn new_resolver() -> Result<TokioAsyncResolver, HickoryDnsSystemConfError> {
    let (config, mut opts) = system_conf::read_system_conf().map_err(HickoryDnsSystemConfError)?;
    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    Ok(TokioAsyncResolver::tokio(config, opts))
}

impl fmt::Display for HickoryDnsSystemConfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error reading DNS system conf for hickory-dns")
    }
}

impl std::error::Error for HickoryDnsSystemConfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
