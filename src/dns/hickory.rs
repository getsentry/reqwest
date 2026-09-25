//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate

use hickory_resolver::{
    config::{LookupIpStrategy, ResolverConfig, GOOGLE},
    net::{runtime::TokioRuntimeProvider, NetError},
    TokioResolver,
};
use once_cell::sync::OnceCell;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::{Addrs, Name, Resolve, Resolving};

#[derive(Debug, Clone)]
pub(crate) enum ResolveError {
    Restricted,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::Restricted => f.write_str("destination is restricted"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Clone)]
pub(crate) struct HickoryDnsResolver {
    /// Since we might not have been called in the context of a
    /// Tokio Runtime in initialization, so we must delay the actual
    /// construction of the resolver.
    state: Arc<OnceCell<TokioResolver>>,
    filter: fn(std::net::IpAddr) -> bool,
}

struct SocketAddrs {
    iter: std::vec::IntoIter<IpAddr>,
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

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let filter = resolver.filter;
            let resolver = resolver.state.get_or_try_init(new_resolver)?;

            let lookup = resolver.lookup_ip(name.as_str()).await?;
            if !lookup.iter().any(filter) {
                return Err(ResolveError::Restricted.into());
            }

            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.iter().collect::<Vec<_>>().into_iter(),
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
/// which reads from `/etc/resolve.conf`. If reading `/etc/resolv.conf` fails,
/// it fallbacks to hickory_resolver's default config.
/// The options are overridden to look up for both IPv4 and IPv6 addresses
/// to work with "happy eyeballs" algorithm.
fn new_resolver() -> Result<TokioResolver, NetError> {
    let mut builder = TokioResolver::builder_tokio().unwrap_or_else(|err| {
        log::debug!(
            "hickory-dns: failed to load system DNS configuration; falling back to Google DNS: {:?}",
            err
        );
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            TokioRuntimeProvider::default(),
        )
    });
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
    builder.build()
}
