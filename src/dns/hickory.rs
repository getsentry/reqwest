use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    lookup_ip::LookupIpIntoIter, 
    TokioAsyncResolver,
    system_conf,
};
use once_cell::sync::OnceCell;

use std::io;
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
    config: Option<(ResolverConfig, ResolverOpts)>,
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
            config: None,
        }
    }

    pub fn with_config(mut self, config: ResolverConfig, opts: ResolverOpts) -> Self {
        self.config = Some((config, opts));
        self
    }

    fn new_resolver(&self) -> io::Result<TokioAsyncResolver> {
        let (config, mut opts) = match self.config.clone() {
            Some((config, opts)) => (config, opts),
            None => system_conf::read_system_conf().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("error reading DNS system conf: {e}"),
                )
            })?,
        };

        opts.cache_size = 500_000; // 500k entries
        Ok(TokioAsyncResolver::tokio(config, opts))
    }
}

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let filter = resolver.filter;
            let resolver = resolver.state.get_or_try_init(|| resolver.new_resolver())?;

            let start = std::time::Instant::now();
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            if rand::random::<f32>() < 0.01 {
                log::warn!(
                    "DNS lookup for {} took {:?}",
                    name.as_str(),
                    start.elapsed()
                );
            }

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
