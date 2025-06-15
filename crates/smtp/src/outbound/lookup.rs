/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use common::{
    Server,
    expr::{V_MX, functions::ResolveVariable},
};
use mail_auth::{IpLookupStrategy, MX};
use rand::{Rng, seq::SliceRandom};

use crate::queue::{Error, ErrorDetails, Status};

use super::NextHop;

pub struct IpLookupResult {
    pub source_ipv4: Option<IpAddr>,
    pub source_ipv6: Option<IpAddr>,
    pub remote_ips: Vec<IpAddr>,
}

pub trait DnsLookup: Sync + Send {
    fn ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
    ) -> impl Future<Output = mail_auth::Result<Vec<IpAddr>>> + Send;

    fn resolve_host(
        &self,
        remote_host: &NextHop<'_>,
        envelope: &impl ResolveVariable,
        max_multihomed: usize,
        session_id: u64,
    ) -> impl Future<Output = Result<IpLookupResult, Status<(), Error>>> + Send;
}

impl DnsLookup for Server {
    async fn ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
    ) -> mail_auth::Result<Vec<IpAddr>> {
        let (has_ipv4, has_ipv6, v4_first) = match strategy {
            IpLookupStrategy::Ipv4Only => (true, false, false),
            IpLookupStrategy::Ipv6Only => (false, true, false),
            IpLookupStrategy::Ipv4thenIpv6 => (true, true, true),
            IpLookupStrategy::Ipv6thenIpv4 => (true, true, false),
        };
        let ipv4_addrs = if has_ipv4 {
            match self
                .core
                .smtp
                .resolvers
                .dns
                .ipv4_lookup(key, Some(&self.inner.cache.dns_ipv4))
                .await
            {
                Ok(addrs) => addrs,
                Err(_) if has_ipv6 => Arc::new(Vec::new()),
                Err(err) => return Err(err),
            }
        } else {
            Arc::new(Vec::new())
        };

        if has_ipv6 {
            let ipv6_addrs = match self
                .core
                .smtp
                .resolvers
                .dns
                .ipv6_lookup(key, Some(&self.inner.cache.dns_ipv6))
                .await
            {
                Ok(addrs) => addrs,
                Err(_) if !ipv4_addrs.is_empty() => Arc::new(Vec::new()),
                Err(err) => return Err(err),
            };
            if v4_first {
                Ok(ipv4_addrs
                    .iter()
                    .copied()
                    .map(IpAddr::from)
                    .chain(ipv6_addrs.iter().copied().map(IpAddr::from))
                    .take(max_results)
                    .collect())
            } else {
                Ok(ipv6_addrs
                    .iter()
                    .copied()
                    .map(IpAddr::from)
                    .chain(ipv4_addrs.iter().copied().map(IpAddr::from))
                    .take(max_results)
                    .collect())
            }
        } else {
            Ok(ipv4_addrs
                .iter()
                .take(max_results)
                .copied()
                .map(IpAddr::from)
                .collect())
        }
    }

    #[allow(unused_mut)]
    async fn resolve_host(
        &self,
        remote_host: &NextHop<'_>,
        envelope: &impl ResolveVariable,
        max_multihomed: usize,
        session_id: u64,
    ) -> Result<IpLookupResult, Status<(), Error>> {
        let mut remote_ips = self
            .ip_lookup(
                remote_host.fqdn_hostname().as_ref(),
                self.eval_if(&self.core.smtp.queue.ip_strategy, envelope, session_id)
                    .await
                    .unwrap_or(IpLookupStrategy::Ipv4thenIpv6),
                max_multihomed,
            )
            .await
            .map_err(|err| {
                if let mail_auth::Error::DnsRecordNotFound(_) = &err {
                    if matches!(
                        remote_host,
                        NextHop::MX {
                            is_implicit: true,
                            ..
                        }
                    ) {
                        Status::PermanentFailure(Error::DnsError("no MX record found.".into()))
                    } else {
                        Status::PermanentFailure(Error::ConnectionError(ErrorDetails {
                            entity: remote_host.hostname().into(),
                            details: "record not found for MX".into(),
                        }))
                    }
                } else {
                    Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
                        entity: remote_host.hostname().into(),
                        details: format!("lookup error: {err}"),
                    }))
                }
            })?;

        if !remote_ips.is_empty() {
            #[cfg(not(feature = "test_mode"))]
            if remote_ips.iter().any(|ip| ip.is_loopback()) {
                remote_ips.retain(|ip| !ip.is_loopback());
                if remote_ips.is_empty() {
                    return Err(Status::PermanentFailure(Error::ConnectionError(
                        ErrorDetails {
                            entity: remote_host.hostname().into(),
                            details: "host resolves loopback address".into(),
                        },
                    )));
                }
            }

            let mut result = IpLookupResult {
                source_ipv4: None,
                source_ipv6: None,
                remote_ips,
            };

            // Obtain source IPv4 address
            let source_ips = self
                .eval_if::<Vec<Ipv4Addr>, _>(
                    &self.core.smtp.queue.source_ip.ipv4,
                    envelope,
                    session_id,
                )
                .await
                .unwrap_or_default();
            match source_ips.len().cmp(&1) {
                std::cmp::Ordering::Equal => {
                    result.source_ipv4 = IpAddr::from(*source_ips.first().unwrap()).into();
                }
                std::cmp::Ordering::Greater => {
                    result.source_ipv4 =
                        IpAddr::from(source_ips[rand::rng().random_range(0..source_ips.len())])
                            .into();
                }
                std::cmp::Ordering::Less => (),
            }

            // Obtain source IPv6 address
            let source_ips = self
                .eval_if::<Vec<Ipv6Addr>, _>(
                    &self.core.smtp.queue.source_ip.ipv6,
                    envelope,
                    session_id,
                )
                .await
                .unwrap_or_default();
            match source_ips.len().cmp(&1) {
                std::cmp::Ordering::Equal => {
                    result.source_ipv6 = IpAddr::from(*source_ips.first().unwrap()).into();
                }
                std::cmp::Ordering::Greater => {
                    result.source_ipv6 =
                        IpAddr::from(source_ips[rand::rng().random_range(0..source_ips.len())])
                            .into();
                }
                std::cmp::Ordering::Less => (),
            }

            Ok(result)
        } else {
            Err(Status::TemporaryFailure(Error::DnsError(format!(
                "No IP addresses found for {:?}.",
                envelope.resolve_variable(V_MX).to_string()
            ))))
        }
    }
}

pub trait ToNextHop {
    fn to_remote_hosts<'x, 'y: 'x>(
        &'x self,
        domain: &'y str,
        max_mx: usize,
    ) -> Option<Vec<NextHop<'x>>>;
}

impl ToNextHop for Vec<MX> {
    fn to_remote_hosts<'x, 'y: 'x>(
        &'x self,
        domain: &'y str,
        max_mx: usize,
    ) -> Option<Vec<NextHop<'x>>> {
        if !self.is_empty() {
            // Obtain max number of MX hosts to process
            let mut remote_hosts = Vec::with_capacity(max_mx);

            'outer: for mx in self.iter() {
                if mx.exchanges.len() > 1 {
                    let mut slice = mx.exchanges.iter().collect::<Vec<_>>();
                    slice.shuffle(&mut rand::rng());
                    for remote_host in slice {
                        remote_hosts.push(NextHop::MX {
                            host: remote_host.as_str(),
                            is_implicit: false,
                        });
                        if remote_hosts.len() == max_mx {
                            break 'outer;
                        }
                    }
                } else if let Some(remote_host) = mx.exchanges.first() {
                    // Check for Null MX
                    if mx.preference == 0 && remote_host == "." {
                        return None;
                    }
                    remote_hosts.push(NextHop::MX {
                        host: remote_host.as_str(),
                        is_implicit: false,
                    });
                    if remote_hosts.len() == max_mx {
                        break;
                    }
                }
            }
            remote_hosts.into()
        } else {
            // If an empty list of MXs is returned, the address is treated as if it was
            // associated with an implicit MX RR with a preference of 0, pointing to that host.
            vec![NextHop::MX {
                host: domain,
                is_implicit: true,
            }]
            .into()
        }
    }
}
