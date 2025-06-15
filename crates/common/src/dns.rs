/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use mail_auth::{Error, IpLookupStrategy};

use crate::Server;

impl Server {
    pub async fn dns_exists_mx(&self, entry: &str) -> trc::Result<bool> {
        match self
            .core
            .smtp
            .resolvers
            .dns
            .mx_lookup(entry, Some(&self.inner.cache.dns_mx))
            .await
        {
            Ok(result) => Ok(result.iter().any(|mx| !mx.exchanges.is_empty())),
            Err(Error::DnsRecordNotFound(_)) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn dns_exists_ip(&self, entry: &str) -> trc::Result<bool> {
        match self
            .core
            .smtp
            .resolvers
            .dns
            .ip_lookup(
                entry,
                IpLookupStrategy::Ipv4thenIpv6,
                10,
                Some(&self.inner.cache.dns_ipv4),
                Some(&self.inner.cache.dns_ipv6),
            )
            .await
        {
            Ok(result) => Ok(!result.is_empty()),
            Err(Error::DnsRecordNotFound(_)) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn dns_exists_ptr(&self, entry: &str) -> trc::Result<bool> {
        if let Ok(addr) = entry.parse::<IpAddr>() {
            match self
                .core
                .smtp
                .resolvers
                .dns
                .ptr_lookup(addr, Some(&self.inner.cache.dns_ptr))
                .await
            {
                Ok(result) => Ok(!result.is_empty()),
                Err(Error::DnsRecordNotFound(_)) => Ok(false),
                Err(err) => Err(err.into()),
            }
        } else {
            Err(trc::EventType::Resource(trc::ResourceEvent::BadParameters).into_err())
        }
    }

    pub async fn dns_exists_ipv4(&self, entry: &str) -> trc::Result<bool> {
        match self
            .core
            .smtp
            .resolvers
            .dns
            .ipv4_lookup(entry, Some(&self.inner.cache.dns_ipv4))
            .await
        {
            Ok(result) => Ok(!result.is_empty()),
            Err(Error::DnsRecordNotFound(_)) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn dns_exists_ipv6(&self, entry: &str) -> trc::Result<bool> {
        match self
            .core
            .smtp
            .resolvers
            .dns
            .ipv6_lookup(entry, Some(&self.inner.cache.dns_ipv6))
            .await
        {
            Ok(result) => Ok(!result.is_empty()),
            Err(Error::DnsRecordNotFound(_)) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}
