/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use mail_auth::{Error, IpLookupStrategy};
use sieve::{runtime::Variable, FunctionMap};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("dns_query", plugin_id, 2);
}

pub fn register_exists(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("dns_exists", plugin_id, 2);
}

pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let entry = ctx.arguments[0].to_string();
    let record_type = ctx.arguments[1].to_string();

    Ok(if record_type.eq_ignore_ascii_case("ip") {
        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .ip_lookup(entry.as_ref(), IpLookupStrategy::Ipv4thenIpv6, 10)
            .await
        {
            Ok(result) => result
                .iter()
                .map(|ip| Variable::from(ip.to_string()))
                .collect::<Vec<_>>()
                .into(),
            Err(err) => err.short_error().into(),
        }
    } else if record_type.eq_ignore_ascii_case("mx") {
        match ctx.core.smtp.resolvers.dns.mx_lookup(entry.as_ref()).await {
            Ok(result) => result
                .iter()
                .flat_map(|mx| {
                    mx.exchanges
                        .iter()
                        .map(|host| Variable::from(format!("{} {}", mx.preference, host)))
                })
                .collect::<Vec<_>>()
                .into(),
            Err(err) => err.short_error().into(),
        }
    } else if record_type.eq_ignore_ascii_case("txt") {
        #[cfg(feature = "test_mode")]
        {
            if entry.contains("origin") {
                return Ok(Variable::from("23028|US|arin|2002-01-04".to_string()));
            }
        }

        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .txt_raw_lookup(entry.as_ref())
            .await
        {
            Ok(result) => Variable::from(String::from_utf8(result).unwrap_or_default()),
            Err(err) => err.short_error().into(),
        }
    } else if record_type.eq_ignore_ascii_case("ptr") {
        if let Ok(addr) = entry.parse::<IpAddr>() {
            match ctx.core.smtp.resolvers.dns.ptr_lookup(addr).await {
                Ok(result) => result
                    .iter()
                    .map(|host| Variable::from(host.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
                Err(err) => err.short_error().into(),
            }
        } else {
            Variable::default()
        }
    } else if record_type.eq_ignore_ascii_case("ipv4") {
        #[cfg(feature = "test_mode")]
        {
            if entry.contains(".168.192.") {
                let parts = entry.split('.').collect::<Vec<_>>();
                return Ok(vec![Variable::from(format!("127.0.{}.{}", parts[1], parts[0]))].into());
            }
        }

        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .ipv4_lookup(entry.as_ref())
            .await
        {
            Ok(result) => result
                .iter()
                .map(|ip| Variable::from(ip.to_string()))
                .collect::<Vec<_>>()
                .into(),
            Err(err) => err.short_error().into(),
        }
    } else if record_type.eq_ignore_ascii_case("ipv6") {
        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .ipv6_lookup(entry.as_ref())
            .await
        {
            Ok(result) => result
                .iter()
                .map(|ip| Variable::from(ip.to_string()))
                .collect::<Vec<_>>()
                .into(),
            Err(err) => err.short_error().into(),
        }
    } else {
        Variable::default()
    })
}

pub async fn exec_exists(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let entry = ctx.arguments[0].to_string();
    let record_type = ctx.arguments[1].to_string();

    Ok(if record_type.eq_ignore_ascii_case("ip") {
        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .ip_lookup(entry.as_ref(), IpLookupStrategy::Ipv4thenIpv6, 10)
            .await
        {
            Ok(result) => i64::from(!result.is_empty()),
            Err(Error::DnsRecordNotFound(_)) => 0,
            Err(_) => -1,
        }
    } else if record_type.eq_ignore_ascii_case("mx") {
        match ctx.core.smtp.resolvers.dns.mx_lookup(entry.as_ref()).await {
            Ok(result) => i64::from(result.iter().any(|mx| !mx.exchanges.is_empty())),
            Err(Error::DnsRecordNotFound(_)) => 0,
            Err(_) => -1,
        }
    } else if record_type.eq_ignore_ascii_case("ptr") {
        if let Ok(addr) = entry.parse::<IpAddr>() {
            match ctx.core.smtp.resolvers.dns.ptr_lookup(addr).await {
                Ok(result) => i64::from(!result.is_empty()),
                Err(Error::DnsRecordNotFound(_)) => 0,
                Err(_) => -1,
            }
        } else {
            -1
        }
    } else if record_type.eq_ignore_ascii_case("ipv4") {
        #[cfg(feature = "test_mode")]
        {
            if entry.starts_with("2.0.168.192.") {
                return Ok(1.into());
            }
        }

        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .ipv4_lookup(entry.as_ref())
            .await
        {
            Ok(result) => i64::from(!result.is_empty()),
            Err(Error::DnsRecordNotFound(_)) => 0,
            Err(_) => -1,
        }
    } else if record_type.eq_ignore_ascii_case("ipv6") {
        match ctx
            .core
            .smtp
            .resolvers
            .dns
            .ipv6_lookup(entry.as_ref())
            .await
        {
            Ok(result) => i64::from(!result.is_empty()),
            Err(Error::DnsRecordNotFound(_)) => 0,
            Err(_) => -1,
        }
    } else {
        -1
    }
    .into())
}

trait ShortError {
    fn short_error(&self) -> &'static str;
}

impl ShortError for mail_auth::Error {
    fn short_error(&self) -> &'static str {
        match self {
            mail_auth::Error::DnsError(_) => "temp_fail",
            mail_auth::Error::DnsRecordNotFound(_) => "not_found",
            mail_auth::Error::Io(_) => "io_error",
            mail_auth::Error::InvalidRecordType => "invalid_record",
            _ => "unknown_error",
        }
    }
}
