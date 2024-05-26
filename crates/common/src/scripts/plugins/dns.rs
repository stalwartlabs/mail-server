/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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

pub async fn exec(ctx: PluginContext<'_>) -> Variable {
    let entry = ctx.arguments[0].to_string();
    let record_type = ctx.arguments[1].to_string();

    if record_type.eq_ignore_ascii_case("ip") {
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
                return Variable::from("23028|US|arin|2002-01-04".to_string());
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
                return vec![Variable::from(format!("127.0.{}.{}", parts[1], parts[0]))].into();
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
    }
}

pub async fn exec_exists(ctx: PluginContext<'_>) -> Variable {
    let entry = ctx.arguments[0].to_string();
    let record_type = ctx.arguments[1].to_string();

    if record_type.eq_ignore_ascii_case("ip") {
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
                return 1.into();
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
    .into()
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
