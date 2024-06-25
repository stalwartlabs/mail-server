/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use mail_send::{smtp::tls::build_tls_connector, SmtpClientBuilder};
use utils::config::{utils::AsKey, Config};

use crate::core::config::build_pool;

use super::{SmtpConnectionManager, SmtpDirectory};

impl SmtpDirectory {
    pub fn from_config(config: &mut Config, prefix: impl AsKey, is_lmtp: bool) -> Option<Self> {
        let prefix = prefix.as_key();
        let address = config.value_require((&prefix, "host"))?.to_string();
        let tls_implicit: bool = config
            .property_or_default((&prefix, "tls.enable"), "false")
            .unwrap_or_default();
        let port: u16 = config
            .property_or_default((&prefix, "port"), if tls_implicit { "465" } else { "25" })
            .unwrap_or(if tls_implicit { 465 } else { 25 });

        let manager = SmtpConnectionManager {
            builder: SmtpClientBuilder {
                addr: format!("{address}:{port}"),
                timeout: config
                    .property_or_default((&prefix, "timeout"), "30s")
                    .unwrap_or_else(|| Duration::from_secs(30)),
                tls_connector: build_tls_connector(
                    config
                        .property_or_default((&prefix, "tls.allow-invalid-certs"), "false")
                        .unwrap_or_default(),
                ),
                tls_hostname: address.to_string(),
                tls_implicit,
                is_lmtp,
                credentials: None,
                local_host: config
                    .value("lookup.default.hostname")
                    .unwrap_or("[127.0.0.1]")
                    .to_string(),
                say_ehlo: false,
            },
            max_rcpt: config
                .property_or_default((&prefix, "limits.rcpt"), "10")
                .unwrap_or(10),
            max_auth_errors: config
                .property_or_default((&prefix, "limits.auth-errors"), "3")
                .unwrap_or(10),
        };

        Some(SmtpDirectory {
            pool: build_pool(config, &prefix, manager)
                .map_err(|e| {
                    config.new_parse_error(
                        prefix.as_str(),
                        format!("Failed to build SMTP pool: {e:?}"),
                    )
                })
                .ok()?,
            domains: config
                .values((&prefix, "lookup.domains"))
                .map(|(_, v)| v.to_lowercase())
                .collect(),
        })
    }
}
