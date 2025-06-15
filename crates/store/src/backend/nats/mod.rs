/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use async_nats::Client;
use utils::config::{Config, utils::AsKey};

pub mod pubsub;

#[derive(Debug)]
pub struct NatsPubSub {
    client: Client,
}

impl NatsPubSub {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let urls = config
            .values((&prefix, "address"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();
        if urls.is_empty() {
            config.new_build_error((&prefix, "address"), "No Nats addresses specified");
            return None;
        }

        let mut opts = async_nats::ConnectOptions::new()
            .max_reconnects(
                config
                    .property_or_default::<Option<usize>>((&prefix, "max-reconnects"), "false")
                    .unwrap_or_default(),
            )
            .connection_timeout(
                config
                    .property_or_default((&prefix, "timeout.connection"), "5s")
                    .unwrap_or_else(|| Duration::from_secs(5)),
            )
            .request_timeout(
                config
                    .property_or_default::<Option<Duration>>((&prefix, "timeout.request"), "10s")
                    .unwrap_or_else(|| Some(Duration::from_secs(10))),
            )
            .ping_interval(
                config
                    .property_or_default((&prefix, "ping-interval"), "60s")
                    .unwrap_or_else(|| Duration::from_secs(5)),
            )
            .client_capacity(
                config
                    .property_or_default((&prefix, "capacity.client"), "2048")
                    .unwrap_or(2048),
            )
            .subscription_capacity(
                config
                    .property_or_default((&prefix, "capacity.subscription"), "65536")
                    .unwrap_or(65536),
            )
            .read_buffer_capacity(
                config
                    .property_or_default((&prefix, "capacity.read-buffer"), "65535")
                    .unwrap_or(65535),
            )
            .require_tls(
                config
                    .property_or_default((&prefix, "tls.enable"), "false")
                    .unwrap_or_default(),
            );

        if config
            .property_or_default((&prefix, "no-echo"), "true")
            .unwrap_or(true)
        {
            opts = opts.no_echo();
        }

        if let (Some(user), Some(pass)) = (
            config.value((&prefix, "user")),
            config.value((&prefix, "password")),
        ) {
            opts = opts.user_and_password(user.to_string(), pass.to_string());
        } else if let Some(credentials) = config.value((&prefix, "credentials")) {
            opts = opts
                .credentials(credentials)
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "credentials"),
                        format!("Failed to parse Nats credentials: {}", err),
                    );
                })
                .ok()?;
        }

        async_nats::connect_with_options(urls, opts)
            .await
            .map_err(|err| {
                config.new_build_error(
                    (&prefix, "urls"),
                    format!("Failed to connect to Nats: {}", err),
                );
            })
            .map(|client| NatsPubSub { client })
            .ok()
    }
}
