/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::{Config, utils::AsKey};
pub mod pubsub;

#[derive(Debug)]
pub struct ZenohPubSub {
    session: zenoh::Session,
}

impl ZenohPubSub {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let zenoh_config =
            zenoh::Config::from_json5(config.value_require_non_empty((&prefix, "config"))?)
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "config"),
                        format!("Invalid zenoh config: {}", err),
                    );
                })
                .ok()?;
        zenoh::open(zenoh_config)
            .await
            .map_err(|err| {
                config.new_build_error(
                    (&prefix, "config"),
                    format!("Failed to create zenoh session: {}", err),
                );
            })
            .map(|session| ZenohPubSub { session })
            .ok()
    }
}
