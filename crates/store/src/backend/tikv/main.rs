/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;

use tikv_client::TransactionClient;
use utils::config::{utils::AsKey, Config};

use super::TikvStore;

impl TikvStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();

        // Parse as SocketAddr but don't use it. TransactionClient takes only a String vector
        let pd_endpoints = config.properties::<String>((&prefix, "pd-endpoints"))
            .into_iter()
            .map(|(_key, addr_str)| addr_str)
            .collect();

        let client = TransactionClient::new(pd_endpoints)
            .await
            .map_err(|err| {
                config.new_build_error(
                    prefix.as_str(),
                    format!("Failed to create TiKV database: {err:?}"),
                )
            })
            .ok()?;

        Some(Self {
            client,
            version: Default::default(),
        })
    }
}
