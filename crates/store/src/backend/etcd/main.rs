/*
 * SPDX-FileCopyrightText: 2024 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use etcd_client::{Client};
use utils::config::{utils::AsKey, Config};
use super::{into_error, EtcdStore};

impl EtcdStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();

        // Parse as SocketAddr but don't use it. TransactionClient takes only a String vector
        let endpoints = config.properties::<String>((&prefix, "endpoints"))
            .into_iter()
            .map(|(_key, addr_str)| addr_str)
            .collect::<Vec<String>>();

        let client = Client::connect(endpoints.clone(), None)
            .await
            .map_err(|err| {
                config.new_build_error(
                    prefix.as_str(),
                    format!("Failed to create Etcd database: {err:?}"),
                )
            })
            .ok()?;

        let store = Self {
            client: client.kv_client(),
        };

        Some(store)
    }
}
