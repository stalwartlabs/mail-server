/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use std::time::Duration;
use tikv_client::{Backoff, CheckLevel, RetryOptions, TransactionClient, TransactionOptions};
use utils::config::{utils::AsKey, Config};
use super::TikvStore;

impl TikvStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();

        // Parse as SocketAddr but don't use it. TransactionClient takes only a String vector
        let pd_endpoints= config.properties::<String>((&prefix, "pd-endpoints"))
            .into_iter()
            .map(|(_key, addr_str)| addr_str)
            .collect::<Vec<String>>();

        let trx_client = TransactionClient::new(pd_endpoints.clone())
            .await
            .map_err(|err| {
                config.new_build_error(
                    prefix.as_str(),
                    format!("Failed to create TiKV database: {err:?}"),
                )
            })
            .ok()?;

        let backoff_min_delay = config
            .property::<Duration>((&prefix, "transaction.backoff-min-delay"))
            .unwrap_or_else(|| Duration::from_millis(2));

        let backoff_max_delay = config
            .property::<Duration>((&prefix, "transaction.backoff-max-delay"))
            .unwrap_or_else(|| Duration::from_millis(500));

        let max_attempts = config
            .property::<u32>((&prefix, "transaction.backoff-retry-limit"))
            .unwrap_or_else(|| 10);

        let backoff = if let Some(backoff_type) = config
            .property::<String>((&prefix, "transaction.backoff-type")) {
            match backoff_type.as_str() {
                "expo-jitter" => Backoff::no_jitter_backoff(
                    backoff_min_delay.as_millis() as u64,
                    backoff_max_delay.as_millis() as u64,
                    max_attempts
                ),
                "equal-jitter" => Backoff::equal_jitter_backoff(
                    backoff_min_delay.as_millis() as u64,
                    backoff_max_delay.as_millis() as u64,
                    max_attempts
                ),
                "decor-jitter" => Backoff::decorrelated_jitter_backoff(
                    backoff_min_delay.as_millis() as u64,
                    backoff_max_delay.as_millis() as u64,
                    max_attempts
                ),
                "none" => Backoff::no_backoff(),
                // Default
                "full-jitter" | &_ => Backoff::full_jitter_backoff(
                    backoff_min_delay.as_millis() as u64,
                    backoff_max_delay.as_millis() as u64,
                    max_attempts
                ),
            }
        } else {
            // Default
            Backoff::full_jitter_backoff(
                backoff_min_delay.as_millis() as u64,
                backoff_max_delay.as_millis() as u64,
                max_attempts
            )
        };

        let write_trx_options = TransactionOptions::new_pessimistic()
            .drop_check(CheckLevel::Warn)
            .retry_options(RetryOptions::new(backoff.clone(), backoff.clone()));

        let read_trx_options = TransactionOptions::new_optimistic()
            .drop_check(CheckLevel::None)
            .retry_options(RetryOptions::none())
            .read_only();

        let store = Self {
            trx_client,
            write_trx_options,
            read_trx_options,
            backoff,
        };

        Some(store)
    }
}