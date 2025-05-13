/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use foundationdb::{api, options::DatabaseOption, Database};
use utils::config::{utils::AsKey, Config};

use super::FdbStore;

impl FdbStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let guard = unsafe {
            api::FdbApiBuilder::default()
                .build()
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!("Failed to boot FoundationDB: {err:?}"),
                    )
                })
                .ok()?
                .boot()
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!("Failed to boot FoundationDB: {err:?}"),
                    )
                })
                .ok()?
        };

        let db = Database::new(config.value((&prefix, "cluster-file")))
            .map_err(|err| {
                config.new_build_error(
                    prefix.as_str(),
                    format!("Failed to create FoundationDB database: {err:?}"),
                )
            })
            .ok()?;

        if let Some(value) = config
            .property::<Option<Duration>>((&prefix, "transaction.timeout"))
            .unwrap_or_default()
        {
            db.set_option(DatabaseOption::TransactionTimeout(value.as_millis() as i32))
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "transaction.timeout"),
                        format!("Failed to set option: {err:?}"),
                    )
                })
                .ok()?;
        }
        if let Some(value) = config.property((&prefix, "transaction.retry-limit")) {
            db.set_option(DatabaseOption::TransactionRetryLimit(value))
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "transaction.retry-limit"),
                        format!("Failed to set option: {err:?}"),
                    )
                })
                .ok()?;
        }
        if let Some(value) = config
            .property::<Option<Duration>>((&prefix, "transaction.max-retry-delay"))
            .unwrap_or_default()
        {
            db.set_option(DatabaseOption::TransactionMaxRetryDelay(
                value.as_millis() as i32
            ))
            .map_err(|err| {
                config.new_build_error(
                    (&prefix, "transaction.max-retry-delay"),
                    format!("Failed to set option: {err:?}"),
                )
            })
            .ok()?;
        }
        if let Some(value) = config.property((&prefix, "ids.machine")) {
            db.set_option(DatabaseOption::MachineId(value))
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "ids.machine"),
                        format!("Failed to set option: {err:?}"),
                    )
                })
                .ok()?;
        }
        if let Some(value) = config.property((&prefix, "ids.datacenter")) {
            db.set_option(DatabaseOption::DatacenterId(value))
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "ids.datacenter"),
                        format!("Failed to set option: {err:?}"),
                    )
                })
                .ok()?;
        }

        Some(Self {
            guard,
            db,
            version: Default::default(),
        })
    }
}
