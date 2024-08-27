/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::time::Duration;

use jmap_proto::types::collection::Collection;
use store::{BitmapKey, Store, Stores};
use utils::config::{cron::SimpleCron, utils::ParseValue, Config};

use super::{license::LicenseValidator, Enterprise, MetricStore, TraceStore, Undelete};

impl Enterprise {
    pub async fn parse(config: &mut Config, stores: &Stores, data: &Store) -> Option<Self> {
        let license = match LicenseValidator::new()
            .try_parse(config.value("enterprise.license-key")?)
            .and_then(|key| {
                key.into_validated_key(config.value("lookup.default.hostname").unwrap_or_default())
            }) {
            Ok(key) => key,
            Err(err) => {
                config.new_build_warning("enterprise.license-key", err.to_string());
                return None;
            }
        };

        match data
            .get_bitmap(BitmapKey::document_ids(u32::MAX, Collection::Principal))
            .await
        {
            Ok(Some(bitmap)) if bitmap.len() > license.accounts as u64 => {
                config.new_build_warning(
                    "enterprise.license-key",
                    format!(
                        "License key is valid but only allows {} accounts, found {}.",
                        license.accounts,
                        bitmap.len()
                    ),
                );
                return None;
            }
            Err(e) => {
                if !matches!(data, Store::None) {
                    config.new_build_error("enterprise.license-key", e.to_string());
                }
                return None;
            }
            _ => (),
        }

        let trace_store = if config
            .property_or_default("tracing.history.enable", "false")
            .unwrap_or(false)
        {
            if let Some(store) = config
                .value("tracing.history.store")
                .and_then(|name| stores.stores.get(name))
                .cloned()
            {
                TraceStore {
                    retention: config
                        .property_or_default::<Option<Duration>>("tracing.history.retention", "30d")
                        .unwrap_or(Some(Duration::from_secs(30 * 24 * 60 * 60))),
                    store,
                }
                .into()
            } else {
                None
            }
        } else {
            None
        };
        let metrics_store = if config
            .property_or_default("metrics.history.enable", "false")
            .unwrap_or(false)
        {
            if let Some(store) = config
                .value("metrics.history.store")
                .and_then(|name| stores.stores.get(name))
                .cloned()
            {
                MetricStore {
                    retention: config
                        .property_or_default::<Option<Duration>>("metrics.history.retention", "90d")
                        .unwrap_or(Some(Duration::from_secs(90 * 24 * 60 * 60))),
                    store,
                    interval: config
                        .property_or_default::<SimpleCron>("metrics.history.interval", "0 * *")
                        .unwrap_or_else(|| SimpleCron::parse_value("0 * *").unwrap()),
                }
                .into()
            } else {
                None
            }
        } else {
            None
        };

        Some(Enterprise {
            license,
            undelete: config
                .property_or_default::<Option<Duration>>("storage.undelete.retention", "false")
                .unwrap_or_default()
                .map(|retention| Undelete { retention }),
            trace_store,
            metrics_store,
        })
    }
}
