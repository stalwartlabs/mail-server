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
use utils::config::Config;

use super::{license::LicenseValidator, Enterprise};

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

        Some(Enterprise {
            license,
            undelete_period: config
                .property_or_default::<Option<Duration>>("storage.undelete.retention", "false")
                .unwrap_or_default(),
            trace_hold_period: config
                .property_or_default::<Option<Duration>>("tracing.history.retention", "30d")
                .unwrap_or(Some(Duration::from_secs(30 * 24 * 60 * 60))),
            trace_store: config
                .value("tracing.history.store")
                .and_then(|name| stores.stores.get(name))
                .cloned(),
        })
    }
}
