/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::hash_map::Entry,
    sync::atomic::{AtomicBool, AtomicU64},
    time::Duration,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use utils::config::Config;

use crate::{InMemoryStore, Stores};

use super::{HttpStore, HttpStoreConfig, HttpStoreFormat};

impl Stores {
    pub fn parse_http_stores(&mut self, config: &mut Config, is_reload: bool) {
        // Parse remote lists
        for id in config
            .sub_keys("http-lookup", ".url")
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
        {
            let id_ = id.as_str();
            if !config
                .property_or_default(("http-lookup", id_, "enable"), "true")
                .unwrap_or(true)
            {
                continue;
            }

            let format = match config
                .value_require(("http-lookup", id_, "format"))
                .unwrap_or_default()
            {
                "list" => HttpStoreFormat::List,
                "csv" => HttpStoreFormat::Csv {
                    index_key: config
                        .property_require(("http-lookup", id_, "index.key"))
                        .unwrap_or(0),
                    index_value: config.property(("http-lookup", id_, "index.value")),
                    separator: config
                        .property_or_default::<String>(("http-lookup", id_, "separator"), ",")
                        .unwrap_or_default()
                        .chars()
                        .next()
                        .unwrap_or(','),
                    skip_first: config
                        .property_or_default::<bool>(("http-lookup", id_, "skip-first"), "false")
                        .unwrap_or(false),
                },
                other => {
                    let message = format!("Invalid format: {other:?}");
                    config.new_build_error(("http-lookup", id_, "format"), message);
                    continue;
                }
            };

            let http_config = HttpStoreConfig {
                url: config
                    .value_require(("http-lookup", id_, "url"))
                    .unwrap_or_default()
                    .to_string(),
                retry: config
                    .property_or_default::<Duration>(("http-lookup", id_, "retry"), "1h")
                    .unwrap_or(Duration::from_secs(3600))
                    .as_secs(),
                refresh: config
                    .property_or_default::<Duration>(("http-lookup", id_, "refresh"), "12h")
                    .unwrap_or(Duration::from_secs(43200))
                    .as_secs(),
                timeout: config
                    .property_or_default::<Duration>(("http-lookup", id_, "timeout"), "30s")
                    .unwrap_or(Duration::from_secs(30)),
                gzipped: config
                    .property_or_default::<bool>(("http-lookup", id_, "gzipped"), "false")
                    .unwrap_or_default(),
                max_size: config
                    .property_or_default::<usize>(("http-lookup", id_, "limits.size"), "104857600")
                    .unwrap_or(104857600),
                max_entries: config
                    .property_or_default::<usize>(("http-lookup", id_, "limits.entries"), "100000")
                    .unwrap_or(100000),
                max_entry_size: config
                    .property_or_default::<usize>(("http-lookup", id_, "limits.entry-size"), "512")
                    .unwrap_or(512),
                format,
                id,
            };

            match self.in_memory_stores.entry(http_config.id.clone()) {
                Entry::Vacant(entry) => {
                    let store = HttpStore {
                        entries: ArcSwap::from_pointee(AHashMap::new()),
                        expires: AtomicU64::new(0),
                        in_flight: AtomicBool::new(false),
                        config: http_config,
                    };

                    entry.insert(InMemoryStore::Http(store.into()));
                }
                Entry::Occupied(e) if !is_reload => {
                    config.new_build_error(
                        ("http-lookup", e.key().as_str()),
                        "An in-memory store with this id already exists",
                    );
                }
                _ => {}
            }
        }
    }
}
