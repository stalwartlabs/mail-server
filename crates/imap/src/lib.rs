/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use core::{ImapInstance, Inner, IMAP};
use std::{collections::hash_map::RandomState, sync::Arc};

use dashmap::DashMap;
use imap_proto::{protocol::capability::Capability, ResponseCode, StatusResponse};
use jmap::JmapInstance;
use utils::{
    config::Config,
    lru_cache::{LruCache, LruCached},
};

pub mod core;
pub mod op;

static SERVER_GREETING: &str = "Stalwart IMAP4rev2 at your service.";

impl IMAP {
    pub async fn init(config: &mut Config, jmap_instance: JmapInstance) -> ImapInstance {
        let shard_amount = config
            .property::<u64>("cache.shard")
            .unwrap_or(32)
            .next_power_of_two() as usize;
        let capacity = config.property("cache.capacity").unwrap_or(100);

        let inner = Inner {
            greeting_plain: StatusResponse::ok(SERVER_GREETING)
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(false, false),
                })
                .into_bytes(),
            greeting_tls: StatusResponse::ok(SERVER_GREETING)
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(false, true),
                })
                .into_bytes(),
            rate_limiter: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                RandomState::default(),
                shard_amount,
            ),
            cache_account: LruCache::with_capacity(
                config.property("cache.account.size").unwrap_or(2048),
            ),
            cache_mailbox: LruCache::with_capacity(
                config.property("cache.mailbox.size").unwrap_or(2048),
            ),
        };

        ImapInstance {
            jmap_instance,
            imap_inner: Arc::new(inner),
        }
    }
}

pub struct ImapError;

pub type Result<T> = std::result::Result<T, ()>;
pub type OpResult = std::result::Result<(), ()>;
