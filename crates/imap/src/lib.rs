/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
