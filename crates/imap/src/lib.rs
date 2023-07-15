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

use std::{collections::hash_map::RandomState, sync::Arc};

use crate::core::IMAP;

use dashmap::DashMap;
use imap_proto::{protocol::capability::Capability, ResponseCode, StatusResponse};
use utils::config::Config;

pub mod core;
pub mod op;

static SERVER_GREETING: &str = concat!(
    "Stalwart IMAP4rev2 v",
    env!("CARGO_PKG_VERSION"),
    " at your service."
);

impl IMAP {
    pub async fn init(config: &Config) -> utils::config::Result<Arc<Self>> {
        Ok(Arc::new(IMAP {
            max_request_size: config.property_or_static("imap.request.max-size", "52428800")?,
            max_auth_failures: config.property_or_static("imap.auth.max-failures", "3")?,
            name_shared: config
                .value("imap.folders.name.shared")
                .unwrap_or("Shared Folders")
                .to_string(),
            name_all: config
                .value("imap.folders.name.all")
                .unwrap_or("All Mail")
                .to_string(),
            timeout_auth: config.property_or_static("imap.timeout.authenticated", "30m")?,
            timeout_unauth: config.property_or_static("imap.timeout.anonymous", "1m")?,
            timeout_idle: config.property_or_static("imap.timeout.idle", "30m")?,
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
                config
                    .property("imap.rate-limit.cache.size")?
                    .unwrap_or(2048),
                RandomState::default(),
                config
                    .property::<u64>("global.shared-map.shard")?
                    .unwrap_or(32)
                    .next_power_of_two() as usize,
            ),
            rate_requests: config.property_or_static("imap.rate-limit.requests", "2000/1m")?,
            rate_concurrent: config.property("imap.rate-limit.concurrent")?.unwrap_or(4),
            allow_plain_auth: config.property_or_static("imap.auth.allow-plain-text", "false")?,
        }))
    }
}

pub struct ImapError;

pub type Result<T> = std::result::Result<T, ()>;
pub type OpResult = std::result::Result<(), ()>;
