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

use crate::core::{throttle::ThrottleKeyHasherBuilder, TlsConnectors};
use core::{Inner, SmtpInstance, SMTP};

use common::{config::scripts::ScriptCache, Ipc, SharedCore};
use dashmap::DashMap;
use mail_send::smtp::tls::build_tls_connector;
use queue::manager::SpawnQueue;
use reporting::scheduler::SpawnReport;
use tokio::sync::mpsc;
use utils::{config::Config, snowflake::SnowflakeIdGenerator};

pub mod core;
pub mod inbound;
pub mod outbound;
pub mod queue;
pub mod reporting;
pub mod scripts;

impl SMTP {
    pub async fn init(config: &mut Config, core: SharedCore, ipc: Ipc) -> SmtpInstance {
        // Build inner
        let capacity = config.property("cache.capacity").unwrap_or(2);
        let shard = config
            .property::<u64>("cache.shard")
            .unwrap_or(32)
            .next_power_of_two() as usize;
        let (queue_tx, queue_rx) = mpsc::channel(1024);
        let (report_tx, report_rx) = mpsc::channel(1024);
        let inner = Inner {
            session_throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                ThrottleKeyHasherBuilder::default(),
                shard,
            ),
            queue_throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                ThrottleKeyHasherBuilder::default(),
                shard,
            ),
            queue_tx,
            report_tx,
            snowflake_id: config
                .property::<u64>("cluster.node-id")
                .map(SnowflakeIdGenerator::with_node_id)
                .unwrap_or_default(),
            connectors: TlsConnectors {
                pki_verify: build_tls_connector(false),
                dummy_verify: build_tls_connector(true),
            },
            ipc,
            script_cache: ScriptCache::parse(config),
        };
        let inner = SmtpInstance::new(core, inner);

        // Spawn queue manager
        queue_rx.spawn(inner.clone());

        // Spawn report manager
        report_rx.spawn(inner.clone());

        inner
    }
}
