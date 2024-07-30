/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{throttle::ThrottleKeyHasherBuilder, TlsConnectors};
use core::{Inner, SmtpInstance, SMTP};
use std::sync::Arc;

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
    pub async fn init(
        config: &mut Config,
        core: SharedCore,
        ipc: Ipc,
        span_id_gen: Arc<SnowflakeIdGenerator>,
    ) -> SmtpInstance {
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
            queue_id_gen: config
                .property::<u64>("cluster.node-id")
                .map(SnowflakeIdGenerator::with_node_id)
                .unwrap_or_default(),
            span_id_gen,
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
