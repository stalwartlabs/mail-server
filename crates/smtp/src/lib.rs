/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use crate::core::{
    throttle::ThrottleKeyHasherBuilder, QueueCore, ReportCore, SessionCore, TlsConnectors, SMTP,
};
use std::sync::Arc;

use config::{
    auth::ConfigAuth, database::ConfigDatabase, list::ConfigList, queue::ConfigQueue,
    remote::ConfigHost, report::ConfigReport, resolver::ConfigResolver, scripts::ConfigSieve,
    session::ConfigSession, ConfigContext,
};
use dashmap::DashMap;
use lookup::Lookup;
use mail_send::smtp::tls::build_tls_connector;
use queue::manager::SpawnQueue;
use reporting::scheduler::SpawnReport;
use tokio::sync::mpsc;
use utils::{
    config::{Config, Servers},
    UnwrapFailure,
};

pub mod config;
pub mod core;
pub mod inbound;
pub mod lookup;
pub mod outbound;
pub mod queue;
pub mod reporting;

pub static USER_AGENT: &str = concat!("StalwartSMTP/", env!("CARGO_PKG_VERSION"),);

impl SMTP {
    pub async fn init(
        config: &Config,
        servers: &Servers,
        #[cfg(feature = "local_delivery")] delivery_tx: mpsc::Sender<utils::ipc::DeliveryEvent>,
    ) -> Arc<Self> {
        // Read configuration parameters
        let mut config_ctx = ConfigContext::new(&servers.inner);

        #[cfg(feature = "local_delivery")]
        config_ctx.lookup.insert(
            "local".to_string(),
            Arc::new(Lookup::Local(delivery_tx.clone())),
        );

        config
            .parse_remote_hosts(&mut config_ctx)
            .failed("Configuration error");
        config
            .parse_databases(&mut config_ctx)
            .failed("Configuration error");
        config
            .parse_lists(&mut config_ctx)
            .failed("Configuration error");
        config
            .parse_signatures(&mut config_ctx)
            .failed("Configuration error");
        let sieve_config = config
            .parse_sieve(&mut config_ctx)
            .failed("Configuration error");
        let session_config = config
            .parse_session_config(&config_ctx)
            .failed("Configuration error");
        let queue_config = config
            .parse_queue(&config_ctx)
            .failed("Configuration error");
        let mail_auth_config = config
            .parse_mail_auth(&config_ctx)
            .failed("Configuration error");
        let report_config = config
            .parse_reports(&config_ctx)
            .failed("Configuration error");

        // Build core
        let (queue_tx, queue_rx) = mpsc::channel(1024);
        let (report_tx, report_rx) = mpsc::channel(1024);
        let core = Arc::new(SMTP {
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(
                    config
                        .property::<usize>("global.thread-pool")
                        .failed("Failed to parse thread pool size")
                        .filter(|v| *v > 0)
                        .unwrap_or_else(num_cpus::get),
                )
                .build()
                .unwrap(),
            resolvers: config.build_resolvers().failed("Failed to build resolvers"),
            session: SessionCore {
                config: session_config,
                throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                    config
                        .property("global.shared-map.capacity")
                        .failed("Failed to parse shared map capacity")
                        .unwrap_or(2),
                    ThrottleKeyHasherBuilder::default(),
                    config
                        .property::<u64>("global.shared-map.shard")
                        .failed("Failed to parse shared map shard amount")
                        .unwrap_or(32)
                        .next_power_of_two() as usize,
                ),
            },
            queue: QueueCore {
                config: queue_config,
                throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                    config
                        .property("global.shared-map.capacity")
                        .failed("Failed to parse shared map capacity")
                        .unwrap_or(2),
                    ThrottleKeyHasherBuilder::default(),
                    config
                        .property::<u64>("global.shared-map.shard")
                        .failed("Failed to parse shared map shard amount")
                        .unwrap_or(32)
                        .next_power_of_two() as usize,
                ),
                id_seq: 0.into(),
                quota: DashMap::with_capacity_and_hasher_and_shard_amount(
                    config
                        .property("global.shared-map.capacity")
                        .failed("Failed to parse shared map capacity")
                        .unwrap_or(2),
                    ThrottleKeyHasherBuilder::default(),
                    config
                        .property::<u64>("global.shared-map.shard")
                        .failed("Failed to parse shared map shard amount")
                        .unwrap_or(32)
                        .next_power_of_two() as usize,
                ),
                tx: queue_tx,
                connectors: TlsConnectors {
                    pki_verify: build_tls_connector(false),
                    dummy_verify: build_tls_connector(true),
                },
            },
            report: ReportCore {
                tx: report_tx,
                config: report_config,
            },
            mail_auth: mail_auth_config,
            sieve: sieve_config,
            #[cfg(feature = "local_delivery")]
            delivery_tx,
        });

        // Spawn queue manager
        queue_rx.spawn(core.clone(), core.queue.read_queue().await);

        // Spawn report manager
        report_rx.spawn(core.clone(), core.report.read_reports().await);

        // Spawn remote hosts
        for host in config_ctx.hosts.into_values() {
            if host.lookup {
                host.spawn(config);
            }
        }

        core
    }
}
