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

use crate::{
    config::RelayHost,
    core::{
        throttle::ThrottleKeyHasherBuilder, QueueCore, ReportCore, SessionCore, TlsConnectors, SMTP,
    },
};
use std::sync::Arc;

use config::{
    auth::ConfigAuth, queue::ConfigQueue, report::ConfigReport, resolver::ConfigResolver,
    scripts::ConfigSieve, session::ConfigSession, shared::ConfigShared, ConfigContext,
};
use dashmap::DashMap;
use directory::Directories;
use mail_send::smtp::tls::build_tls_connector;
use queue::manager::SpawnQueue;
use reporting::scheduler::SpawnReport;
use store::Stores;
use tokio::sync::mpsc;
use utils::{
    config::{Config, ServerProtocol, Servers},
    snowflake::SnowflakeIdGenerator,
    UnwrapFailure,
};

pub mod config;
pub mod core;
pub mod inbound;
pub mod outbound;
pub mod queue;
pub mod reporting;
pub mod scripts;

pub static USER_AGENT: &str = concat!("StalwartSMTP/", env!("CARGO_PKG_VERSION"),);
pub static DAEMON_NAME: &str = concat!("Stalwart SMTP v", env!("CARGO_PKG_VERSION"),);

impl SMTP {
    pub async fn init(
        config: &Config,
        servers: &Servers,
        stores: &Stores,
        directory: &Directories,
        #[cfg(feature = "local_delivery")] delivery_tx: mpsc::Sender<utils::ipc::DeliveryEvent>,
    ) -> Result<Arc<Self>, String> {
        // Read configuration parameters
        let mut config_ctx = ConfigContext::new(&servers.inner);
        config_ctx.directory = directory.clone();
        config_ctx.stores = stores.clone();

        // Parse configuration
        config.parse_signatures(&mut config_ctx)?;
        let sieve_config = config.parse_sieve(&mut config_ctx)?;
        let session_config = config.parse_session_config()?;
        let queue_config = config.parse_queue()?;
        let mail_auth_config = config.parse_mail_auth()?;
        let report_config = config.parse_reports()?;
        let mut shared = config.parse_shared(&config_ctx)?;

        // Add local delivery host
        #[cfg(feature = "local_delivery")]
        {
            shared.relay_hosts.insert(
                "local".to_string(),
                RelayHost {
                    address: String::new(),
                    port: 0,
                    protocol: ServerProtocol::Jmap,
                    tls_implicit: Default::default(),
                    tls_allow_invalid_certs: Default::default(),
                    auth: None,
                },
            );
        }

        // Build core
        let (queue_tx, queue_rx) = mpsc::channel(1024);
        let (report_tx, report_rx) = mpsc::channel(1024);
        let core = Arc::new(SMTP {
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(
                    config
                        .property::<usize>("global.thread-pool")?
                        .filter(|v| *v > 0)
                        .unwrap_or_else(num_cpus::get),
                )
                .build()
                .unwrap(),
            resolvers: config.build_resolvers().failed("Failed to build resolvers"),
            session: SessionCore {
                config: session_config,
                throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                    config.property("global.shared-map.capacity")?.unwrap_or(2),
                    ThrottleKeyHasherBuilder::default(),
                    config
                        .property::<u64>("global.shared-map.shard")?
                        .unwrap_or(32)
                        .next_power_of_two() as usize,
                ),
            },
            queue: QueueCore {
                config: queue_config,
                throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                    config.property("global.shared-map.capacity")?.unwrap_or(2),
                    ThrottleKeyHasherBuilder::default(),
                    config
                        .property::<u64>("global.shared-map.shard")?
                        .unwrap_or(32)
                        .next_power_of_two() as usize,
                ),
                snowflake_id: config
                    .property::<u64>("storage.cluster.node-id")?
                    .map(SnowflakeIdGenerator::with_node_id)
                    .unwrap_or_else(SnowflakeIdGenerator::new),
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
            shared,
            #[cfg(feature = "local_delivery")]
            delivery_tx,
        });

        // Spawn queue manager
        queue_rx.spawn(core.clone());

        // Spawn report manager
        report_rx.spawn(core.clone());

        Ok(core)
    }
}
