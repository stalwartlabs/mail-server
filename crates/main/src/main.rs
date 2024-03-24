/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::time::Duration;

use common::{
    config::{
        server::{ServerProtocol, Servers},
        tracers::Tracers,
    },
    Core,
};
use imap::core::{ImapSessionManager, IMAP};
use jmap::{api::JmapSessionManager, services::IPC_CHANNEL_BUFFER, JMAP};
use managesieve::core::ManageSieveSessionManager;
use smtp::core::{SmtpSessionManager, SMTP};
use store::Stores;
use tokio::sync::mpsc;
use utils::{
    config::{Config, ConfigError},
    wait_for_shutdown,
};

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Load config and apply macros
    let mut config = Config::init();
    config.resolve_macros().await;

    // Parse servers
    let servers = Servers::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Build stores
    let stores = Stores::parse(&mut config).await;
    let todo = "merge config with data store, resolve macros";

    // Enable tracing
    let guards = Tracers::parse(&mut config).enable(&mut config);
    tracing::info!(
        "Starting Stalwart Mail Server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Parse core
    let core = Core::parse(&mut config, stores).await;
    let store = core.storage.data.clone();
    let shared_core = core.into_shared();

    // Init servers
    let (delivery_tx, delivery_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let smtp = SMTP::init(&mut config, shared_core.clone(), delivery_tx).await;
    let jmap = JMAP::init(
        &mut config,
        delivery_rx,
        shared_core.clone(),
        smtp.inner.clone(),
    )
    .await;
    let imap = IMAP::init(&mut config, jmap.clone()).await;

    // Log configuration errors
    config.log_errors(guards.is_none());
    config.log_warnings(guards.is_none());

    // Spawn servers
    let shutdown_tx = servers.spawn(
        |server, shutdown_rx| {
            match &server.protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                    SmtpSessionManager::new(smtp.clone()),
                    shared_core.clone(),
                    shutdown_rx,
                ),
                ServerProtocol::Http => server.spawn(
                    JmapSessionManager::new(jmap.clone()),
                    shared_core.clone(),
                    shutdown_rx,
                ),
                ServerProtocol::Imap => server.spawn(
                    ImapSessionManager::new(imap.clone()),
                    shared_core.clone(),
                    shutdown_rx,
                ),
                ServerProtocol::ManageSieve => server.spawn(
                    ManageSieveSessionManager::new(imap.clone()),
                    shared_core.clone(),
                    shutdown_rx,
                ),
            };
        },
        store,
    );

    // Wait for shutdown signal
    wait_for_shutdown(&format!(
        "Shutting down Stalwart Mail Server v{}...",
        env!("CARGO_PKG_VERSION")
    ))
    .await;

    // Stop services
    let _ = shutdown_tx.send(true);

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
