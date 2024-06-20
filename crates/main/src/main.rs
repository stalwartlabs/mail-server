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
    config::server::ServerProtocol, manager::boot::BootManager,
    webhooks::manager::spawn_webhook_manager, Ipc, IPC_CHANNEL_BUFFER,
};
use imap::core::{ImapSessionManager, IMAP};
use jmap::{api::JmapSessionManager, services::gossip::spawn::GossiperBuilder, JMAP};
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use smtp::core::{SmtpSessionManager, SMTP};
use tokio::sync::mpsc;
use utils::wait_for_shutdown;

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Load config and apply macros
    let init = BootManager::init().await;

    // Parse core
    let mut config = init.config;
    let core = init.core;

    // Spawn webhook manager
    let webhook_tx = spawn_webhook_manager(core.clone());

    // Setup IPC channels
    let (delivery_tx, delivery_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let ipc = Ipc {
        delivery_tx,
        webhook_tx,
    };

    // Init servers
    let smtp = SMTP::init(&mut config, core.clone(), ipc).await;
    let jmap = JMAP::init(&mut config, delivery_rx, core.clone(), smtp.inner.clone()).await;
    let imap = IMAP::init(&mut config, jmap.clone()).await;
    let gossiper = GossiperBuilder::try_parse(&mut config);

    // Log configuration errors
    config.log_errors(init.guards.is_none());
    config.log_warnings(init.guards.is_none());

    // Spawn servers
    let (shutdown_tx, shutdown_rx) = init.servers.spawn(|server, acceptor, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                SmtpSessionManager::new(smtp.clone()),
                core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Http => server.spawn(
                JmapSessionManager::new(jmap.clone()),
                core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(imap.clone()),
                core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Pop3 => server.spawn(
                Pop3SessionManager::new(imap.clone()),
                core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(imap.clone()),
                core.clone(),
                acceptor,
                shutdown_rx,
            ),
        };
    });

    // Spawn gossip
    if let Some(gossiper) = gossiper {
        gossiper.spawn(jmap, shutdown_rx.clone()).await;
    }

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
