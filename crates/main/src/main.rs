/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use common::{config::server::ServerProtocol, core::BuildServer, manager::boot::BootManager};
use directory::backend::internal::MigrateDirectory;
use imap::core::ImapSessionManager;
use jmap::{api::JmapSessionManager, services::gossip::spawn::GossiperBuilder, StartServices};
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use smtp::{core::SmtpSessionManager, StartQueueManager};
use trc::Collector;
use utils::wait_for_shutdown;

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Load config and apply macros
    let mut init = BootManager::init().await;

    // Init services
    init.start_services().await;
    init.start_queue_manager();
    let gossiper = GossiperBuilder::try_parse(&mut init.config);

    // Log configuration errors
    init.config.log_errors();
    init.config.log_warnings();

    {
        let server = init.inner.build_server();

        // Log licensing information
        #[cfg(feature = "enterprise")]
        server.log_license_details();

        // Migrate directory
        if let Err(err) = server.store().migrate_directory().await {
            trc::error!(err.details("Directory migration failed"));
            std::process::exit(1);
        }
    }

    // Spawn servers
    let (shutdown_tx, shutdown_rx) = init.servers.spawn(|server, acceptor, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                SmtpSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Http => server.spawn(
                JmapSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Pop3 => server.spawn(
                Pop3SessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
        };
    });

    // Spawn gossip
    if let Some(gossiper) = gossiper {
        gossiper.spawn(init.inner, shutdown_rx.clone()).await;
    }

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Shutdown collector
    Collector::shutdown();

    // Stop services
    let _ = shutdown_tx.send(true);

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
