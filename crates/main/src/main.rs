use std::time::Duration;

use jmap::{api::JmapSessionManager, services::IPC_CHANNEL_BUFFER, JMAP};
use smtp::{
    core::{SmtpAdminSessionManager, SmtpSessionManager, SMTP},
    outbound::delivery,
};
use tokio::sync::mpsc;
use utils::{
    config::{Config, ServerProtocol},
    enable_tracing, wait_for_shutdown, UnwrapFailure,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = Config::init();
    let servers = config.parse_servers().failed("Invalid configuration");

    // Bind ports and drop privileges
    servers.bind(&config);

    // Enable tracing
    let _tracer = enable_tracing(&config).failed("Failed to enable tracing");
    tracing::info!(
        "Starting Stalwart mail server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Init servers
    let (delivery_tx, delivery_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let smtp = SMTP::init(&config, &servers, delivery_tx).await;
    let jmap = JMAP::init(&config, delivery_rx).await;

    // Spawn servers
    let shutdown_tx = servers.spawn(|server, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                server.spawn(SmtpSessionManager::new(smtp.clone()), shutdown_rx)
            }
            ServerProtocol::Http => {
                server.spawn(SmtpAdminSessionManager::new(smtp.clone()), shutdown_rx)
            }
            ServerProtocol::Jmap => {
                server.spawn(JmapSessionManager::new(jmap.clone()), shutdown_rx)
            }
            ServerProtocol::Imap => unimplemented!("IMAP is not implemented yet"),
        };
    });

    // Wait for shutdown signal
    wait_for_shutdown().await;
    tracing::info!(
        "Shutting down Stalwart mail server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Stop services
    let _ = shutdown_tx.send(true);

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
