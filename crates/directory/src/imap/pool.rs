use std::sync::atomic::Ordering;

use bb8::ManageConnection;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::{ImapClient, ImapConnectionManager, ImapError};

#[async_trait::async_trait]
impl ManageConnection for ImapConnectionManager {
    type Connection = ImapClient<TlsStream<TcpStream>>;
    type Error = ImapError;

    /// Attempts to create a new connection.
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let mut conn = ImapClient::connect(
            &self.addr,
            self.timeout,
            &self.tls_connector,
            &self.tls_hostname,
            self.tls_implicit,
        )
        .await?;

        // Obtain the list of supported authentication mechanisms.
        conn.mechanisms = self.mechanisms.load(Ordering::Relaxed);
        if conn.mechanisms == 0 {
            conn.mechanisms = conn.authentication_mechanisms().await?;
            self.mechanisms.store(conn.mechanisms, Ordering::Relaxed);
        }

        Ok(conn)
    }

    /// Determines if the connection is still connected to the database.
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.noop().await
    }

    /// Synchronously determine if the connection is no longer usable, if possible.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        false
    }
}
