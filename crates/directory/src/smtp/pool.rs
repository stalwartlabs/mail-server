use bb8::ManageConnection;
use mail_send::{smtp::AssertReply, Error};

use super::{SmtpClient, SmtpConnectionManager};

#[async_trait::async_trait]
impl ManageConnection for SmtpConnectionManager {
    type Connection = SmtpClient;
    type Error = Error;

    /// Attempts to create a new connection.
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let mut client = self.builder.connect().await?;
        let capabilities = client
            .capabilities(&self.builder.local_host, self.builder.is_lmtp)
            .await?;

        Ok(SmtpClient {
            capabilities,
            client,
            max_auth_errors: self.max_auth_errors,
            max_rcpt: self.max_rcpt,
            num_rcpts: 0,
            num_auth_failures: 0,
            sent_mail_from: false,
        })
    }

    /// Determines if the connection is still connected to the database.
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.client
            .cmd(b"NOOP\r\n")
            .await?
            .assert_positive_completion()
    }

    /// Synchronously determine if the connection is no longer usable, if possible.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.num_auth_failures >= conn.max_auth_errors
    }
}
