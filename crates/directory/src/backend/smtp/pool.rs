/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use async_trait::async_trait;
use deadpool::managed;
use mail_send::{smtp::AssertReply, Error};

use super::{SmtpClient, SmtpConnectionManager};

#[async_trait]
impl managed::Manager for SmtpConnectionManager {
    type Type = SmtpClient;
    type Error = Error;

    async fn create(&self) -> Result<SmtpClient, Error> {
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

    async fn recycle(
        &self,
        conn: &mut SmtpClient,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<Error> {
        if conn.num_auth_failures < conn.max_auth_errors {
            conn.client
                .cmd(b"NOOP\r\n")
                .await?
                .assert_positive_completion()
                .map(|_| ())
                .map_err(managed::RecycleError::Backend)
        } else {
            Err(managed::RecycleError::StaticMessage(
                "No longer valid: Too many authentication failures",
            ))
        }
    }
}
