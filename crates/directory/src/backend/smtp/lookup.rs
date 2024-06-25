/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::{smtp::AssertReply, Credentials};
use smtp_proto::Severity;

use crate::{DirectoryError, Principal, QueryBy};

use super::{SmtpClient, SmtpDirectory};

impl SmtpDirectory {
    pub async fn query(&self, query: QueryBy<'_>) -> crate::Result<Option<Principal<u32>>> {
        if let QueryBy::Credentials(credentials) = query {
            self.pool.get().await?.authenticate(credentials).await
        } else {
            Err(DirectoryError::unsupported("smtp", "query"))
        }
    }

    pub async fn email_to_ids(&self, _address: &str) -> crate::Result<Vec<u32>> {
        Err(DirectoryError::unsupported("smtp", "email_to_ids"))
    }

    pub async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        let mut conn = self.pool.get().await?;
        if !conn.sent_mail_from {
            conn.client
                .cmd(b"MAIL FROM:<>\r\n")
                .await?
                .assert_positive_completion()?;
            conn.sent_mail_from = true;
        }
        let reply = conn
            .client
            .cmd(format!("RCPT TO:<{address}>\r\n").as_bytes())
            .await?;
        match reply.severity() {
            Severity::PositiveCompletion => {
                conn.num_rcpts += 1;
                if conn.num_rcpts >= conn.max_rcpt {
                    let _ = conn.client.rset().await;
                    conn.num_rcpts = 0;
                    conn.sent_mail_from = false;
                }
                Ok(true)
            }
            Severity::PermanentNegativeCompletion => Ok(false),
            _ => Err(mail_send::Error::UnexpectedReply(reply).into()),
        }
    }

    pub async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        self.pool
            .get()
            .await?
            .expand(&format!("VRFY {address}\r\n"))
            .await
    }

    pub async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        self.pool
            .get()
            .await?
            .expand(&format!("EXPN {address}\r\n"))
            .await
    }

    pub async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}

impl SmtpClient {
    async fn authenticate(
        &mut self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal<u32>>> {
        match self
            .client
            .authenticate(credentials, &self.capabilities)
            .await
        {
            Ok(_) => Ok(Some(Principal::default())),
            Err(err) => match &err {
                mail_send::Error::AuthenticationFailed(err) if err.code() == 535 => {
                    self.num_auth_failures += 1;
                    Ok(None)
                }
                _ => Err(err.into()),
            },
        }
    }

    async fn expand(&mut self, command: &str) -> crate::Result<Vec<String>> {
        let reply = self.client.cmd(command.as_bytes()).await?;
        match reply.code() {
            250 | 251 => Ok(reply
                .message()
                .split('\n')
                .map(|p| p.to_string())
                .collect::<Vec<String>>()),
            550 | 551 | 553 | 500 | 502 => Err(DirectoryError::Unsupported),
            _ => Err(mail_send::Error::UnexpectedReply(reply).into()),
        }
    }
}
