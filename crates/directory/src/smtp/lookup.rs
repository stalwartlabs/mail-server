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

use mail_send::{smtp::AssertReply, Credentials};
use smtp_proto::Severity;

use crate::{Directory, DirectoryError, Principal};

use super::{SmtpClient, SmtpDirectory};

#[async_trait::async_trait]
impl Directory for SmtpDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        self.pool.get().await?.authenticate(credentials).await
    }

    async fn principal(&self, _name: &str) -> crate::Result<Option<Principal>> {
        Err(DirectoryError::unsupported("smtp", "principal"))
    }

    async fn emails_by_name(&self, _: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("smtp", "emails_by_name"))
    }

    async fn names_by_email(&self, _address: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("smtp", "names_by_email"))
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
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

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        self.pool
            .get()
            .await?
            .expand(&format!("VRFY {address}\r\n"))
            .await
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        self.pool
            .get()
            .await?
            .expand(&format!("EXPN {address}\r\n"))
            .await
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}

impl SmtpClient {
    async fn authenticate(
        &mut self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
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
