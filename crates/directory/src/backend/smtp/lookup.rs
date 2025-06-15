/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::{Credentials, smtp::AssertReply};
use smtp_proto::Severity;

use crate::{IntoError, Principal, QueryBy, Type, backend::RcptType};

use super::{SmtpClient, SmtpDirectory};

impl SmtpDirectory {
    pub async fn query(&self, query: QueryBy<'_>) -> trc::Result<Option<Principal>> {
        if let QueryBy::Credentials(credentials) = query {
            self.pool
                .get()
                .await
                .map_err(|err| err.into_error().caused_by(trc::location!()))?
                .authenticate(credentials)
                .await
        } else {
            Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
        }
    }

    pub async fn email_to_id(&self, _address: &str) -> trc::Result<Option<u32>> {
        Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<RcptType> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;
        if !conn.sent_mail_from {
            conn.client
                .cmd(b"MAIL FROM:<>\r\n")
                .await
                .map_err(|err| err.into_error().caused_by(trc::location!()))?
                .assert_positive_completion()
                .map_err(|err| err.into_error().caused_by(trc::location!()))?;
            conn.sent_mail_from = true;
        }
        let reply = conn
            .client
            .cmd(format!("RCPT TO:<{address}>\r\n").as_bytes())
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;
        match reply.severity() {
            Severity::PositiveCompletion => {
                conn.num_rcpts += 1;
                if conn.num_rcpts >= conn.max_rcpt {
                    let _ = conn.client.rset().await;
                    conn.num_rcpts = 0;
                    conn.sent_mail_from = false;
                }
                Ok(RcptType::Mailbox)
            }
            Severity::PermanentNegativeCompletion => Ok(RcptType::Invalid),
            _ => Err(trc::StoreEvent::UnexpectedError
                .ctx(trc::Key::Code, reply.code())
                .ctx(trc::Key::Details, reply.message)),
        }
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        self.pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .expand(&format!("VRFY {address}\r\n"))
            .await
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        self.pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .expand(&format!("EXPN {address}\r\n"))
            .await
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}

impl SmtpClient {
    async fn authenticate(
        &mut self,
        credentials: &Credentials<String>,
    ) -> trc::Result<Option<Principal>> {
        match self
            .client
            .authenticate(credentials, &self.capabilities)
            .await
        {
            Ok(_) => Ok(Some(Principal::new(u32::MAX, Type::Individual))),
            Err(err) => match &err {
                mail_send::Error::AuthenticationFailed(err) if err.code() == 535 => {
                    self.num_auth_failures += 1;
                    Ok(None)
                }
                _ => Err(err.into_error()),
            },
        }
    }

    async fn expand(&mut self, command: &str) -> trc::Result<Vec<String>> {
        let reply = self
            .client
            .cmd(command.as_bytes())
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;
        match reply.code() {
            250 | 251 => Ok(reply
                .message()
                .split('\n')
                .map(|p| p.into())
                .collect::<Vec<String>>()),
            code @ (550 | 551 | 553 | 500 | 502) => {
                Err(trc::StoreEvent::NotSupported.ctx(trc::Key::Code, code))
            }
            code => Err(trc::StoreEvent::UnexpectedError
                .ctx(trc::Key::Code, code)
                .ctx(trc::Key::Details, reply.message)),
        }
    }
}
