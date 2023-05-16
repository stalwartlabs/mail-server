/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::sync::Arc;

use mail_send::smtp::AssertReply;
use smtp_proto::Severity;
use tokio::sync::{mpsc, oneshot};

use super::{spawn::LoggedUnwrap, Event, Item, LookupItem, LookupResult, RemoteLookup};

pub struct SmtpClientBuilder {
    pub builder: mail_send::SmtpClientBuilder<String>,
    pub max_rcpt: usize,
    pub max_auth_errors: usize,
}

impl SmtpClientBuilder {
    pub async fn lookup_smtp(
        &self,
        mut lookup: LookupItem,
        tx: &mpsc::Sender<Event>,
    ) -> Result<(), mail_send::Error> {
        let mut client = self.builder.connect().await?;
        let mut sent_mail_from = false;
        let mut num_rcpts = 0;
        let mut num_auth_failures = 0;
        let capabilities = client
            .capabilities(&self.builder.local_host, self.builder.is_lmtp)
            .await?;

        loop {
            let (result, is_reusable): (LookupResult, bool) = match &lookup.item {
                Item::IsAccount(rcpt_to) => {
                    if !sent_mail_from {
                        client
                            .cmd(b"MAIL FROM:<>\r\n")
                            .await?
                            .assert_positive_completion()?;
                        sent_mail_from = true;
                    }
                    let reply = client
                        .cmd(format!("RCPT TO:<{rcpt_to}>\r\n").as_bytes())
                        .await?;
                    let result = match reply.severity() {
                        Severity::PositiveCompletion => {
                            num_rcpts += 1;
                            LookupResult::True
                        }
                        Severity::PermanentNegativeCompletion => LookupResult::False,
                        _ => return Err(mail_send::Error::UnexpectedReply(reply)),
                    };

                    // Try to reuse the connection with any queued requests
                    (result, num_rcpts < self.max_rcpt)
                }
                Item::Authenticate(credentials) => {
                    let result = match client.authenticate(credentials, &capabilities).await {
                        Ok(_) => true,
                        Err(err) => match &err {
                            mail_send::Error::AuthenticationFailed(err) if err.code() == 535 => {
                                num_auth_failures += 1;
                                false
                            }
                            _ => {
                                return Err(err);
                            }
                        },
                    };
                    (
                        result.into(),
                        !result && num_auth_failures < self.max_auth_errors,
                    )
                }
                Item::Verify(address) | Item::Expand(address) => {
                    let reply = client
                        .cmd(
                            if matches!(&lookup.item, Item::Verify(_)) {
                                format!("VRFY {address}\r\n")
                            } else {
                                format!("EXPN {address}\r\n")
                            }
                            .as_bytes(),
                        )
                        .await?;
                    match reply.code() {
                        250 | 251 => (
                            reply
                                .message()
                                .split('\n')
                                .map(|p| p.to_string())
                                .collect::<Vec<String>>()
                                .into(),
                            true,
                        ),
                        550 | 551 | 553 | 500 | 502 => (LookupResult::False, true),
                        _ => {
                            return Err(mail_send::Error::UnexpectedReply(reply));
                        }
                    }
                }
            };

            // Try to reuse the connection with any queued requests
            let cached_result = match &result {
                LookupResult::True => Some(true),
                LookupResult::False => Some(false),
                LookupResult::Values(_) => None,
            };
            lookup.result.send(result).logged_unwrap();
            if is_reusable {
                let (next_lookup_tx, next_lookup_rx) = oneshot::channel::<Option<LookupItem>>();
                if tx
                    .send(Event::WorkerReady {
                        item: lookup.item,
                        result: cached_result,
                        next_lookup: next_lookup_tx.into(),
                    })
                    .await
                    .logged_unwrap()
                {
                    if let Ok(Some(next_lookup)) = next_lookup_rx.await {
                        lookup = next_lookup;
                        continue;
                    }
                }
            } else {
                tx.send(Event::WorkerReady {
                    item: lookup.item,
                    result: cached_result,
                    next_lookup: None,
                })
                .await
                .logged_unwrap();
            }
            break;
        }

        Ok(())
    }
}

impl RemoteLookup for Arc<SmtpClientBuilder> {
    fn spawn_lookup(&self, lookup: LookupItem, tx: mpsc::Sender<Event>) {
        let builder = self.clone();
        tokio::spawn(async move {
            if let Err(err) = builder.lookup_smtp(lookup, &tx).await {
                tracing::warn!(
                    context = "remote",
                    event = "lookup-failed",
                    remote.addr = &builder.builder.addr,
                    remote.protocol = "smtp",
                    "Remote lookup failed: {}",
                    err
                );
                tx.send(Event::WorkerFailed).await.logged_unwrap();
            }
        });
    }
}
