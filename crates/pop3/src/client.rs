/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::{SessionResult, SessionStream};
use mail_send::Credentials;
use trc::AddContext;

use crate::{
    protocol::{request::Error, response::Response, Command, Mechanism},
    Session, State,
};

impl<T: SessionStream> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> SessionResult {
        /*let tmp = "dd";
        for line in String::from_utf8_lossy(bytes).split("\r\n") {
            println!("<- {:?}", &line[..std::cmp::min(line.len(), 100)]);
        }*/

        let mut bytes = bytes.iter();
        let mut requests = Vec::with_capacity(2);

        loop {
            match self.receiver.parse(&mut bytes) {
                Ok(request) => {
                    // Group delete requests when possible
                    match (request, requests.last_mut()) {
                        (Command::Dele { msg }, Some(Ok(Command::DeleMany { msgs }))) => {
                            msgs.push(msg);
                        }
                        (Command::Dele { msg }, Some(Ok(Command::Dele { msg: other_msg }))) => {
                            let request = Ok(Command::DeleMany {
                                msgs: vec![*other_msg, msg],
                            });
                            requests.pop();
                            requests.push(request);
                        }
                        (request, _) => {
                            requests.push(Ok(request));
                        }
                    }
                }
                Err(Error::NeedsMoreData) => {
                    break;
                }
                Err(Error::Parse(err)) => {
                    requests.push(Err(trc::Cause::Pop3.into_err().details(err)));
                }
            }
        }

        for request in requests {
            let result = match request {
                Ok(command) => match self.validate_request(command).await {
                    Ok(command) => match command {
                        Command::User { name } => {
                            if let State::NotAuthenticated { username, .. } = &mut self.state {
                                let response = format!("{name} is a valid mailbox");
                                *username = Some(name);
                                self.write_ok(response)
                                    .await
                                    .map(|_| SessionResult::Continue)
                            } else {
                                unreachable!();
                            }
                        }
                        Command::Pass { string } => {
                            let username =
                                if let State::NotAuthenticated { username, .. } = &mut self.state {
                                    username.take().unwrap()
                                } else {
                                    unreachable!()
                                };
                            self.handle_auth(Credentials::Plain {
                                username,
                                secret: string,
                            })
                            .await
                            .map(|_| SessionResult::Continue)
                        }
                        Command::Quit => self.handle_quit().await.map(|_| SessionResult::Close),
                        Command::Stat => self.handle_stat().await.map(|_| SessionResult::Continue),
                        Command::List { msg } => {
                            self.handle_list(msg).await.map(|_| SessionResult::Continue)
                        }
                        Command::Retr { msg } => self
                            .handle_fetch(msg, None)
                            .await
                            .map(|_| SessionResult::Continue),
                        Command::Dele { msg } => self
                            .handle_dele(vec![msg])
                            .await
                            .map(|_| SessionResult::Continue),
                        Command::DeleMany { msgs } => self
                            .handle_dele(msgs)
                            .await
                            .map(|_| SessionResult::Continue),
                        Command::Top { msg, n } => self
                            .handle_fetch(msg, n.into())
                            .await
                            .map(|_| SessionResult::Continue),
                        Command::Uidl { msg } => {
                            self.handle_uidl(msg).await.map(|_| SessionResult::Continue)
                        }
                        Command::Noop => {
                            self.write_ok("NOOP").await.map(|_| SessionResult::Continue)
                        }
                        Command::Rset => self.handle_rset().await.map(|_| SessionResult::Continue),
                        Command::Capa => {
                            let mechanisms =
                                if self.stream.is_tls() || self.jmap.core.imap.allow_plain_auth {
                                    vec![Mechanism::Plain, Mechanism::OAuthBearer]
                                } else {
                                    vec![Mechanism::OAuthBearer]
                                };

                            self.write_bytes(
                                Response::Capability::<u32> {
                                    mechanisms,
                                    stls: !self.stream.is_tls(),
                                }
                                .serialize(),
                            )
                            .await
                            .map(|_| SessionResult::Continue)
                        }
                        Command::Stls => self
                            .write_ok("Begin TLS negotiation now")
                            .await
                            .map(|_| SessionResult::UpgradeTls),
                        Command::Utf8 => self
                            .write_ok("UTF8 enabled")
                            .await
                            .map(|_| SessionResult::Continue),
                        Command::Auth { mechanism, params } => self
                            .handle_sasl(mechanism, params)
                            .await
                            .map(|_| SessionResult::Continue),
                        Command::Apop { .. } => {
                            Err(trc::Cause::Pop3.into_err().details("APOP not supported."))
                        }
                    },
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            };

            match result {
                Ok(SessionResult::Continue) => (),
                Ok(result) => return result,
                Err(err) => {
                    if !self.write_err(err).await {
                        return SessionResult::Close;
                    }
                }
            }
        }

        SessionResult::Continue
    }

    async fn validate_request(
        &self,
        command: Command<String, Mechanism>,
    ) -> trc::Result<Command<String, Mechanism>> {
        match &command {
            Command::Capa | Command::Quit | Command::Noop => Ok(command),
            Command::Auth {
                mechanism: Mechanism::Plain,
                ..
            }
            | Command::User { .. }
            | Command::Pass { .. }
            | Command::Apop { .. } => {
                if let State::NotAuthenticated { username, .. } = &self.state {
                    if self.stream.is_tls() || self.jmap.core.imap.allow_plain_auth {
                        if !matches!(command, Command::Pass { .. }) || username.is_some() {
                            Ok(command)
                        } else {
                            Err(trc::Cause::Pop3
                                .into_err()
                                .details("Username was not provided."))
                        }
                    } else {
                        Err(trc::Cause::Pop3
                            .into_err()
                            .details("Cannot authenticate over plain-text."))
                    }
                } else {
                    Err(trc::Cause::Pop3
                        .into_err()
                        .details("Already authenticated."))
                }
            }
            Command::Auth { .. } => {
                if let State::NotAuthenticated { .. } = &self.state {
                    Ok(command)
                } else {
                    Err(trc::Cause::Pop3
                        .into_err()
                        .details("Already authenticated."))
                }
            }
            Command::Stls => {
                if !self.stream.is_tls() {
                    Ok(command)
                } else {
                    Err(trc::Cause::Pop3.into_err().details("Already in TLS mode."))
                }
            }

            Command::List { .. }
            | Command::Retr { .. }
            | Command::Dele { .. }
            | Command::DeleMany { .. }
            | Command::Top { .. }
            | Command::Uidl { .. }
            | Command::Utf8
            | Command::Stat
            | Command::Rset => {
                if let State::Authenticated { mailbox, .. } = &self.state {
                    if let Some(rate) = &self.jmap.core.imap.rate_requests {
                        if self
                            .jmap
                            .core
                            .storage
                            .lookup
                            .is_rate_allowed(
                                format!("ireq:{}", mailbox.account_id).as_bytes(),
                                rate,
                                true,
                            )
                            .await
                            .caused_by(trc::location!())?
                            .is_none()
                        {
                            Ok(command)
                        } else {
                            Err(trc::LimitCause::TooManyRequests.into_err())
                        }
                    } else {
                        Ok(command)
                    }
                } else {
                    Err(trc::Cause::Pop3.into_err().details("Not authenticated."))
                }
            }
        }
    }
}
