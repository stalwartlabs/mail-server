/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use mail_send::Credentials;

use crate::{
    protocol::{request::Error, response::Response, Command, Mechanism},
    Session, State,
};

impl<T: SessionStream> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
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
                    requests.push(Err(err));
                }
            }
        }

        for request in requests {
            match request {
                Ok(command) => match self.validate_request(command).await {
                    Ok(command) => match command {
                        Command::User { name } => {
                            if let State::NotAuthenticated { username, .. } = &mut self.state {
                                let response = format!("{name} is a valid mailbox");
                                *username = Some(name);
                                self.write_ok(response).await?;
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
                            .await?;
                        }
                        Command::Quit => {
                            self.handle_quit().await?;
                        }
                        Command::Stat => self.handle_stat().await?,
                        Command::List { msg } => {
                            self.handle_list(msg).await?;
                        }
                        Command::Retr { msg } => {
                            self.handle_fetch(msg, None).await?;
                        }
                        Command::Dele { msg } => self.handle_dele(vec![msg]).await?,
                        Command::DeleMany { msgs } => self.handle_dele(msgs).await?,
                        Command::Top { msg, n } => {
                            self.handle_fetch(msg, n.into()).await?;
                        }
                        Command::Uidl { msg } => self.handle_uidl(msg).await?,
                        Command::Noop => {
                            self.write_ok("NOOP").await?;
                        }
                        Command::Rset => {
                            self.handle_rset().await?;
                        }
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
                            .await?;
                        }
                        Command::Stls => {
                            self.write_ok("Begin TLS negotiation now").await?;
                            return Ok(false);
                        }
                        Command::Utf8 => {
                            self.write_ok("UTF8 enabled").await?;
                        }
                        Command::Auth { mechanism, params } => {
                            self.handle_sasl(mechanism, params).await?;
                        }
                        Command::Apop { .. } => {
                            self.write_err("APOP not supported.").await?;
                        }
                    },
                    Err(err) => {
                        self.write_err(err).await?;
                    }
                },
                Err(err) => {
                    self.write_err(err).await?;
                }
            }
        }

        Ok(true)
    }

    async fn validate_request(
        &self,
        command: Command<String, Mechanism>,
    ) -> Result<Command<String, Mechanism>, &'static str> {
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
                            Err("Username was not provided.")
                        }
                    } else {
                        Err("Cannot authenticate over plain-text.")
                    }
                } else {
                    Err("Already authenticated.")
                }
            }
            Command::Auth { .. } => {
                if let State::NotAuthenticated { .. } = &self.state {
                    Ok(command)
                } else {
                    Err("Already authenticated.")
                }
            }
            Command::Stls => {
                if !self.stream.is_tls() {
                    Ok(command)
                } else {
                    Err("Already in TLS mode.")
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
                        match self
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
                        {
                            Ok(None) => Ok(command),
                            Ok(Some(_)) => Err("Too many requests"),
                            Err(_) => Err("Internal server error"),
                        }
                    } else {
                        Ok(command)
                    }
                } else {
                    Err("Not authenticated.")
                }
            }
        }
    }
}
