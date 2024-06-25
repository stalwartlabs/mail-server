/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use imap_proto::receiver::{self, Request};
use jmap_proto::types::{collection::Collection, property::Property};
use store::query::Filter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Command, ResponseCode, ResponseType, Session, State, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        /*let tmp = "dd";
        for line in String::from_utf8_lossy(bytes).split("\r\n") {
            println!("<- {:?}", &line[..std::cmp::min(line.len(), 100)]);
        }*/

        let mut bytes = bytes.iter();
        let mut requests = Vec::with_capacity(2);
        let mut needs_literal = None;

        loop {
            match self.receiver.parse(&mut bytes) {
                Ok(request) => match self.validate_request(request).await {
                    Ok(request) => {
                        requests.push(request);
                    }
                    Err(response) => {
                        self.write(&response.into_bytes()).await?;
                    }
                },
                Err(receiver::Error::NeedsMoreData) => {
                    break;
                }
                Err(receiver::Error::NeedsLiteral { size }) => {
                    needs_literal = size.into();
                    break;
                }
                Err(receiver::Error::Error { response }) => {
                    self.write(&StatusResponse::no(response.message).into_bytes())
                        .await?;
                    break;
                }
            }
        }

        for request in requests {
            match match request.command {
                Command::ListScripts => self.handle_listscripts().await,
                Command::PutScript => self.handle_putscript(request).await,
                Command::SetActive => self.handle_setactive(request).await,
                Command::GetScript => self.handle_getscript(request).await,
                Command::DeleteScript => self.handle_deletescript(request).await,
                Command::RenameScript => self.handle_renamescript(request).await,
                Command::CheckScript => self.handle_checkscript(request).await,
                Command::HaveSpace => self.handle_havespace(request).await,
                Command::Capability => self.handle_capability("").await,
                Command::Authenticate => self.handle_authenticate(request).await,
                Command::StartTls => {
                    self.write(b"OK Begin TLS negotiation now\r\n").await?;
                    return Ok(false);
                }
                Command::Logout => self.handle_logout().await,
                Command::Noop => self.handle_noop(request).await,
                Command::Unauthenticate => self.handle_unauthenticate().await,
            } {
                Ok(response) => {
                    self.write(&response).await?;
                }
                Err(err) => {
                    let disconnect = matches!(err.rtype, ResponseType::Bye | ResponseType::Ok);
                    self.write(&err.into_bytes()).await?;
                    if disconnect {
                        return Err(());
                    }
                }
            }
        }

        if let Some(needs_literal) = needs_literal {
            self.write(format!("OK Ready for {} bytes.\r\n", needs_literal).as_bytes())
                .await?;
        }

        Ok(true)
    }

    async fn validate_request(
        &self,
        command: Request<Command>,
    ) -> Result<Request<Command>, StatusResponse> {
        match &command.command {
            Command::Capability | Command::Logout | Command::Noop => Ok(command),
            Command::Authenticate => {
                if let State::NotAuthenticated { .. } = &self.state {
                    if self.stream.is_tls() || self.jmap.core.imap.allow_plain_auth {
                        Ok(command)
                    } else {
                        Err(StatusResponse::no("Cannot authenticate over plain-text.")
                            .with_code(ResponseCode::EncryptNeeded))
                    }
                } else {
                    Err(StatusResponse::no("Already authenticated."))
                }
            }
            Command::StartTls => {
                if !self.stream.is_tls() {
                    Ok(command)
                } else {
                    Err(StatusResponse::no("Already in TLS mode."))
                }
            }
            Command::HaveSpace
            | Command::PutScript
            | Command::ListScripts
            | Command::SetActive
            | Command::GetScript
            | Command::DeleteScript
            | Command::RenameScript
            | Command::CheckScript
            | Command::Unauthenticate => {
                if let State::Authenticated { access_token, .. } = &self.state {
                    if let Some(rate) = &self.jmap.core.imap.rate_requests {
                        match self
                            .jmap
                            .core
                            .storage
                            .lookup
                            .is_rate_allowed(
                                format!("ireq:{}", access_token.primary_id()).as_bytes(),
                                rate,
                                true,
                            )
                            .await
                        {
                            Ok(None) => Ok(command),
                            Ok(Some(_)) => Err(StatusResponse::no("Too many requests")
                                .with_code(ResponseCode::TryLater)),
                            Err(_) => Err(StatusResponse::no("Internal server error")
                                .with_code(ResponseCode::TryLater)),
                        }
                    } else {
                        Ok(command)
                    }
                } else {
                    Err(StatusResponse::no("Not authenticated."))
                }
            }
        }
    }
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    #[inline(always)]
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let err = match self.stream.write_all(bytes).await {
            Ok(_) => match self.stream.flush().await {
                Ok(_) => {
                    tracing::trace!(parent: &self.span,
                            event = "write",
                            data = std::str::from_utf8(bytes).unwrap_or_default() ,
                            size = bytes.len());
                    return Ok(());
                }
                Err(err) => err,
            },
            Err(err) => err,
        };

        tracing::debug!(parent: &self.span,
            event = "error",
            "Failed to write to stream: {:?}", err);
        Err(())
    }

    #[inline(always)]
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        match self.stream.read(bytes).await {
            Ok(len) => {
                tracing::trace!(parent: &self.span,
                                event = "read",
                                data =  bytes
                                    .get(0..len)
                                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                    .unwrap_or("[invalid UTF8]"),
                                size = len);
                Ok(len)
            }
            Err(err) => {
                tracing::trace!(
                    parent: &self.span,
                    event = "error",
                    "Failed to read from stream: {:?}", err
                );
                Err(())
            }
        }
    }
}

impl<T: AsyncWrite + AsyncRead> Session<T> {
    pub async fn get_script_id(&self, account_id: u32, name: &str) -> Result<u32, StatusResponse> {
        self.jmap
            .core
            .storage
            .data
            .filter(
                account_id,
                Collection::SieveScript,
                vec![Filter::eq(Property::Name, name)],
            )
            .await
            .map_err(|_| StatusResponse::database_failure())
            .and_then(|results| {
                results.results.min().ok_or_else(|| {
                    StatusResponse::no("There is no script by that name")
                        .with_code(ResponseCode::NonExistent)
                })
            })
    }
}
