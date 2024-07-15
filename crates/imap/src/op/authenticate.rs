/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{config::server::ServerProtocol, listener::SessionStream};
use imap_proto::{
    protocol::{authenticate::Mechanism, capability::Capability},
    receiver::{self, Request},
    Command, ResponseCode, StatusResponse,
};
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use std::sync::Arc;

use crate::core::{Session, SessionData, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> trc::Result<()> {
        let mut args = request.parse_authenticate()?;

        match args.mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer => {
                if !args.params.is_empty() {
                    let challenge = base64_decode(args.params.pop().unwrap().as_bytes())
                        .ok_or_else(|| {
                            trc::Cause::Authentication
                                .into_err()
                                .details("Failed to decode challenge.")
                                .id(args.tag.clone())
                                .code(ResponseCode::Parse)
                        })?;

                    let credentials = if args.mechanism == Mechanism::Plain {
                        decode_challenge_plain(&challenge)
                    } else {
                        decode_challenge_oauth(&challenge)
                    }
                    .map_err(|err| {
                        trc::Cause::Authentication
                            .into_err()
                            .details(err)
                            .id(args.tag.clone())
                    })?;

                    self.authenticate(credentials, args.tag).await
                } else {
                    self.receiver.request = receiver::Request {
                        tag: args.tag,
                        command: Command::Authenticate,
                        tokens: vec![receiver::Token::Argument(args.mechanism.into_bytes())],
                    };
                    self.receiver.state = receiver::State::Argument { last_ch: b' ' };
                    self.write_bytes(b"+ \"\"\r\n".to_vec()).await
                }
            }
            _ => Err(trc::Cause::Authentication
                .into_err()
                .details("Authentication mechanism not supported.")
                .id(args.tag)
                .code(ResponseCode::Cannot)),
        }
    }

    pub async fn authenticate(
        &mut self,
        credentials: Credentials<String>,
        tag: String,
    ) -> trc::Result<()> {
        // Throttle authentication requests
        self.jmap.is_auth_allowed_soft(&self.remote_addr).await?;

        // Authenticate
        let access_token = match credentials {
            Credentials::Plain { username, secret } | Credentials::XOauth2 { username, secret } => {
                self.jmap
                    .authenticate_plain(&username, &secret, self.remote_addr, ServerProtocol::Imap)
                    .await?
            }
            Credentials::OAuthBearer { token } => {
                let (account_id, _, _) = self
                    .jmap
                    .validate_access_token("access_token", &token)
                    .await?;

                self.jmap.get_access_token(account_id).await?
            }
        };

        // Enforce concurrency limits
        let in_flight = match self
            .get_concurrency_limiter(access_token.primary_id())
            .map(|limiter| limiter.concurrent_requests.is_allowed())
        {
            Some(Some(limiter)) => Some(limiter),
            None => None,
            Some(None) => {
                return Err(trc::Cause::TooManyConcurrentRequests.into());
            }
        };

        // Cache access token
        let access_token = Arc::new(access_token);
        self.jmap.cache_access_token(access_token.clone());

        // Create session
        let todo = "handle auth errors";
        self.state = State::Authenticated {
            data: Arc::new(SessionData::new(self, &access_token, in_flight).await?),
        };
        self.write_bytes(
            StatusResponse::ok("Authentication successful")
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(true, self.is_tls),
                })
                .with_tag(tag)
                .into_bytes(),
        )
        .await

        /*if let Some(access_token) = access_token {

        } else {
            self.write_bytes(
                StatusResponse::no(if is_totp_error {
                    "Missing TOTP code, try with 'secret$totp_code'."
                } else {
                    "Authentication failed."
                })
                .with_tag(tag)
                .with_code(ResponseCode::AuthenticationFailed)
                .into_bytes(),
            )
            .await?;

            let auth_failures = self.state.auth_failures();
            if auth_failures < self.jmap.core.imap.max_auth_failures {
                self.state = State::NotAuthenticated {
                    auth_failures: auth_failures + 1,
                };
                Ok(())
            } else {
                self.write_bytes(
                    StatusResponse::bye("Too many authentication failures").into_bytes(),
                )
                .await?;
                tracing::debug!(
                    parent: &self.span,
                    event = "disconnect",
                    "Too many authentication failures, disconnecting.",
                );
                Err(())
            }
        }*/
    }

    pub async fn handle_unauthenticate(&mut self, request: Request<Command>) -> trc::Result<()> {
        self.state = State::NotAuthenticated { auth_failures: 0 };

        self.write_bytes(
            StatusResponse::completed(Command::Unauthenticate)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}

pub fn decode_challenge_plain(challenge: &[u8]) -> Result<Credentials<String>, &'static str> {
    let mut username = Vec::new();
    let mut secret = Vec::new();
    let mut arg_num = 0;
    for &ch in challenge {
        if ch != 0 {
            if arg_num == 1 {
                username.push(ch);
            } else if arg_num == 2 {
                secret.push(ch);
            }
        } else {
            arg_num += 1;
        }
    }

    match (String::from_utf8(username), String::from_utf8(secret)) {
        (Ok(username), Ok(secret)) if !username.is_empty() && !secret.is_empty() => {
            Ok((username, secret).into())
        }
        _ => Err("Invalid AUTH=PLAIN challenge."),
    }
}

pub fn decode_challenge_oauth(challenge: &[u8]) -> Result<Credentials<String>, &'static str> {
    let mut saw_marker = true;
    for (pos, &ch) in challenge.iter().enumerate() {
        if saw_marker {
            if challenge
                .get(pos..)
                .map_or(false, |b| b.starts_with(b"auth=Bearer "))
            {
                let pos = pos + 12;
                return Ok(Credentials::OAuthBearer {
                    token: String::from_utf8(
                        challenge
                            .get(
                                pos..pos
                                    + challenge
                                        .get(pos..)
                                        .and_then(|c| c.iter().position(|&ch| ch == 0x01))
                                        .unwrap_or(challenge.len()),
                            )
                            .ok_or("Failed to find end of bearer token")?
                            .to_vec(),
                    )
                    .map_err(|_| "Bearer token is not a valid UTF-8 string.")?,
                });
            } else {
                saw_marker = false;
            }
        } else if ch == 0x01 {
            saw_marker = true;
        }
    }

    Err("Failed to find 'auth=Bearer' in challenge.")
}
