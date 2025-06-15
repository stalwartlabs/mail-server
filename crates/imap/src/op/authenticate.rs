/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    auth::{
        AuthRequest,
        sasl::{sasl_decode_challenge_oauth, sasl_decode_challenge_plain},
    },
    listener::{SessionStream, limiter::LimiterResult},
};

use directory::Permission;
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{authenticate::Mechanism, capability::Capability},
    receiver::{self, Request},
};
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use std::sync::Arc;

use crate::core::{Session, SessionData, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> trc::Result<()> {
        let mut args = request.parse_authenticate()?;

        match args.mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {
                if !args.params.is_empty() {
                    let challenge = base64_decode(args.params.pop().unwrap().as_bytes())
                        .ok_or_else(|| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details("Failed to decode challenge.")
                                .id(args.tag.clone())
                                .code(ResponseCode::Parse)
                        })?;

                    let credentials = if args.mechanism == Mechanism::Plain {
                        sasl_decode_challenge_plain(&challenge)
                    } else {
                        sasl_decode_challenge_oauth(&challenge)
                    }
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Invalid SASL challenge.")
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
                    self.write_bytes(b"+ \r\n".to_vec()).await
                }
            }
            _ => Err(trc::AuthEvent::Error
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
        // Authenticate
        let access_token = self
            .server
            .authenticate(&AuthRequest::from_credentials(
                credentials,
                self.session_id,
                self.remote_addr,
            ))
            .await
            .map_err(|err| {
                if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
                    let auth_failures = self.state.auth_failures();
                    if auth_failures < self.server.core.imap.max_auth_failures {
                        self.state = State::NotAuthenticated {
                            auth_failures: auth_failures + 1,
                        };
                    } else {
                        return trc::AuthEvent::TooManyAttempts.into_err().caused_by(err);
                    }
                }

                err.id(tag.clone())
            })
            .and_then(|token| {
                token
                    .assert_has_permission(Permission::ImapAuthenticate)
                    .map(|_| token)
            })?;

        // Enforce concurrency limits
        let in_flight = match access_token.is_imap_request_allowed() {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => {
                return Err(trc::LimitEvent::ConcurrentRequest
                    .into_err()
                    .id(tag.clone()));
            }
            LimiterResult::Disabled => None,
        };

        // Create session
        self.state = State::Authenticated {
            data: Arc::new(
                SessionData::new(self, access_token, in_flight)
                    .await
                    .map_err(|err| err.id(tag.clone()))?,
            ),
        };
        self.write_bytes(
            StatusResponse::ok("Authentication successful")
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(
                        true,
                        !self.is_tls && self.instance.acceptor.is_tls(),
                    ),
                })
                .with_tag(tag)
                .into_bytes(),
        )
        .await
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
