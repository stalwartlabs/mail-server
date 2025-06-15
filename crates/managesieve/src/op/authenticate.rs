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
    protocol::authenticate::Mechanism,
    receiver::{self, Request},
};
use mail_parser::decoders::base64::base64_decode;

use crate::core::{Command, Session, State, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        if request.tokens.is_empty() {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Authentication mechanism missing."));
        }

        let mut tokens = request.tokens.into_iter();
        let mechanism = Mechanism::parse(&tokens.next().unwrap().unwrap_bytes())
            .map_err(|err| trc::AuthEvent::Error.into_err().details(err))?;
        let mut params: Vec<String> = tokens
            .filter_map(|token| token.unwrap_string().ok())
            .collect();

        let credentials = match mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {
                if !params.is_empty() {
                    base64_decode(params.pop().unwrap().as_bytes())
                        .and_then(|challenge| {
                            if mechanism == Mechanism::Plain {
                                sasl_decode_challenge_plain(&challenge)
                            } else {
                                sasl_decode_challenge_oauth(&challenge)
                            }
                        })
                        .ok_or_else(|| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details("Failed to decode challenge.")
                        })?
                } else {
                    self.receiver.request = receiver::Request {
                        tag: "".into(),
                        command: Command::Authenticate,
                        tokens: vec![receiver::Token::Argument(mechanism.into_bytes())],
                    };
                    self.receiver.state = receiver::State::Argument { last_ch: b' ' };
                    return Ok(b"{0}\r\n".to_vec());
                }
            }
            _ => {
                return Err(trc::AuthEvent::Error
                    .into_err()
                    .details("Authentication mechanism not supported."));
            }
        };

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
                    match &self.state {
                        State::NotAuthenticated { auth_failures }
                            if *auth_failures < self.server.core.imap.max_auth_failures =>
                        {
                            self.state = State::NotAuthenticated {
                                auth_failures: auth_failures + 1,
                            };
                        }
                        _ => {
                            return trc::AuthEvent::TooManyAttempts.into_err().caused_by(err);
                        }
                    }
                }

                err
            })
            .and_then(|token| {
                token
                    .assert_has_permission(Permission::SieveAuthenticate)
                    .map(|_| token)
            })?;

        // Enforce concurrency limits
        let in_flight = match access_token.is_imap_request_allowed() {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => {
                return Err(trc::LimitEvent::ConcurrentRequest.into_err());
            }
            LimiterResult::Disabled => None,
        };

        // Create session
        self.state = State::Authenticated {
            access_token,
            in_flight,
        };

        Ok(StatusResponse::ok("Authentication successful").into_bytes())
    }

    pub async fn handle_unauthenticate(&mut self) -> trc::Result<Vec<u8>> {
        self.state = State::NotAuthenticated { auth_failures: 0 };

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::Unauthenticate),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        Ok(StatusResponse::ok("Unauthenticate successful.").into_bytes())
    }
}
