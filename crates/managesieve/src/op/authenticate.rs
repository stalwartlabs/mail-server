/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    auth::{
        sasl::{sasl_decode_challenge_oauth, sasl_decode_challenge_plain},
        AuthRequest,
    },
    listener::{limiter::ConcurrencyLimiter, SessionStream},
    ConcurrencyLimiters,
};
use directory::Permission;
use imap_proto::{
    protocol::authenticate::Mechanism,
    receiver::{self, Request},
};
use jmap::auth::rate_limit::RateLimiter;
use mail_parser::decoders::base64::base64_decode;
use std::sync::Arc;

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
            Mechanism::Plain | Mechanism::OAuthBearer => {
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
                        tag: String::new(),
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
                    .details("Authentication mechanism not supported."))
            }
        };

        // Throttle authentication requests
        self.server.is_auth_allowed_soft(&self.remote_addr).await?;

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
        let in_flight = match self
            .get_concurrency_limiter(access_token.primary_id())
            .map(|limiter| limiter.concurrent_requests.is_allowed())
        {
            Some(Some(limiter)) => Some(limiter),
            None => None,
            Some(None) => {
                return Err(trc::LimitEvent::ConcurrentRequest.into_err());
            }
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

    pub fn get_concurrency_limiter(&self, account_id: u32) -> Option<Arc<ConcurrencyLimiters>> {
        let rate = self.server.core.imap.rate_concurrent?;
        self.server
            .inner
            .data
            .imap_limiter
            .get(&account_id)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(ConcurrencyLimiters {
                    concurrent_requests: ConcurrencyLimiter::new(rate),
                    concurrent_uploads: ConcurrencyLimiter::new(rate),
                });
                self.server
                    .inner
                    .data
                    .imap_limiter
                    .insert(account_id, limiter.clone());
                limiter
            })
            .into()
    }
}
