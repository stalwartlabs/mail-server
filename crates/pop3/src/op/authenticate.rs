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
use jmap::auth::rate_limit::RateLimiter;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use std::sync::Arc;

use crate::{
    protocol::{request, Command, Mechanism},
    Session, State,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_sasl(
        &mut self,
        mechanism: Mechanism,
        mut params: Vec<String>,
    ) -> trc::Result<()> {
        match mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer => {
                if !params.is_empty() {
                    let credentials = base64_decode(params.pop().unwrap().as_bytes())
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
                                .details("Invalid SASL challenge")
                        })?;

                    self.handle_auth(credentials).await
                } else {
                    // TODO: This hack is temporary until the SASL library is developed
                    self.receiver.state = request::State::Argument {
                        request: Command::Auth {
                            mechanism: mechanism.as_str().as_bytes().to_vec(),
                            params: vec![],
                        },
                        num: 1,
                        last_is_space: true,
                    };

                    self.write_bytes("+\r\n").await
                }
            }
            _ => Err(trc::AuthEvent::Error
                .into_err()
                .details("Authentication mechanism not supported.")),
        }
    }

    pub async fn handle_auth(&mut self, credentials: Credentials<String>) -> trc::Result<()> {
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
                        State::NotAuthenticated {
                            auth_failures,
                            username,
                        } if *auth_failures < self.server.core.imap.max_auth_failures => {
                            self.state = State::NotAuthenticated {
                                auth_failures: auth_failures + 1,
                                username: username.clone(),
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
                    .assert_has_permission(Permission::Pop3Authenticate)
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

        // Fetch mailbox
        let mailbox = self.fetch_mailbox(access_token.primary_id()).await?;

        // Create session
        self.state = State::Authenticated {
            in_flight,
            mailbox,
            access_token,
        };
        self.write_ok("Authentication successful").await
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
