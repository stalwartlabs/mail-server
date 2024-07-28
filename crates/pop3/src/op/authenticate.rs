/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::{limiter::ConcurrencyLimiter, SessionStream};
use imap::op::authenticate::{decode_challenge_oauth, decode_challenge_plain};
use jmap::auth::rate_limit::ConcurrencyLimiters;
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
                        .ok_or("Failed to decode challenge.")
                        .and_then(|challenge| {
                            if mechanism == Mechanism::Plain {
                                decode_challenge_plain(&challenge)
                            } else {
                                decode_challenge_oauth(&challenge)
                            }
                        })
                        .map_err(|err| trc::AuthEvent::Error.into_err().details(err))?;

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
        self.jmap.is_auth_allowed_soft(&self.remote_addr).await?;

        // Authenticate
        let access_token = match credentials {
            Credentials::Plain { username, secret } | Credentials::XOauth2 { username, secret } => {
                self.jmap
                    .authenticate_plain(&username, &secret, self.remote_addr, self.session_id)
                    .await
            }
            Credentials::OAuthBearer { token } => {
                match self
                    .jmap
                    .validate_access_token("access_token", &token)
                    .await
                {
                    Ok((account_id, _, _)) => self.jmap.get_access_token(account_id).await,
                    Err(err) => Err(err),
                }
            }
        }
        .map_err(|err| {
            if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
                match &self.state {
                    State::NotAuthenticated {
                        auth_failures,
                        username,
                    } if *auth_failures < self.jmap.core.imap.max_auth_failures => {
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

        // Cache access token
        let access_token = Arc::new(access_token);
        self.jmap.cache_access_token(access_token.clone());

        // Fetch mailbox
        let mailbox = self.fetch_mailbox(access_token.primary_id()).await?;

        // Create session
        self.state = State::Authenticated { in_flight, mailbox };
        self.write_ok("Authentication successful").await
    }

    pub fn get_concurrency_limiter(&self, account_id: u32) -> Option<Arc<ConcurrencyLimiters>> {
        let rate = self.jmap.core.imap.rate_concurrent?;
        self.imap
            .rate_limiter
            .get(&account_id)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(ConcurrencyLimiters {
                    concurrent_requests: ConcurrencyLimiter::new(rate),
                    concurrent_uploads: ConcurrencyLimiter::new(rate),
                });
                self.imap.rate_limiter.insert(account_id, limiter.clone());
                limiter
            })
            .into()
    }
}
