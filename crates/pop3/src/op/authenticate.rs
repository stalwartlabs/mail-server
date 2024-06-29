/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::server::ServerProtocol,
    listener::{limiter::ConcurrencyLimiter, SessionStream},
    AuthFailureReason, AuthResult,
};
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
    ) -> Result<(), ()> {
        match mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer => {
                if !params.is_empty() {
                    let result = base64_decode(params.pop().unwrap().as_bytes())
                        .ok_or("Failed to decode challenge.")
                        .and_then(|challenge| {
                            if mechanism == Mechanism::Plain {
                                decode_challenge_plain(&challenge)
                            } else {
                                decode_challenge_oauth(&challenge)
                            }
                        });

                    match result {
                        Ok(credentials) => self.handle_auth(credentials).await,
                        Err(err) => self.write_err(err).await,
                    }
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
            _ => {
                self.write_err("Authentication mechanism not supported.")
                    .await
            }
        }
    }

    pub async fn handle_auth(&mut self, credentials: Credentials<String>) -> Result<(), ()> {
        // Throttle authentication requests
        if self
            .jmap
            .is_auth_allowed_soft(&self.remote_addr)
            .await
            .is_err()
        {
            tracing::debug!(parent: &self.span,
                event = "disconnect",
                "Too many authentication attempts, disconnecting.",
            );

            self.write_err("Too many authentication requests from this IP address.")
                .await?;
            return Err(());
        }

        // Authenticate
        let mut is_totp_error = false;
        let access_token = match credentials {
            Credentials::Plain { username, secret } | Credentials::XOauth2 { username, secret } => {
                match self
                    .jmap
                    .authenticate_plain(&username, &secret, self.remote_addr, ServerProtocol::Pop3)
                    .await
                {
                    AuthResult::Success(token) => Some(token),
                    AuthResult::Failure(
                        AuthFailureReason::InvalidCredentials | AuthFailureReason::InternalError(_),
                    ) => None,
                    AuthResult::Failure(AuthFailureReason::MissingTotp) => {
                        is_totp_error = true;
                        None
                    }
                    AuthResult::Failure(AuthFailureReason::Banned) => {
                        self.write_err("Too many authentication requests from this IP address.")
                            .await?;
                        return Err(());
                    }
                }
            }
            Credentials::OAuthBearer { token } => {
                match self
                    .jmap
                    .validate_access_token("access_token", &token)
                    .await
                {
                    Ok((account_id, _, _)) => self.jmap.get_access_token(account_id).await,
                    Err(err) => {
                        tracing::debug!(
                            parent: &self.span,
                            context = "authenticate",
                            err = err,
                            "Failed to validate access token."
                        );
                        None
                    }
                }
            }
        };

        if let Some(access_token) = access_token {
            // Enforce concurrency limits
            let in_flight = match self
                .get_concurrency_limiter(access_token.primary_id())
                .map(|limiter| limiter.concurrent_requests.is_allowed())
            {
                Some(Some(limiter)) => Some(limiter),
                None => None,
                Some(None) => {
                    tracing::debug!(parent: &self.span,
                        event = "disconnect",
                        "Too many concurrent connection.",
                    );
                    self.write_err("Too many concurrent connections.").await?;
                    return Err(());
                }
            };

            // Cache access token
            let access_token = Arc::new(access_token);
            self.jmap.cache_access_token(access_token.clone());

            // Fetch mailbox
            match self.fetch_mailbox(access_token.primary_id()).await {
                Ok(mailbox) => {
                    // Create session
                    self.state = State::Authenticated { in_flight, mailbox };

                    self.write_ok("Authentication successful").await
                }
                Err(_) => {
                    self.write_err("Temporary server failure").await?;
                    Err(())
                }
            }
        } else {
            match &self.state {
                State::NotAuthenticated {
                    auth_failures,
                    username,
                } if *auth_failures < self.jmap.core.imap.max_auth_failures => {
                    self.state = State::NotAuthenticated {
                        auth_failures: auth_failures + 1,
                        username: username.clone(),
                    };
                    self.write_err(if is_totp_error {
                        "Missing TOTP code, try with 'secret$totp_code'."
                    } else {
                        "Authentication failed."
                    })
                    .await
                }
                _ => {
                    tracing::debug!(
                        parent: &self.span,
                        event = "disconnect",
                        "Too many authentication failures, disconnecting.",
                    );
                    self.write_err("Too many authentication failures").await?;
                    Err(())
                }
            }
        }
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
