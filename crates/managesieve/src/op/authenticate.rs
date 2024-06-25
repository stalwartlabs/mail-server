/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::server::ServerProtocol,
    listener::{limiter::ConcurrencyLimiter, SessionStream},
    AuthResult,
};
use imap::op::authenticate::{decode_challenge_oauth, decode_challenge_plain};
use imap_proto::{
    protocol::authenticate::Mechanism,
    receiver::{self, Request},
};
use jmap::auth::rate_limit::ConcurrencyLimiters;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use std::sync::Arc;

use crate::core::{Command, Session, State, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> crate::op::OpResult {
        if request.tokens.is_empty() {
            return Err(StatusResponse::no("Authentication mechanism missing."));
        }

        let mut tokens = request.tokens.into_iter();
        let mechanism =
            Mechanism::parse(&tokens.next().unwrap().unwrap_bytes()).map_err(StatusResponse::no)?;
        let mut params: Vec<String> = tokens
            .filter_map(|token| token.unwrap_string().ok())
            .collect();

        let credentials = match mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer => {
                if !params.is_empty() {
                    let challenge = base64_decode(params.pop().unwrap().as_bytes())
                        .ok_or_else(|| StatusResponse::no("Failed to decode challenge."))?;
                    (if mechanism == Mechanism::Plain {
                        decode_challenge_plain(&challenge)
                    } else {
                        decode_challenge_oauth(&challenge)
                    }
                    .map_err(StatusResponse::no))?
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
                return Err(StatusResponse::no(
                    "Authentication mechanism not supported.",
                ))
            }
        };

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
            return Err(StatusResponse::bye(
                "Too many authentication requests from this IP address.",
            ));
        }

        // Authenticate
        let access_token = match credentials {
            Credentials::Plain { username, secret } | Credentials::XOauth2 { username, secret } => {
                match self
                    .jmap
                    .authenticate_plain(
                        &username,
                        &secret,
                        self.remote_addr,
                        ServerProtocol::ManageSieve,
                    )
                    .await
                {
                    AuthResult::Success(token) => Some(token),
                    AuthResult::Failure => None,
                    AuthResult::Banned => {
                        return Err(StatusResponse::bye(
                            "Too many authentication requests from this IP address.",
                        ))
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
                    return Err(StatusResponse::bye("Too many concurrent connections."));
                }
            };

            // Cache access token
            let access_token = Arc::new(access_token);
            self.jmap.cache_access_token(access_token.clone());

            // Create session
            self.state = State::Authenticated {
                access_token,
                in_flight,
            };

            Ok(StatusResponse::ok("Authentication successful").into_bytes())
        } else {
            match &self.state {
                State::NotAuthenticated { auth_failures }
                    if *auth_failures < self.jmap.core.imap.max_auth_failures =>
                {
                    self.state = State::NotAuthenticated {
                        auth_failures: auth_failures + 1,
                    };
                    Ok(StatusResponse::no("Authentication failed").into_bytes())
                }
                _ => {
                    tracing::debug!(
                        parent: &self.span,
                        event = "disconnect",
                        "Too many authentication failures, disconnecting.",
                    );
                    Err(StatusResponse::bye("Too many authentication failures"))
                }
            }
        }
    }

    pub async fn handle_unauthenticate(&mut self) -> super::OpResult {
        self.state = State::NotAuthenticated { auth_failures: 0 };

        Ok(StatusResponse::ok("Unauthenticate successful.").into_bytes())
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
