/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::sync::Arc;

use imap::op::authenticate::{decode_challenge_oauth, decode_challenge_plain};
use imap_proto::{
    protocol::authenticate::Mechanism,
    receiver::{self, Request},
};
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, IsTls, Session, State, StatusResponse};

impl<T: AsyncRead + AsyncWrite + IsTls> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> crate::op::OpResult {
        if request.tokens.is_empty() {
            return Err(StatusResponse::no("Authentication mechanism missing."));
        }

        let mut tokens = request.tokens.into_iter();
        let mechanism =
            Mechanism::parse(&tokens.next().unwrap().unwrap_bytes()).map_err(StatusResponse::no)?;
        let mut params: Vec<String> = tokens
            .into_iter()
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
        if self.jmap.is_auth_allowed(self.remote_addr.clone()).is_err() {
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
                self.jmap.authenticate_plain(&username, &secret).await
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
            let in_flight = self
                .imap
                .get_authenticated_limiter(access_token.primary_id())
                .lock()
                .concurrent_requests
                .is_allowed();
            if let Some(in_flight) = in_flight {
                // Cache access token
                let access_token = Arc::new(access_token);
                self.jmap.cache_access_token(access_token.clone());

                // Create session
                self.state = State::Authenticated {
                    access_token,
                    in_flight,
                };

                self.handle_capability("Authentication successful").await
            } else {
                tracing::debug!(parent: &self.span,
                    event = "disconnect",
                    "Too many concurrent connection.",
                );
                Err(StatusResponse::bye("Too many concurrent connections."))
            }
        } else {
            match &self.state {
                State::NotAuthenticated { auth_failures }
                    if *auth_failures < self.imap.max_auth_failures =>
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
}
