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
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;

use crate::{
    Session, State,
    protocol::{Command, Mechanism, request},
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_sasl(
        &mut self,
        mechanism: Mechanism,
        mut params: Vec<String>,
    ) -> trc::Result<()> {
        match mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {
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
        let in_flight = match access_token.is_imap_request_allowed() {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => {
                return Err(trc::LimitEvent::ConcurrentRequest.into_err());
            }
            LimiterResult::Disabled => None,
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
}
