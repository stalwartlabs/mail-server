/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use smtp_proto::{IntoString, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2};
use trc::{AuthEvent, SmtpEvent};

use crate::core::Session;

pub struct SaslToken {
    mechanism: u64,
    credentials: Credentials<String>,
}

impl SaslToken {
    pub fn from_mechanism(mechanism: u64) -> Option<SaslToken> {
        match mechanism {
            AUTH_PLAIN | AUTH_LOGIN => SaslToken {
                mechanism,
                credentials: Credentials::Plain {
                    username: String::new(),
                    secret: String::new(),
                },
            }
            .into(),
            AUTH_OAUTHBEARER => SaslToken {
                mechanism,
                credentials: Credentials::OAuthBearer {
                    token: String::new(),
                },
            }
            .into(),
            AUTH_XOAUTH2 => SaslToken {
                mechanism,
                credentials: Credentials::XOauth2 {
                    username: String::new(),
                    secret: String::new(),
                },
            }
            .into(),
            _ => None,
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn handle_sasl_response(
        &mut self,
        token: &mut SaslToken,
        response: &[u8],
    ) -> Result<bool, ()> {
        if response.is_empty() {
            match (token.mechanism, &token.credentials) {
                (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER, _) => {
                    self.write(b"334 Go ahead.\r\n").await?;
                    return Ok(true);
                }
                (AUTH_LOGIN, Credentials::Plain { username, secret }) => {
                    if username.is_empty() && secret.is_empty() {
                        self.write(b"334 VXNlcm5hbWU6\r\n").await?;
                        return Ok(true);
                    }
                }
                _ => (),
            }
        } else if let Some(response) = base64_decode(response) {
            match (token.mechanism, &mut token.credentials) {
                (AUTH_PLAIN, Credentials::Plain { username, secret }) => {
                    let mut b_username = Vec::new();
                    let mut b_secret = Vec::new();
                    let mut arg_num = 0;
                    for ch in response {
                        if ch != 0 {
                            if arg_num == 1 {
                                b_username.push(ch);
                            } else if arg_num == 2 {
                                b_secret.push(ch);
                            }
                        } else {
                            arg_num += 1;
                        }
                    }
                    match (String::from_utf8(b_username), String::from_utf8(b_secret)) {
                        (Ok(s_username), Ok(s_secret)) if !s_username.is_empty() => {
                            *username = s_username;
                            *secret = s_secret;
                            return self
                                .authenticate(std::mem::take(&mut token.credentials))
                                .await;
                        }
                        _ => (),
                    }
                }
                (AUTH_LOGIN, Credentials::Plain { username, secret }) => {
                    return if username.is_empty() {
                        *username = response.into_string();
                        self.write(b"334 UGFzc3dvcmQ6\r\n").await?;
                        Ok(true)
                    } else {
                        *secret = response.into_string();
                        self.authenticate(std::mem::take(&mut token.credentials))
                            .await
                    };
                }
                (AUTH_OAUTHBEARER, Credentials::OAuthBearer { token: token_ }) => {
                    let response = response.into_string();
                    if response.contains("auth=") {
                        *token_ = response;
                        return self
                            .authenticate(std::mem::take(&mut token.credentials))
                            .await;
                    }
                }
                (AUTH_XOAUTH2, Credentials::XOauth2 { username, secret }) => {
                    let mut b_username = Vec::new();
                    let mut b_secret = Vec::new();
                    let mut arg_num = 0;
                    let mut in_arg = false;

                    for ch in response {
                        if in_arg {
                            if ch != 1 {
                                if arg_num == 1 {
                                    b_username.push(ch);
                                } else if arg_num == 2 {
                                    b_secret.push(ch);
                                }
                            } else {
                                in_arg = false;
                            }
                        } else if ch == b'=' {
                            arg_num += 1;
                            in_arg = true;
                        }
                    }
                    match (String::from_utf8(b_username), String::from_utf8(b_secret)) {
                        (Ok(s_username), Ok(s_secret)) if !s_username.is_empty() => {
                            *username = s_username;
                            *secret = s_secret;
                            return self
                                .authenticate(std::mem::take(&mut token.credentials))
                                .await;
                        }
                        _ => (),
                    }
                }

                _ => (),
            }
        }

        self.auth_error(b"500 5.5.6 Invalid challenge.\r\n").await
    }

    pub async fn authenticate(&mut self, credentials: Credentials<String>) -> Result<bool, ()> {
        if let Some(directory) = &self.params.auth_directory {
            let authenticated_as = match &credentials {
                Credentials::Plain { username, .. }
                | Credentials::XOauth2 { username, .. }
                | Credentials::OAuthBearer { token: username } => username.to_string(),
            };
            match self
                .core
                .core
                .authenticate(
                    directory,
                    self.data.session_id,
                    &credentials,
                    self.data.remote_ip,
                    false,
                )
                .await
            {
                Ok(principal) => {
                    self.data.authenticated_as = authenticated_as.to_lowercase();
                    self.data.authenticated_emails = principal
                        .emails
                        .into_iter()
                        .map(|e| e.trim().to_lowercase())
                        .collect();
                    self.eval_post_auth_params().await;
                    self.write(b"235 2.7.0 Authentication succeeded.\r\n")
                        .await?;
                    return Ok(false);
                }
                Err(err) => {
                    let reason = *err.as_ref();

                    trc::error!(err.span_id(self.data.session_id));

                    match reason {
                        trc::EventType::Auth(trc::AuthEvent::Failed) => {
                            return self
                                .auth_error(b"535 5.7.8 Authentication credentials invalid.\r\n")
                                .await;
                        }
                        trc::EventType::Auth(trc::AuthEvent::MissingTotp) => {
                            return self
                            .auth_error(
                                b"334 5.7.8 Missing TOTP token, try with 'secret$totp_code'.\r\n",
                            )
                            .await;
                        }
                        trc::EventType::Security(_) => {
                            return Err(());
                        }
                        _ => (),
                    }
                }
            }
        } else {
            trc::event!(
                Smtp(SmtpEvent::MissingAuthDirectory),
                SpanId = self.data.session_id,
            );
        }
        self.write(b"454 4.7.0 Temporary authentication failure\r\n")
            .await?;

        Ok(false)
    }

    pub async fn auth_error(&mut self, response: &[u8]) -> Result<bool, ()> {
        tokio::time::sleep(self.params.auth_errors_wait).await;
        self.data.auth_errors += 1;
        self.write(response).await?;
        if self.data.auth_errors < self.params.auth_errors_max {
            Ok(false)
        } else {
            trc::event!(
                Auth(AuthEvent::TooManyAttempts),
                SpanId = self.data.session_id,
            );

            self.write(b"421 4.3.0 Too many authentication errors, disconnecting.\r\n")
                .await?;
            Err(())
        }
    }
}
