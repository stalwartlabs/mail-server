/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use common::{listener::SessionStream, AuthResult};
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use smtp_proto::{IntoString, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2};

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
                    &self.core.inner.ipc,
                    &credentials,
                    self.data.remote_ip,
                    self.instance.protocol,
                    false,
                )
                .await
            {
                Ok(AuthResult::Success(principal)) => {
                    tracing::debug!(
                        parent: &self.span,
                        context = "auth",
                        event = "authenticate",
                        result = "success"
                    );

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
                Ok(AuthResult::Failure) => {
                    tracing::debug!(
                        parent: &self.span,
                        context = "auth",
                        event = "authenticate",
                        result = "failed"
                    );

                    return self
                        .auth_error(b"535 5.7.8 Authentication credentials invalid.\r\n")
                        .await;
                }
                Ok(AuthResult::Banned) => {
                    tracing::debug!(
                        parent: &self.span,
                        context = "auth",
                        event = "authenticate",
                        result = "banned"
                    );

                    return Err(());
                }
                _ => (),
            }
        } else {
            tracing::warn!(
                parent: &self.span,
                context = "auth",
                event = "error",
                "No lookup list configured for authentication."
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
            self.write(b"421 4.3.0 Too many authentication errors, disconnecting.\r\n")
                .await?;
            tracing::debug!(
                parent: &self.span,
                event = "disconnect",
                reason = "auth-errors",
                "Too many authentication errors."
            );
            Err(())
        }
    }
}
