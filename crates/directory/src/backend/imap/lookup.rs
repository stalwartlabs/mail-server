/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::Credentials;
use smtp_proto::{AUTH_CRAM_MD5, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2};

use crate::{IntoError, Principal, QueryBy};

use super::{ImapDirectory, ImapError};

impl ImapDirectory {
    pub async fn query(&self, query: QueryBy<'_>) -> trc::Result<Option<Principal<u32>>> {
        if let QueryBy::Credentials(credentials) = query {
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|err| err.into_error().caused_by(trc::location!()))?;
            let mechanism = match credentials {
                Credentials::Plain { .. }
                    if (client.mechanisms & (AUTH_PLAIN | AUTH_LOGIN | AUTH_CRAM_MD5)) != 0 =>
                {
                    if client.mechanisms & AUTH_CRAM_MD5 != 0 {
                        AUTH_CRAM_MD5
                    } else if client.mechanisms & AUTH_PLAIN != 0 {
                        AUTH_PLAIN
                    } else {
                        AUTH_LOGIN
                    }
                }
                Credentials::OAuthBearer { .. } if client.mechanisms & AUTH_OAUTHBEARER != 0 => {
                    AUTH_OAUTHBEARER
                }
                Credentials::XOauth2 { .. } if client.mechanisms & AUTH_XOAUTH2 != 0 => {
                    AUTH_XOAUTH2
                }
                _ => {
                    trc::bail!(trc::StoreEvent::NotSupported.ctx(
                        trc::Key::Reason,
                        "IMAP server does not offer any supported auth mechanisms."
                    ));
                }
            };

            match client.authenticate(mechanism, credentials).await {
                Ok(_) => {
                    client.is_valid = false;
                    Ok(Some(Principal::default()))
                }
                Err(err) => match &err {
                    ImapError::AuthenticationFailed => Ok(None),
                    _ => Err(err.into_error()),
                },
            }
        } else {
            Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
        }
    }

    pub async fn email_to_ids(&self, _address: &str) -> trc::Result<Vec<u32>> {
        Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
    }

    pub async fn rcpt(&self, _address: &str) -> trc::Result<bool> {
        Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
    }

    pub async fn vrfy(&self, _address: &str) -> trc::Result<Vec<String>> {
        Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
    }

    pub async fn expn(&self, _address: &str) -> trc::Result<Vec<String>> {
        Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()))
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}
