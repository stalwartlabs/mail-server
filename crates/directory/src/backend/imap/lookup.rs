/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::Credentials;
use smtp_proto::{AUTH_CRAM_MD5, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2};

use crate::{DirectoryError, Principal, QueryBy};

use super::{ImapDirectory, ImapError};

impl ImapDirectory {
    pub async fn query(&self, query: QueryBy<'_>) -> crate::Result<Option<Principal<u32>>> {
        if let QueryBy::Credentials(credentials) = query {
            let mut client = self.pool.get().await?;
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
                    tracing::warn!(
                        context = "remote",
                        event = "error",
                        protocol = "imap",
                        "IMAP server does not offer any supported auth mechanisms.",
                    );
                    return Ok(None);
                }
            };

            match client.authenticate(mechanism, credentials).await {
                Ok(_) => {
                    client.is_valid = false;
                    Ok(Some(Principal::default()))
                }
                Err(err) => match &err {
                    ImapError::AuthenticationFailed => Ok(None),
                    _ => Err(err.into()),
                },
            }
        } else {
            Err(DirectoryError::unsupported("imap", "query"))
        }
    }

    pub async fn email_to_ids(&self, _address: &str) -> crate::Result<Vec<u32>> {
        Err(DirectoryError::unsupported("imap", "email_to_ids"))
    }

    pub async fn rcpt(&self, _address: &str) -> crate::Result<bool> {
        Err(DirectoryError::unsupported("imap", "rcpt"))
    }

    pub async fn vrfy(&self, _address: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("imap", "vrfy"))
    }

    pub async fn expn(&self, _address: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("imap", "expn"))
    }

    pub async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}
