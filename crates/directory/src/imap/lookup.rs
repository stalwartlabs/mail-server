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

use mail_send::Credentials;
use smtp_proto::{AUTH_CRAM_MD5, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2};

use crate::{Directory, DirectoryError, Principal};

use super::{ImapDirectory, ImapError};

#[async_trait::async_trait]
impl Directory for ImapDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
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
            Credentials::XOauth2 { .. } if client.mechanisms & AUTH_XOAUTH2 != 0 => AUTH_XOAUTH2,
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
    }

    async fn principal(&self, _name: &str) -> crate::Result<Option<Principal>> {
        Err(DirectoryError::unsupported("imap", "principal"))
    }

    async fn emails_by_name(&self, _: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("imap", "emails_by_name"))
    }

    async fn names_by_email(&self, _address: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("imap", "names_by_email"))
    }

    async fn rcpt(&self, _address: &str) -> crate::Result<bool> {
        Err(DirectoryError::unsupported("imap", "rcpt"))
    }

    async fn vrfy(&self, _address: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("imap", "vrfy"))
    }

    async fn expn(&self, _address: &str) -> crate::Result<Vec<String>> {
        Err(DirectoryError::unsupported("imap", "expn"))
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}
