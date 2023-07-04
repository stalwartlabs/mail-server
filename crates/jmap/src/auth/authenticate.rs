/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Instant,
};

use hyper::header;
use jmap_proto::{
    error::{method::MethodError, request::RequestError},
    types::collection::Collection,
};
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use store::{
    write::{key::KeySerializer, BatchBuilder, Operation, ValueClass},
    CustomValueKey, Serialize,
};
use utils::{listener::limiter::InFlight, map::ttl_dashmap::TtlMap};

use crate::{JMAP, SUPERUSER_ID};

use super::{rate_limit::RemoteAddress, AccessToken};

impl JMAP {
    pub async fn authenticate_headers(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
        remote_ip: IpAddr,
    ) -> Result<Option<(InFlight, Arc<AccessToken>)>, RequestError> {
        if let Some((mechanism, token)) = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' ').map(|(l, t)| (l, t.trim().to_string())))
        {
            let session = if let Some(account_id) = self.sessions.get_with_ttl(&token) {
                self.get_cached_access_token(account_id).await
            } else {
                let addr = self.build_remote_addr(req, remote_ip);
                if mechanism.eq_ignore_ascii_case("basic") {
                    // Enforce rate limit for authentication requests
                    self.is_auth_allowed(addr)?;

                    // Decode the base64 encoded credentials
                    if let Some((account, secret)) = base64_decode(token.as_bytes())
                        .and_then(|token| String::from_utf8(token).ok())
                        .and_then(|token| {
                            token.split_once(':').map(|(login, secret)| {
                                (login.trim().to_lowercase(), secret.to_string())
                            })
                        })
                    {
                        self.authenticate_plain(&account, &secret).await
                    } else {
                        tracing::debug!(
                            context = "authenticate_headers",
                            token = token,
                            "Failed to decode Basic auth request.",
                        );
                        None
                    }
                } else if mechanism.eq_ignore_ascii_case("bearer") {
                    // Enforce anonymous rate limit for bearer auth requests
                    self.is_anonymous_allowed(addr)?;

                    match self.validate_access_token("access_token", &token).await {
                        Ok((account_id, _, _)) => self.get_access_token(account_id).await,
                        Err(err) => {
                            tracing::debug!(
                                context = "authenticate_headers",
                                err = err,
                                "Failed to validate access token."
                            );
                            None
                        }
                    }
                } else {
                    // Enforce anonymous rate limit
                    self.is_anonymous_allowed(addr)?;
                    None
                }
                .map(|access_token| {
                    let access_token = Arc::new(access_token);
                    self.cache_session(token, &access_token);
                    self.cache_access_token(access_token.clone());
                    access_token
                })
            };

            if let Some(session) = session {
                // Enforce authenticated rate limit
                Ok(Some((self.is_account_allowed(&session)?, session)))
            } else {
                Ok(None)
            }
        } else {
            // Enforce anonymous rate limit
            self.is_anonymous_allowed(self.build_remote_addr(req, remote_ip))?;

            Ok(None)
        }
    }

    pub fn cache_session(&self, session_id: String, access_token: &AccessToken) {
        self.sessions.insert_with_ttl(
            session_id,
            access_token.primary_id(),
            Instant::now() + self.config.session_cache_ttl,
        );
    }

    pub fn cache_access_token(&self, access_token: Arc<AccessToken>) {
        self.access_tokens.insert_with_ttl(
            access_token.primary_id(),
            access_token,
            Instant::now() + self.config.session_cache_ttl,
        );
    }

    pub async fn get_cached_access_token(&self, primary_id: u32) -> Option<Arc<AccessToken>> {
        if let Some(access_token) = self.access_tokens.get_with_ttl(&primary_id) {
            access_token.into()
        } else {
            // Refresh ACL token
            self.get_access_token(primary_id).await.map(|access_token| {
                let access_token = Arc::new(access_token);
                self.cache_access_token(access_token.clone());
                access_token
            })
        }
    }

    pub async fn get_account_id(&self, name: &str) -> Result<u32, MethodError> {
        let mut try_count = 0;

        loop {
            // Try to obtain ID
            match self
                .store
                .get_value::<u32>(CustomValueKey {
                    value: KeySerializer::new(name.len() + std::mem::size_of::<u32>() + 1)
                        .write(u32::MAX)
                        .write(0u8)
                        .write(name)
                        .finalize(),
                })
                .await
            {
                Ok(Some(id)) => return Ok(id),
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(event = "error",
                            context = "store",
                            account_name = name,
                            error = ?err,
                            "Failed to retrieve account id");
                    return Err(MethodError::ServerPartialFail);
                }
            }

            // Assign new ID
            let account_id = self
                .assign_document_id(u32::MAX, Collection::Principal)
                .await?;

            // Serialize key
            let key = KeySerializer::new(name.len() + std::mem::size_of::<u32>() + 1)
                .write(u32::MAX)
                .write(0u8)
                .write(name)
                .finalize();

            // Write account ID
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .create_document(account_id)
                .assert_value(ValueClass::Custom { bytes: key.clone() }, ())
                .op(Operation::Value {
                    class: ValueClass::Custom { bytes: key },
                    set: account_id.serialize().into(),
                })
                .op(Operation::Value {
                    class: ValueClass::Custom {
                        bytes: KeySerializer::new(std::mem::size_of::<u32>() * 2 + 1)
                            .write(u32::MAX)
                            .write(1u8)
                            .write(account_id)
                            .finalize(),
                    },
                    set: name.serialize().into(),
                });

            match self.store.write(batch.build()).await {
                Ok(_) => {
                    return Ok(account_id);
                }
                Err(store::Error::AssertValueFailed) if try_count < 3 => {
                    try_count += 1;
                    continue;
                }
                Err(err) => {
                    tracing::error!(event = "error",
                                        context = "store",
                                        error = ?err,
                                        "Failed to generate account id");
                    return Err(MethodError::ServerPartialFail);
                }
            }
        }
    }

    pub async fn map_member_of(&self, names: Vec<String>) -> Result<Vec<u32>, MethodError> {
        let mut ids = Vec::with_capacity(names.len());
        for name in names {
            if !name.eq_ignore_ascii_case(&self.config.superusers_group_name) {
                ids.push(self.get_account_id(&name).await?);
            } else {
                ids.push(SUPERUSER_ID);
            }
        }
        Ok(ids)
    }

    pub async fn get_account_name(&self, account_id: u32) -> Result<Option<String>, MethodError> {
        self.store
            .get_value::<String>(CustomValueKey {
                value: KeySerializer::new(std::mem::size_of::<u32>() * 2 + 1)
                    .write(u32::MAX)
                    .write(1u8)
                    .write(account_id)
                    .finalize(),
            })
            .await
            .map_err(|err| {
                tracing::error!(event = "error",
                        context = "store",
                        account_id = account_id,
                        error = ?err,
                        "Failed to retrieve account name");
                MethodError::ServerPartialFail
            })
    }

    pub fn build_remote_addr(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
        remote_ip: IpAddr,
    ) -> RemoteAddress {
        if !self.config.rate_use_forwarded {
            RemoteAddress::IpAddress(remote_ip)
        } else if let Some(forwarded_for) = req
            .headers()
            .get(header::FORWARDED)
            .and_then(|h| h.to_str().ok())
        {
            RemoteAddress::IpAddressFwd(forwarded_for.trim().to_string())
        } else {
            tracing::debug!("Warning: No remote address found in request, using loopback.");
            RemoteAddress::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into())
        }
    }

    pub async fn authenticate_plain(&self, username: &str, secret: &str) -> Option<AccessToken> {
        let mut principal = self
            .directory
            .authenticate(&Credentials::Plain {
                username: username.to_string(),
                secret: secret.to_string(),
            })
            .await
            .ok()??;
        if !principal.has_name() {
            principal.name = username.to_string();
        }
        // Obtain groups
        if let (Ok(account_id), Ok(member_of)) = (
            self.get_account_id(&principal.name).await,
            self.map_member_of(std::mem::take(&mut principal.member_of))
                .await,
        ) {
            // Create access token
            self.update_access_token(
                AccessToken::new(principal, account_id).with_member_of(member_of),
            )
            .await
        } else {
            None
        }
    }

    pub async fn get_access_token(&self, account_id: u32) -> Option<AccessToken> {
        let name = self.get_account_name(account_id).await.ok()??;
        let mut principal = self.directory.principal(&name).await.ok()??;

        // Obtain groups
        if let (Ok(account_id), Ok(member_of)) = (
            self.get_account_id(&principal.name).await,
            self.map_member_of(std::mem::take(&mut principal.member_of))
                .await,
        ) {
            // Create access token
            self.update_access_token(
                AccessToken::new(principal, account_id).with_member_of(member_of),
            )
            .await
        } else {
            None
        }
    }
}
