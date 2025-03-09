/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;

use common::KV_LOCK_DAV;
use common::{Server, auth::AccessToken};
use dav_proto::schema::property::{ActiveLock, LockScope, WebDavProperty};
use dav_proto::schema::request::{DavPropertyValue, DeadProperty};
use dav_proto::schema::response::{BaseCondition, List, PropResponse};
use dav_proto::{Depth, ResourceState, Timeout};
use dav_proto::{RequestHeaders, schema::request::LockInfo};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::dispatch::lookup::KeyValue;
use store::write::serialize::rkyv_deserialize;
use store::write::{Archive, Archiver, now};
use store::{Serialize, U32_LEN};
use trc::AddContext;

use super::uri::{DavUriResource, UriResource};
use crate::{DavError, DavErrorCondition};

pub(crate) trait LockRequestHandler: Sync + Send {
    fn handle_lock_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        lock_info: Option<LockInfo>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl LockRequestHandler for Server {
    async fn handle_lock_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        lock_info: Option<LockInfo>,
    ) -> crate::Result<HttpResponse> {
        let resource = self.validate_uri(access_token, headers.uri).await?;
        let resource_hash = resource
            .lock_key()
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;
        let resource_path = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;
        if !access_token.is_member(resource.account_id.unwrap()) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let mut lock_data = if let Some(lock_data) = self
            .in_memory_store()
            .key_get::<Archive>(resource_hash.as_slice())
            .await
            .caused_by(trc::location!())?
        {
            let lock_data = lock_data
                .unarchive::<LockData>()
                .caused_by(trc::location!())?;
            if let Some((lock_path, lock_item)) = lock_data.find_lock(resource_path) {
                if !lock_item.is_lock_owner(access_token) {
                    return Err(DavErrorCondition::new(
                        StatusCode::LOCKED,
                        BaseCondition::LockTokenSubmitted(List(vec![
                            headers.format_to_base_uri(lock_path).into(),
                        ])),
                    )
                    .into());
                } else if headers.has_if()
                    && !headers.eval_if(&[ResourceState {
                        resource: None,
                        etag: String::new(),
                        state_token: lock_item.uuid(),
                    }])
                {
                    return Err(DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        BaseCondition::LockTokenMatchesRequestUri,
                    )
                    .into());
                }
            } else if lock_info.is_some() {
                if let Some((lock_path, lock_item)) = lock_data.can_lock(resource_path) {
                    if !lock_item.is_lock_owner(access_token) {
                        return Err(DavErrorCondition::new(
                            StatusCode::LOCKED,
                            BaseCondition::LockTokenSubmitted(List(vec![
                                headers.format_to_base_uri(lock_path).into(),
                            ])),
                        )
                        .into());
                    } else if headers.has_if()
                        && !headers.eval_if(&[ResourceState {
                            resource: None,
                            etag: String::new(),
                            state_token: lock_item.uuid(),
                        }])
                    {
                        return Err(DavErrorCondition::new(
                            StatusCode::PRECONDITION_FAILED,
                            BaseCondition::LockTokenMatchesRequestUri,
                        )
                        .into());
                    }
                }
            }

            rkyv_deserialize(lock_data).caused_by(trc::location!())?
        } else if lock_info.is_some() {
            LockData::default()
        } else {
            return Err(DavErrorCondition::new(
                StatusCode::CONFLICT,
                BaseCondition::LockTokenMatchesRequestUri,
            )
            .into());
        };

        let now = now();
        let response = if let Some(lock_info) = lock_info {
            let timeout = if let Timeout::Second(seconds) = headers.timeout {
                std::cmp::min(seconds, self.core.dav.max_lock_timeout)
            } else {
                self.core.dav.max_lock_timeout
            };

            let lock_item = LockItem {
                owner: access_token.primary_id,
                depth_infinity: matches!(headers.depth, Depth::Infinity),
                owner_dav: lock_info.owner,
                exclusive: matches!(lock_info.lock_scope, LockScope::Exclusive),
                lock_id: store::rand::random(),
                expires: now + timeout,
            };
            if lock_item
                .owner_dav
                .as_ref()
                .is_some_and(|o| o.size() > self.core.dav.dead_property_size.unwrap_or(512))
            {
                return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
            }
            let active_lock = lock_item.to_active_lock(headers.format_to_base_uri(resource_path));
            lock_data.locks.insert(resource_path.to_string(), lock_item);

            HttpResponse::new(StatusCode::CREATED)
                .with_lock_token(&active_lock.lock_token.as_ref().unwrap().0)
                .with_xml_body(
                    PropResponse::new(vec![DavPropertyValue::new(
                        WebDavProperty::LockDiscovery,
                        vec![active_lock],
                    )])
                    .to_string(),
                )
        } else {
            let lock_token = headers
                .lock_token
                .ok_or(DavError::Code(StatusCode::BAD_REQUEST))?;
            let mut found_path = None;
            for (lock_path, lock_item) in lock_data.locks.iter() {
                if lock_item.uuid() == lock_token {
                    if lock_item.is_lock_owner(access_token) {
                        found_path = Some(lock_path.to_string());
                        break;
                    } else {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }
                }
            }

            if let Some(found_path) = found_path {
                lock_data.locks.remove(&found_path);
                HttpResponse::new(StatusCode::NO_CONTENT)
            } else {
                return Err(DavErrorCondition::new(
                    StatusCode::CONFLICT,
                    BaseCondition::LockTokenMatchesRequestUri,
                )
                .into());
            }
        };

        // Remove expired locks
        let mut max_expire = 0;
        lock_data.locks.retain(|_, lock| {
            if lock.expires > now {
                max_expire = std::cmp::max(max_expire, lock.expires);
                true
            } else {
                false
            }
        });

        if !lock_data.locks.is_empty() {
            self.in_memory_store()
                .key_set(
                    KeyValue::new(
                        resource_hash,
                        Archiver::new(lock_data)
                            .serialize()
                            .caused_by(trc::location!())?,
                    )
                    .expires(max_expire),
                )
                .await
                .caused_by(trc::location!())?;
        } else {
            self.in_memory_store()
                .key_delete(resource_hash)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(response)
    }
}

#[derive(Debug, Default, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct LockData {
    locks: HashMap<String, LockItem>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct LockItem {
    lock_id: u64,
    owner: u32,
    expires: u64,
    depth_infinity: bool,
    exclusive: bool,
    owner_dav: Option<DeadProperty>,
}

impl LockItem {
    pub fn to_active_lock(&self, href: String) -> ActiveLock {
        ActiveLock::new(
            href,
            if self.exclusive {
                LockScope::Exclusive
            } else {
                LockScope::Shared
            },
        )
        .with_depth(if self.depth_infinity {
            Depth::Infinity
        } else {
            Depth::Zero
        })
        .with_owner_opt(self.owner_dav.clone())
        .with_timeout(self.expires.saturating_sub(now()))
        .with_lock_token(self.uuid())
    }

    pub fn uuid(&self) -> String {
        let lock_id_high = (self.lock_id >> 32) as u32;
        let lock_id_low = self.lock_id as u32;
        let expires_high = (self.expires >> 48) as u16;
        let expires_low = ((self.expires >> 16) & 0xFFFF) as u16;

        format!(
            "urn:uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:04x}{:04x}",
            lock_id_high,
            lock_id_low >> 16,
            lock_id_low & 0xFFFF,
            self.owner >> 16,
            self.owner & 0xFFFF,
            expires_high,
            expires_low
        )
    }
}

impl ArchivedLockData {
    pub fn find_lock<'x, 'y>(
        &'x self,
        resource: &'y str,
    ) -> Option<(&'y str, &'x ArchivedLockItem)> {
        let now = now();
        let mut resource_part = resource;
        loop {
            if let Some(lock) = self.locks.get(resource_part).filter(|lock| {
                lock.expires > now && (resource == resource_part || lock.depth_infinity)
            }) {
                return Some((resource_part, lock));
            } else if let Some((resource_part_, _)) = resource_part.rsplit_once('/') {
                resource_part = resource_part_;
            } else {
                return None;
            }
        }
    }

    pub fn can_lock<'x>(&'x self, resource: &'x str) -> Option<(&'x str, &'x ArchivedLockItem)> {
        if let Some(lock) = self.find_lock(resource) {
            Some(lock)
        } else {
            let now = now();
            self.locks.iter().find_map(|(resource_part, lock)| {
                if lock.depth_infinity
                    && lock.expires > now
                    && resource_part
                        .strip_prefix(resource)
                        .is_some_and(|v| v.starts_with('/'))
                {
                    Some((resource_part.as_str(), lock))
                } else {
                    None
                }
            })
        }
    }
}

impl ArchivedLockItem {
    #[inline]
    pub fn is_lock_owner(&self, access_token: &AccessToken) -> bool {
        self.owner == access_token.primary_id
    }

    pub fn uuid(&self) -> String {
        let lock_id_high = (self.lock_id >> 32) as u32;
        let lock_id_low = u64::from(self.lock_id) as u32;
        let expires_high = (self.expires >> 48) as u16;
        let expires_low = ((self.expires >> 16) & 0xFFFF) as u16;

        format!(
            "urn:uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:04x}{:04x}",
            lock_id_high,
            lock_id_low >> 16,
            lock_id_low & 0xFFFF,
            self.owner >> 16,
            self.owner & 0xFFFF,
            expires_high,
            expires_low
        )
    }
}

impl LockItem {
    #[inline]
    pub fn is_lock_owner(&self, access_token: &AccessToken) -> bool {
        self.owner == access_token.primary_id
    }
}

impl UriResource<Option<&str>> {
    pub fn lock_key(&self) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(U32_LEN + 2);
        result.push(KV_LOCK_DAV);
        result.extend_from_slice(self.account_id?.to_be_bytes().as_slice());
        result.push(u8::from(self.collection));
        Some(result)
    }
}
