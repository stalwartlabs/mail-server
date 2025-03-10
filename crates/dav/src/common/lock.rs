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
use dav_proto::{Condition, Depth, Timeout};
use dav_proto::{RequestHeaders, schema::request::LockInfo};
use groupware::file::hierarchy::FileHierarchy;
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use jmap_proto::types::property::Property;
use store::dispatch::lookup::KeyValue;
use store::write::serialize::rkyv_deserialize;
use store::write::{Archive, Archiver, now};
use store::{Serialize, U32_LEN};
use trc::AddContext;

use super::ETag;
use super::uri::{DavUriResource, UriResource};
use crate::{DavError, DavErrorCondition, DavMethod};

#[derive(Debug, Clone)]
pub struct ResourceState<'x> {
    pub account_id: u32,
    pub collection: Collection,
    pub document_id: Option<u32>,
    pub etag: Option<String>,
    pub lock_token: Option<String>,
    pub path: &'x str,
}

pub(crate) trait LockRequestHandler: Sync + Send {
    fn handle_lock_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        lock_info: Option<LockInfo>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn validate_headers(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        resources: Vec<ResourceState<'_>>,
        locks: LockCaches<'_>,
        method: DavMethod,
    ) -> impl Future<Output = crate::Result<()>> + Send;
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
        let account_id = resource.account_id.unwrap();
        if !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let resources = vec![ResourceState {
            account_id,
            collection: resource.collection,
            path: resource_path,
            document_id: None,
            etag: None,
            lock_token: None,
        }];

        let mut lock_data = if let Some(lock_data) = self
            .in_memory_store()
            .key_get::<Archive>(resource_hash.as_slice())
            .await
            .caused_by(trc::location!())?
        {
            let lock_data = lock_data
                .unarchive::<LockData>()
                .caused_by(trc::location!())?;

            self.validate_headers(
                access_token,
                &headers,
                resources,
                LockCaches::new_shared(account_id, resource.collection, lock_data),
                DavMethod::LOCK,
            )
            .await?;

            if lock_info.is_some() {
                if let Some((lock_path, lock_item)) = lock_data.can_lock(resource_path) {
                    if !lock_item.is_lock_owner(access_token) {
                        return Err(DavErrorCondition::new(
                            StatusCode::LOCKED,
                            BaseCondition::LockTokenSubmitted(List(vec![
                                headers.format_to_base_uri(lock_path).into(),
                            ])),
                        )
                        .into());
                    }
                }
            }

            rkyv_deserialize(lock_data).caused_by(trc::location!())?
        } else if lock_info.is_some() {
            self.validate_headers(
                access_token,
                &headers,
                resources,
                Default::default(),
                DavMethod::LOCK,
            )
            .await?;

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

    async fn validate_headers(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut resources: Vec<ResourceState<'_>>,
        mut locks_: LockCaches<'_>,
        method: DavMethod,
    ) -> crate::Result<()> {
        let no_if_headers = headers.if_.is_empty();
        match method {
            DavMethod::GET | DavMethod::HEAD => {
                // Return early for GET/HEAD requests without If headers
                if no_if_headers {
                    return Ok(());
                }
            }
            DavMethod::COPY
            | DavMethod::MOVE
            | DavMethod::POST
            | DavMethod::PUT
            | DavMethod::PATCH => {
                if headers.overwrite_fail && resources.last().is_some_and(|r| r.etag.is_some()) {
                    return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
                }
            }
            _ => {}
        }

        // Add lock data to the cache
        for resource in &resources {
            if locks_.is_cached(resource).is_none() {
                locks_.insert_lock_data(self, resource).await?;
            }
        }

        // Unarchive lock data
        let mut locks = locks_.to_unarchived().caused_by(trc::location!())?;

        // Validate locks
        if !matches!(method, DavMethod::GET | DavMethod::HEAD) {
            for resource in &resources {
                if let Some(idx) = locks.find_cache_pos(self, resource).await? {
                    if let Some((lock_path, lock_item)) = locks.find_lock_by_pos(idx, resource)? {
                        if !lock_item.is_lock_owner(access_token) {
                            return Err(DavErrorCondition::new(
                                StatusCode::LOCKED,
                                BaseCondition::LockTokenSubmitted(List(vec![
                                    headers.format_to_base_uri(lock_path).into(),
                                ])),
                            )
                            .into());
                        }
                    }
                }
            }
        }

        // There are no If headers, so we can return early
        if no_if_headers {
            return Ok(());
        }

        let mut resource_not_found = ResourceState {
            account_id: u32::MAX,
            collection: Collection::None,
            document_id: None,
            etag: None,
            lock_token: None,
            path: "",
        };

        'outer: for if_ in &headers.if_ {
            if if_.list.is_empty() {
                continue;
            }

            let mut resource_state = &mut resource_not_found;

            if let Some(resource) = if_.resource {
                if let Some(resource) = self
                    .validate_uri(access_token, resource)
                    .await
                    .ok()
                    .and_then(|r| {
                        Some(ResourceState {
                            account_id: r.account_id?,
                            collection: r.collection,
                            path: r.resource?,
                            document_id: None,
                            etag: None,
                            lock_token: None,
                        })
                    })
                {
                    if let Some(known_resource) = resources.iter_mut().find(|r| {
                        r.account_id == resource.account_id
                            && r.collection == resource.collection
                            && r.path == resource.path
                    }) {
                        resource_state = known_resource;
                    } else if access_token.has_access(resource.account_id, resource.collection) {
                        resources.push(resource);
                        resource_state = resources.last_mut().unwrap();
                    }
                }
            } else if let Some(resource) = resources.first_mut() {
                resource_state = resource;
            };

            // Fill missing data for resource
            if resource_state.collection != Collection::None
                && (resource_state.etag.is_none() || resource_state.lock_token.is_none())
            {
                let mut needs_token = false;
                let mut needs_etag = false;

                for cond in &if_.list {
                    match cond {
                        Condition::StateToken { .. } => {
                            needs_token = true;
                        }
                        Condition::ETag { .. } | Condition::Exists { .. } => {
                            needs_etag = true;
                        }
                    }
                }

                // Fetch eTag
                if needs_etag && resource_state.etag.is_none() {
                    if resource_state.document_id.is_none() {
                        let todo = "map cal, card";

                        resource_state.document_id = match resource_state.collection {
                            Collection::FileNode => self
                                .fetch_file_hierarchy(resource_state.account_id)
                                .await
                                .caused_by(trc::location!())?
                                .files
                                .by_name(resource_state.path)
                                .map(|f| f.document_id),
                            Collection::Calendar => todo!(),
                            Collection::CalendarEvent => todo!(),
                            Collection::AddressBook => todo!(),
                            Collection::ContactCard => todo!(),
                            _ => None,
                        }
                        .unwrap_or(u32::MAX)
                        .into();
                    }

                    if let Some(document_id) =
                        resource_state.document_id.filter(|&id| id != u32::MAX)
                    {
                        if let Some(archive) = self
                            .get_property::<Archive>(
                                resource_state.account_id,
                                resource_state.collection,
                                document_id,
                                Property::Value,
                            )
                            .await
                            .caused_by(trc::location!())?
                        {
                            resource_state.etag = archive.etag().into();
                        }
                    }
                }

                // Fetch lock token
                if needs_token && resource_state.lock_token.is_none() {
                    if let Some(idx) = locks.find_cache_pos(self, resource_state).await? {
                        if let Some((_, lock)) = locks.find_lock_by_pos(idx, resource_state)? {
                            resource_state.lock_token = Some(lock.uuid());
                        }
                    }
                }
            }

            for cond in &if_.list {
                match cond {
                    Condition::StateToken { is_not, token } => {
                        if !((resource_state
                            .lock_token
                            .as_ref()
                            .is_some_and(|lock_token| lock_token == token))
                            ^ is_not)
                        {
                            continue 'outer;
                        }
                    }
                    Condition::ETag { is_not, tag } => {
                        if !((resource_state.etag.as_ref().is_some_and(|etag| etag == tag))
                            ^ is_not)
                        {
                            continue 'outer;
                        }
                    }
                    Condition::Exists { is_not } => {
                        if !((resource_state.etag.is_some()) ^ is_not) {
                            continue 'outer;
                        }
                    }
                }
            }

            return Ok(());
        }

        Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
    }
}

struct LockCache<'x> {
    account_id: u32,
    collection: Collection,
    lock_archive: LockArchive<'x>,
}

enum LockArchive<'x> {
    Unarchived(&'x ArchivedLockData),
    Archived(Archive),
}

#[derive(Default)]
pub(crate) struct LockCaches<'x> {
    caches: Vec<LockCache<'x>>,
}

impl<'x> LockArchive<'x> {
    fn unarchive(&'x self) -> trc::Result<&'x ArchivedLockData> {
        match self {
            LockArchive::Unarchived(archived_lock_data) => Ok(archived_lock_data),
            LockArchive::Archived(archive) => {
                archive.unarchive::<LockData>().caused_by(trc::location!())
            }
        }
    }
}

impl<'x> LockCaches<'x> {
    pub(self) fn new_shared(
        account_id: u32,
        collection: Collection,
        lock_data: &'x ArchivedLockData,
    ) -> Self {
        Self {
            caches: vec![LockCache {
                account_id,
                collection,
                lock_archive: LockArchive::Unarchived(lock_data),
            }],
        }
    }

    pub fn to_unarchived(&'x self) -> trc::Result<LockCaches<'x>> {
        let caches = self
            .caches
            .iter()
            .map(|cache| {
                Ok(LockCache {
                    account_id: cache.account_id,
                    collection: cache.collection,
                    lock_archive: LockArchive::Unarchived(
                        cache.lock_archive.unarchive().caused_by(trc::location!())?,
                    ),
                })
            })
            .collect::<trc::Result<Vec<_>>>()?;

        Ok(LockCaches { caches })
    }

    #[inline]
    pub fn is_cached(&self, resource_state: &ResourceState<'_>) -> Option<usize> {
        self.caches.iter().position(|cache| {
            resource_state.account_id == cache.account_id
                && resource_state.collection == cache.collection
        })
    }

    pub async fn find_cache_pos(
        &mut self,
        server: &Server,
        resource_state: &ResourceState<'_>,
    ) -> trc::Result<Option<usize>> {
        if let Some(idx) = self.is_cached(resource_state) {
            Ok(Some(idx))
        } else if resource_state.collection != Collection::None {
            if self.insert_lock_data(server, resource_state).await? {
                Ok(Some(self.caches.len() - 1))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn find_lock_by_pos<'y>(
        &'x self,
        pos: usize,
        resource_state: &'y ResourceState<'_>,
    ) -> trc::Result<Option<(&'y str, &'x ArchivedLockItem)>> {
        self.caches[pos]
            .lock_archive
            .unarchive()
            .map(|l| l.find_lock(resource_state.path))
    }

    async fn insert_lock_data(
        &mut self,
        server: &Server,
        resource_state: &ResourceState<'_>,
    ) -> trc::Result<bool> {
        if let Some(lock_archive) = server
            .in_memory_store()
            .key_get::<Archive>(resource_state.lock_key().as_slice())
            .await
            .caused_by(trc::location!())?
        {
            self.caches.push(LockCache {
                account_id: resource_state.account_id,
                collection: resource_state.collection,
                lock_archive: LockArchive::Archived(lock_archive),
            });

            Ok(true)
        } else {
            Ok(false)
        }
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

impl ResourceState<'_> {
    pub fn lock_key(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(U32_LEN + 2);
        result.push(KV_LOCK_DAV);
        result.extend_from_slice(self.account_id.to_be_bytes().as_slice());
        result.push(u8::from(self.collection));
        result
    }
}

impl PartialEq for ResourceState<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            && self.collection == other.collection
            && self.document_id == other.document_id
    }
}

impl Eq for ResourceState<'_> {}
