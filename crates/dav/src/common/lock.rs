/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::KV_LOCK_DAV;
use common::{Server, auth::AccessToken};
use dav_proto::schema::property::{ActiveLock, LockScope, WebDavProperty};
use dav_proto::schema::request::{DavPropertyValue, DeadProperty};
use dav_proto::schema::response::{BaseCondition, List, PropResponse};
use dav_proto::{Condition, Depth, Timeout};
use dav_proto::{RequestHeaders, schema::request::LockInfo};

use groupware::cache::GroupwareCache;
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use std::collections::HashMap;
use store::dispatch::lookup::KeyValue;
use store::write::serialize::rkyv_deserialize;
use store::write::{AlignedBytes, Archive, Archiver, now};
use store::{Serialize, U32_LEN};
use trc::AddContext;

use super::ETag;
use super::uri::{DavUriResource, OwnedUri, UriResource, Urn};
use crate::{DavError, DavErrorCondition, DavMethod};

#[derive(Debug, Default, Clone)]
pub struct ResourceState<'x> {
    pub account_id: u32,
    pub collection: Collection,
    pub document_id: Option<u32>,
    pub etag: Option<String>,
    pub lock_tokens: Vec<String>,
    pub sync_token: Option<String>,
    pub path: &'x str,
}

#[derive(Debug, Default, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct LockData {
    locks: HashMap<String, LockItems>,
}

#[derive(Debug, Default, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[repr(transparent)]
pub(crate) struct LockItems(Vec<LockItem>);

#[derive(Debug, Default, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct LockItem {
    lock_id: u64,
    owner: u32,
    expires: u64,
    depth_infinity: bool,
    exclusive: bool,
    owner_dav: Option<DeadProperty>,
}

struct LockCache<'x> {
    account_id: u32,
    collection: Collection,
    lock_archive: LockArchive<'x>,
}

enum LockArchive<'x> {
    Unarchived(&'x ArchivedLockData),
    Archived(Archive<AlignedBytes>),
}

#[derive(Default)]
pub(crate) struct LockCaches<'x> {
    caches: Vec<LockCache<'x>>,
}

pub(crate) trait LockRequestHandler: Sync + Send {
    fn handle_lock_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        lock_info: LockRequest,
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

pub(crate) enum LockRequest {
    Lock(LockInfo),
    Unlock,
    Refresh,
}

impl LockRequestHandler for Server {
    async fn handle_lock_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        lock_info: LockRequest,
    ) -> crate::Result<HttpResponse> {
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let resource_hash = resource.lock_key();
        let resource_path = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;
        let account_id = resource.account_id;
        if !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let resources = vec![ResourceState {
            account_id,
            collection: resource.collection,
            path: resource_path,
            ..Default::default()
        }];

        let mut base_path = None;
        let is_lock_request = !matches!(lock_info, LockRequest::Unlock);
        let if_lock_token = headers
            .if_
            .iter()
            .flat_map(|if_| if_.list.iter())
            .find_map(|cond| {
                if let Condition::StateToken { token, .. } = cond {
                    Urn::parse(token).and_then(|u| u.try_unwrap_lock())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let mut lock_data = if let Some(lock_data) = self
            .in_memory_store()
            .key_get::<Archive<AlignedBytes>>(resource_hash.as_slice())
            .await
            .caused_by(trc::location!())?
        {
            let lock_data = lock_data
                .unarchive::<LockData>()
                .caused_by(trc::location!())?;

            self.validate_headers(
                access_token,
                headers,
                resources,
                LockCaches::new_shared(account_id, resource.collection, lock_data),
                if is_lock_request {
                    DavMethod::LOCK
                } else {
                    DavMethod::UNLOCK
                },
            )
            .await?;

            if let LockRequest::Lock(lock_info) = &lock_info {
                let mut failed_locks = Vec::new();
                let is_exclusive = matches!(lock_info.lock_scope, LockScope::Exclusive);
                let is_infinity = matches!(headers.depth, Depth::Infinity);

                for (lock_path, lock_item) in lock_data.find_locks(resource_path, true) {
                    if if_lock_token != lock_item.lock_id
                        && (lock_item.exclusive || is_exclusive)
                        && (lock_path.len() == resource_path.len()
                            || lock_item.depth_infinity && resource_path.len() > lock_path.len()
                            || is_infinity && lock_path.len() > resource_path.len())
                    {
                        let base_path =
                            base_path.get_or_insert_with(|| headers.base_uri().unwrap_or_default());
                        failed_locks.push(format!("{base_path}/{lock_path}").into());
                    }
                }

                if !failed_locks.is_empty() {
                    return Err(DavErrorCondition::new(
                        StatusCode::LOCKED,
                        BaseCondition::LockTokenSubmitted(List(failed_locks)),
                    )
                    .into());
                }

                // Validate lock_info
                if lock_info.owner.as_ref().is_some_and(|o| {
                    o.size() > self.core.groupware.dead_property_size.unwrap_or(512)
                }) {
                    return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
                }

                if self.core.groupware.max_locks_per_user > 0
                    && lock_data
                        .locks
                        .values()
                        .flat_map(|locks| {
                            locks
                                .0
                                .iter()
                                .filter(|lock| lock.owner == access_token.primary_id)
                        })
                        .count()
                        >= self.core.groupware.max_locks_per_user
                {
                    return Err(DavError::Code(StatusCode::TOO_MANY_REQUESTS));
                }
            }

            rkyv_deserialize(lock_data).caused_by(trc::location!())?
        } else if is_lock_request {
            self.validate_headers(
                access_token,
                headers,
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
        let response = if is_lock_request {
            let timeout = if let Timeout::Second(seconds) = headers.timeout {
                std::cmp::min(seconds, self.core.groupware.max_lock_timeout)
            } else {
                self.core.groupware.max_lock_timeout
            };
            let expires = now + timeout;

            let lock_item = if if_lock_token > 0 {
                if let Some(lock_item) = lock_data
                    .locks
                    .values_mut()
                    .flat_map(|locks| locks.0.iter_mut())
                    .find(|lock| lock.lock_id == if_lock_token)
                {
                    lock_item
                } else {
                    return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
                }
            } else {
                let locks = lock_data
                    .locks
                    .entry(resource_path.to_string())
                    .or_insert_with(Default::default);
                locks.0.push(LockItem::default());
                locks.0.last_mut().unwrap()
            };

            lock_item.expires = expires;
            if let LockRequest::Lock(lock_info) = lock_info {
                // Validate lock_info
                if lock_info.owner.as_ref().is_some_and(|o| {
                    o.size() > self.core.groupware.dead_property_size.unwrap_or(512)
                }) {
                    return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
                }

                lock_item.lock_id = store::rand::random::<u64>() ^ expires;
                lock_item.owner = access_token.primary_id;
                lock_item.depth_infinity = matches!(headers.depth, Depth::Infinity);
                lock_item.owner_dav = lock_info.owner;
                lock_item.exclusive = matches!(lock_info.lock_scope, LockScope::Exclusive);
            }

            let base_path = base_path.get_or_insert_with(|| headers.base_uri().unwrap_or_default());
            let active_lock = lock_item.to_active_lock(format!("{base_path}/{resource_path}"));

            HttpResponse::new(if if_lock_token == 0 {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            })
            .with_lock_token(&active_lock.lock_token.as_ref().unwrap().0)
            .with_xml_body(
                PropResponse::new(vec![DavPropertyValue::new(
                    WebDavProperty::LockDiscovery,
                    vec![active_lock],
                )])
                .to_string(),
            )
        } else {
            let lock_id = headers
                .lock_token
                .and_then(Urn::parse)
                .and_then(|urn| urn.try_unwrap_lock())
                .ok_or(DavError::Code(StatusCode::BAD_REQUEST))?;

            if lock_data.remove_lock(lock_id) {
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
        let max_expire = lock_data.remove_expired();
        if max_expire > 0 {
            self.in_memory_store()
                .key_set(
                    KeyValue::new(
                        resource_hash,
                        Archiver::new(lock_data)
                            .untrusted()
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
                if headers.overwrite_fail
                    && resources.last().is_some_and(|r| {
                        r.etag.is_some() || r.document_id.is_some_and(|id| id != u32::MAX)
                    })
                {
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

        // Validate locks for write operations
        let mut lock_response = Ok(());
        if !matches!(
            method,
            DavMethod::GET | DavMethod::HEAD | DavMethod::LOCK | DavMethod::UNLOCK
        ) {
            let mut base_path = None;

            'outer: for (pos, resource) in resources.iter().enumerate() {
                if pos == 0 && matches!(method, DavMethod::COPY) {
                    continue;
                }

                if let Some(idx) = locks.find_cache_pos(self, resource).await? {
                    let mut failed_locks = Vec::new();

                    for (lock_path, lock_item) in locks.find_locks_by_pos(idx, resource, true)? {
                        let lock_token = lock_item.urn().to_string();
                        if headers.if_.iter().any(|if_| {
                            if_.resource
                                .is_none_or(|r| {
                                    r.trim_end_matches('/').ends_with(lock_path)})
                                && if_.list.iter().any(|cond| matches!(cond, Condition::StateToken { token, .. } if token == &lock_token))
                        }) {
                            break 'outer;
                        } else {
                            let base_path = base_path.get_or_insert_with(|| {
                                headers.base_uri()
                                    .unwrap_or_default()
                            });
                            failed_locks.push(format!("{base_path}/{lock_path}").into());
                        }
                    }

                    if !failed_locks.is_empty() {
                        lock_response = Err(DavErrorCondition::new(
                            StatusCode::LOCKED,
                            BaseCondition::LockTokenSubmitted(List(failed_locks)),
                        )
                        .into());
                        break;
                    }
                }
            }
        }

        // There are no If headers, so we can return early
        if no_if_headers {
            return lock_response;
        }

        let mut resource_not_found = ResourceState {
            account_id: u32::MAX,
            collection: Collection::None,
            path: "",
            ..Default::default()
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
                        let path = r.resource?;

                        Some(ResourceState {
                            account_id: r.account_id?,
                            collection: if !matches!(r.collection, Collection::FileNode)
                                && path.contains('/')
                            {
                                r.collection.child_collection().unwrap_or(r.collection)
                            } else {
                                r.collection
                            },
                            path,
                            ..Default::default()
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
                && (resource_state.etag.is_none()
                    || resource_state.lock_tokens.is_empty()
                    || resource_state.sync_token.is_none())
            {
                let mut needs_lock_token = false;
                let mut needs_sync_token = false;
                let mut needs_etag = false;

                for cond in &if_.list {
                    match cond {
                        Condition::StateToken { token, .. } => {
                            if token.starts_with("urn:stalwart:davsync:") {
                                needs_sync_token = true;
                            } else {
                                needs_lock_token = true;
                            }
                        }
                        Condition::ETag { .. } | Condition::Exists { .. } => {
                            needs_etag = true;
                        }
                    }
                }

                // Fetch eTag
                if needs_etag && resource_state.etag.is_none() {
                    if resource_state.document_id.is_none() {
                        resource_state.document_id = self
                            .map_uri_resource(
                                access_token,
                                UriResource {
                                    collection: resource_state.collection,
                                    account_id: resource_state.account_id,
                                    resource: resource_state.path.into(),
                                },
                            )
                            .await
                            .caused_by(trc::location!())?
                            .map(|uri| uri.resource)
                            .unwrap_or(u32::MAX)
                            .into();
                    }

                    if let Some(document_id) =
                        resource_state.document_id.filter(|&id| id != u32::MAX)
                    {
                        if let Some(archive) = self
                            .get_archive(
                                resource_state.account_id,
                                resource_state.collection,
                                document_id,
                            )
                            .await
                            .caused_by(trc::location!())?
                        {
                            resource_state.etag = archive.etag().into();
                        }
                    }
                }

                // Fetch lock token
                if needs_lock_token && resource_state.lock_tokens.is_empty() {
                    if let Some(idx) = locks.find_cache_pos(self, resource_state).await? {
                        let found_locks = locks
                            .find_locks_by_pos(idx, resource_state, false)?
                            .iter()
                            .map(|(_, lock)| lock.urn().to_string())
                            .collect::<Vec<_>>();
                        resource_state.lock_tokens = found_locks;
                    }
                }

                // Fetch sync token
                if needs_sync_token && resource_state.sync_token.is_none() {
                    let id = self
                        .fetch_dav_resources(
                            access_token,
                            resource_state.account_id,
                            resource_state.collection.into(),
                        )
                        .await
                        .caused_by(trc::location!())?
                        .highest_change_id;
                    resource_state.sync_token = Some(Urn::Sync { id, seq: 0 }.to_string());
                }
            }

            for cond in &if_.list {
                match cond {
                    Condition::StateToken { is_not, token } => {
                        if let Some(token) = Urn::try_extract_sync_id(token) {
                            if !((resource_state
                                .sync_token
                                .as_deref()
                                .and_then(Urn::try_extract_sync_id)
                                .is_some_and(|sync_token| sync_token == token))
                                ^ is_not)
                            {
                                continue 'outer;
                            }
                        } else if !((resource_state.lock_tokens.iter().any(|t| t == token))
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

            return lock_response;
        }

        Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
    }
}

impl LockData {
    pub fn remove_lock(&mut self, lock_id: u64) -> bool {
        for (lock_path, lock_items) in self.locks.iter_mut() {
            for (idx, lock_item) in lock_items.0.iter().enumerate() {
                if lock_item.lock_id == lock_id {
                    lock_items.0.swap_remove(idx);
                    if lock_items.0.is_empty() {
                        let lock_path = lock_path.clone();
                        self.locks.remove(&lock_path);
                    }
                    return true;
                }
            }
        }

        false
    }

    pub fn remove_expired(&mut self) -> u64 {
        let mut max_expire = 0;
        let now = now();

        self.locks.retain(|_, locks| {
            locks.0.retain(|lock| {
                if lock.expires > now {
                    max_expire = std::cmp::max(max_expire, lock.expires);
                    true
                } else {
                    false
                }
            });

            !locks.0.is_empty()
        });

        max_expire
    }
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
                && resource_state.collection.main_collection() == cache.collection.main_collection()
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

    fn find_locks_by_pos(
        &'x self,
        pos: usize,
        resource_state: &'x ResourceState<'_>,
        include_children: bool,
    ) -> trc::Result<Vec<(&'x str, &'x ArchivedLockItem)>> {
        self.caches[pos]
            .lock_archive
            .unarchive()
            .map(|l| l.find_locks(resource_state.path, include_children))
    }

    async fn insert_lock_data(
        &mut self,
        server: &Server,
        resource_state: &ResourceState<'_>,
    ) -> trc::Result<bool> {
        if let Some(lock_archive) = server
            .in_memory_store()
            .key_get::<Archive<AlignedBytes>>(resource_state.lock_key().as_slice())
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
        .with_lock_token(self.urn().to_string())
    }

    pub fn urn(&self) -> Urn {
        Urn::Lock(self.lock_id)
    }
}

impl ArchivedLockData {
    pub fn find_locks<'x: 'y, 'y>(
        &'x self,
        resource: &'y str,
        include_children: bool,
    ) -> Vec<(&'y str, &'x ArchivedLockItem)> {
        let now = now();
        let mut resource_part = resource;
        let mut found_locks = Vec::new();

        loop {
            if let Some(locks) = self.locks.get(resource_part) {
                found_locks.extend(
                    locks
                        .0
                        .iter()
                        .filter(|lock| {
                            lock.expires > now && (resource == resource_part || lock.depth_infinity)
                        })
                        .map(|lock| (resource_part, lock)),
                );
            }

            if let Some((resource_part_, _)) = resource_part.rsplit_once('/') {
                resource_part = resource_part_;
            } else {
                break;
            }
        }

        if include_children {
            let prefix = format!("{}/", resource);
            for (resource_part, locks) in self.locks.iter() {
                if resource_part.starts_with(&prefix) {
                    found_locks.extend(
                        locks
                            .0
                            .iter()
                            .filter(|lock| lock.expires > now)
                            .map(|lock| (resource_part.as_str(), lock)),
                    );
                }
            }
        }

        found_locks
    }
}

impl ArchivedLockItem {
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
        .with_owner_opt(self.owner_dav.as_ref().map(Into::into))
        .with_timeout(u64::from(self.expires).saturating_sub(now()))
        .with_lock_token(self.urn().to_string())
    }

    pub fn urn(&self) -> Urn {
        Urn::Lock(self.lock_id.into())
    }
}

impl OwnedUri<'_> {
    pub fn lock_key(&self) -> Vec<u8> {
        build_lock_key(self.account_id, self.collection.main_collection())
    }
}

impl ResourceState<'_> {
    pub fn lock_key(&self) -> Vec<u8> {
        build_lock_key(self.account_id, self.collection.main_collection())
    }
}

pub(crate) fn build_lock_key(account_id: u32, collection: Collection) -> Vec<u8> {
    let mut result = Vec::with_capacity(U32_LEN + 2);
    result.push(KV_LOCK_DAV);
    result.extend_from_slice(account_id.to_be_bytes().as_slice());
    result.push(u8::from(collection));
    result
}

impl PartialEq for ResourceState<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            && self.collection == other.collection
            && self.document_id == other.document_id
    }
}

impl Eq for ResourceState<'_> {}
