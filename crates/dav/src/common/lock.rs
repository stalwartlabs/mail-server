/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::KV_LOCK_DAV;
use common::{Server, auth::AccessToken};
use dav_proto::schema::property::LockScope;
use dav_proto::schema::request::DeadProperty;
use dav_proto::{Depth, Timeout};
use dav_proto::{RequestHeaders, schema::request::LockInfo};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::dispatch::lookup::KeyValue;
use store::write::{Archive, Archiver};
use store::{Serialize, blake3};
use trc::AddContext;

use super::uri::{DavUriResource, UriResource};
use crate::DavError;

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
        if !access_token.is_member(resource.account_id.unwrap()) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let lock_data = if let Some(lock_data) = self
            .in_memory_store()
            .key_get::<Archive>(resource_hash.as_slice())
            .await
            .caused_by(trc::location!())?
        {
            let lock_data = lock_data
                .deserialize::<LockData>()
                .caused_by(trc::location!())?;
            if access_token.primary_id == lock_data.owner {
                Some(lock_data)
            } else {
                return Err(DavError::Code(StatusCode::LOCKED));
            }
        } else {
            None
        };

        if let Some(lock_info) = lock_info {
            let timeout = if let Timeout::Second(seconds) = headers.timeout {
                std::cmp::min(seconds, self.core.dav.max_lock_timeout)
            } else {
                self.core.dav.max_lock_timeout
            };

            let lock_data = if let Some(mut lock_data) = lock_data {
                lock_data.depth_infinity = matches!(headers.depth, Depth::Infinity);
                lock_data.owner_dav = lock_info.owner;
                lock_data.exclusive = matches!(lock_info.lock_scope, LockScope::Exclusive);
                lock_data
            } else {
                LockData {
                    owner: access_token.primary_id,
                    depth_infinity: matches!(headers.depth, Depth::Infinity),
                    owner_dav: lock_info.owner,
                    exclusive: matches!(lock_info.lock_scope, LockScope::Exclusive),
                }
            };
            if lock_data
                .owner_dav
                .as_ref()
                .is_some_and(|o| o.size() > self.core.dav.dead_property_size.unwrap_or(512))
            {
                return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
            }

            self.in_memory_store()
                .key_set(
                    KeyValue::new(
                        resource_hash,
                        Archiver::new(lock_data)
                            .serialize()
                            .caused_by(trc::location!())?,
                    )
                    .expires(timeout),
                )
                .await
                .caused_by(trc::location!())?;
        } else if lock_data.is_some() {
            self.in_memory_store()
                .key_delete(resource_hash.as_slice())
                .await
                .caused_by(trc::location!())?;
        }

        todo!()
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct LockData {
    owner: u32,
    depth_infinity: bool,
    exclusive: bool,
    owner_dav: Option<DeadProperty>,
}

impl UriResource<Option<&str>> {
    pub fn lock_key(&self) -> Option<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.resource?.as_bytes());
        hasher.update(self.account_id?.to_be_bytes().as_slice());
        hasher.update(u8::from(self.collection).to_be_bytes().as_slice());
        let hash = hasher.finalize();
        let mut result = Vec::with_capacity(hash.as_bytes().len() + 1);
        result.push(KV_LOCK_DAV);
        result.extend_from_slice(hash.as_bytes());
        Some(result)
    }
}
