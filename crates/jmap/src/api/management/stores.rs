/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::{
    auth::AccessToken,
    ipc::{HousekeeperEvent, PurgeType},
    manager::webadmin::Resource,
    Server,
};
use directory::{
    backend::internal::manage::{self, ManageDirectory},
    Permission,
};
use hyper::Method;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{
        http::{HttpSessionData, ToHttpResponse},
        HttpRequest, HttpResponse, JsonResponse,
    },
    services::index::Indexer,
};

use super::{decode_path_element, enterprise::undelete::UndeleteApi};
use std::future::Future;

pub trait ManageStore: Sync + Send {
    fn handle_manage_store(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn housekeeper_request(
        &self,
        event: HousekeeperEvent,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManageStore for Server {
    async fn handle_manage_store(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (
            path.get(1).copied(),
            path.get(2).copied(),
            path.get(3).copied(),
            req.method(),
        ) {
            (Some("blobs"), Some(blob_hash), _, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::BlobFetch)?;

                let blob_hash = URL_SAFE_NO_PAD
                    .decode(decode_path_element(blob_hash).as_bytes())
                    .map_err(|err| {
                        trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                            .from_base64_error(err)
                    })?;
                let contents = self
                    .core
                    .storage
                    .blob
                    .get_blob(&blob_hash, 0..usize::MAX)
                    .await?
                    .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;
                let params = UrlParams::new(req.uri().query());
                let offset = params.parse("offset").unwrap_or(0);
                let limit = params.parse("limit").unwrap_or(usize::MAX);
                let contents = if offset == 0 && limit == usize::MAX {
                    contents
                } else {
                    contents
                        .get(offset..std::cmp::min(offset + limit, contents.len()))
                        .unwrap_or_default()
                        .to_vec()
                };

                Ok(Resource::new("application/octet-stream", contents).into_http_response())
            }
            (Some("purge"), Some("blob"), _, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeBlobStore)?;

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Blobs {
                    store: self.core.storage.data.clone(),
                    blob_store: self.core.storage.blob.clone(),
                }))
                .await
            }
            (Some("purge"), Some("data"), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeDataStore)?;

                let store = if let Some(id) = id {
                    if let Some(store) = self.core.storage.stores.get(id) {
                        store.clone()
                    } else {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                } else {
                    self.core.storage.data.clone()
                };

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Data(store)))
                    .await
            }
            (Some("purge"), Some("lookup"), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeLookupStore)?;

                let store = if let Some(id) = id {
                    if let Some(store) = self.core.storage.lookups.get(id) {
                        store.clone()
                    } else {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                } else {
                    self.core.storage.lookup.clone()
                };

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Lookup(store)))
                    .await
            }
            (Some("purge"), Some("account"), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeAccount)?;

                let account_id = if let Some(id) = id {
                    self.core
                        .storage
                        .data
                        .get_principal_id(decode_path_element(id).as_ref())
                        .await?
                        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?
                        .into()
                } else {
                    None
                };

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Account(account_id)))
                    .await
            }
            (Some("reindex"), id, None, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::FtsReindex)?;

                let account_id = if let Some(id) = id {
                    self.core
                        .storage
                        .data
                        .get_principal_id(decode_path_element(id).as_ref())
                        .await?
                        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?
                        .into()
                } else {
                    None
                };
                let tenant_id = access_token.tenant.map(|t| t.id);

                let jmap = self.clone();
                tokio::spawn(async move {
                    if let Err(err) = jmap.reindex(account_id, tenant_id).await {
                        trc::error!(err.details("Failed to reindex FTS"));
                    }
                });

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            (Some("undelete"), _, _, _) => {
                // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
                // Any attempt to modify, bypass, or disable this license validation mechanism
                // constitutes a severe violation of the Stalwart Enterprise License Agreement.
                // Such actions may result in immediate termination of your license, legal action,
                // and substantial financial penalties. Stalwart Labs Ltd. actively monitors for
                // unauthorized modifications and will pursue all available legal remedies against
                // violators to the fullest extent of the law, including but not limited to claims
                // for copyright infringement, breach of contract, and fraud.

                // Validate the access token
                access_token.assert_has_permission(Permission::Undelete)?;

                if self.core.is_enterprise_edition() {
                    self.handle_undelete_api_request(req, path, body, session)
                        .await
                } else {
                    Err(manage::enterprise())
                }
            }
            // SPDX-SnippetEnd
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn housekeeper_request(&self, event: HousekeeperEvent) -> trc::Result<HttpResponse> {
        self.inner
            .ipc
            .housekeeper_tx
            .send(event)
            .await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .details("Failed to send housekeeper event")
            })?;

        Ok(JsonResponse::new(json!({
            "data": (),
        }))
        .into_http_response())
    }
}
