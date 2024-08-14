/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::manager::webadmin::Resource;
use directory::backend::internal::manage::ManageDirectory;
use hyper::Method;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{
        http::{HttpSessionData, ToHttpResponse},
        HttpRequest, HttpResponse, JsonResponse,
    },
    services::housekeeper::{Event, PurgeType},
    JMAP,
};

use super::decode_path_element;

impl JMAP {
    pub async fn handle_manage_store(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        match (
            path.get(1).copied(),
            path.get(2).copied(),
            path.get(3).copied(),
            req.method(),
        ) {
            (Some("blobs"), Some(blob_hash), _, &Method::GET) => {
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

                Ok(Resource {
                    content_type: "application/octet-stream",
                    contents,
                }
                .into_http_response())
            }
            (Some("purge"), Some("blob"), _, &Method::GET) => {
                self.housekeeper_request(Event::Purge(PurgeType::Blobs {
                    store: self.core.storage.data.clone(),
                    blob_store: self.core.storage.blob.clone(),
                }))
                .await
            }
            (Some("purge"), Some("data"), id, &Method::GET) => {
                let store = if let Some(id) = id {
                    if let Some(store) = self.core.storage.stores.get(id) {
                        store.clone()
                    } else {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                } else {
                    self.core.storage.data.clone()
                };

                self.housekeeper_request(Event::Purge(PurgeType::Data(store)))
                    .await
            }
            (Some("purge"), Some("lookup"), id, &Method::GET) => {
                let store = if let Some(id) = id {
                    if let Some(store) = self.core.storage.lookups.get(id) {
                        store.clone()
                    } else {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                } else {
                    self.core.storage.lookup.clone()
                };

                self.housekeeper_request(Event::Purge(PurgeType::Lookup(store)))
                    .await
            }
            (Some("purge"), Some("account"), id, &Method::GET) => {
                let account_id = if let Some(id) = id {
                    self.core
                        .storage
                        .data
                        .get_account_id(decode_path_element(id).as_ref())
                        .await?
                        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?
                        .into()
                } else {
                    None
                };

                self.housekeeper_request(Event::Purge(PurgeType::Account(account_id)))
                    .await
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            (Some("undelete"), _, _, _) if self.core.is_enterprise_edition() => {
                // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
                // Any attempt to modify, bypass, or disable this license validation mechanism
                // constitutes a severe violation of the Stalwart Enterprise License Agreement.
                // Such actions may result in immediate termination of your license, legal action,
                // and substantial financial penalties. Stalwart Labs Ltd. actively monitors for
                // unauthorized modifications and will pursue all available legal remedies against
                // violators to the fullest extent of the law, including but not limited to claims
                // for copyright infringement, breach of contract, and fraud.

                self.handle_undelete_api_request(req, path, body, session)
                    .await
            }
            // SPDX-SnippetEnd
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn housekeeper_request(&self, event: Event) -> trc::Result<HttpResponse> {
        self.inner.housekeeper_tx.send(event).await.map_err(|err| {
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
