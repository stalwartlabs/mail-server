/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::manager::webadmin::Resource;
use directory::backend::internal::manage::ManageDirectory;
use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    services::housekeeper::{Event, PurgeType},
    JMAP,
};

use super::decode_path_element;

impl JMAP {
    pub async fn handle_manage_store(&self, req: &HttpRequest, path: Vec<&str>) -> HttpResponse {
        match (
            path.get(1).copied(),
            path.get(2).copied(),
            path.get(3).copied(),
            req.method(),
        ) {
            (Some("blobs"), Some(blob_hash), _, &Method::GET) => {
                match URL_SAFE_NO_PAD.decode(decode_path_element(blob_hash).as_bytes()) {
                    Ok(blob_hash) => {
                        match self
                            .core
                            .storage
                            .blob
                            .get_blob(&blob_hash, 0..usize::MAX)
                            .await
                        {
                            Ok(Some(contents)) => {
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

                                Resource {
                                    content_type: "application/octet-stream",
                                    contents,
                                }
                                .into_http_response()
                            }
                            Ok(None) => RequestError::not_found().into_http_response(),
                            Err(err) => err.into_http_response(),
                        }
                    }
                    Err(_) => RequestError::invalid_parameters().into_http_response(),
                }
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
                        return RequestError::not_found().into_http_response();
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
                        return RequestError::not_found().into_http_response();
                    }
                } else {
                    self.core.storage.lookup.clone()
                };

                self.housekeeper_request(Event::Purge(PurgeType::Lookup(store)))
                    .await
            }
            (Some("purge"), Some("account"), id, &Method::GET) => {
                let account_id = if let Some(id) = id {
                    match self
                        .core
                        .storage
                        .data
                        .get_account_id(decode_path_element(id).as_ref())
                        .await
                    {
                        Ok(Some(id)) => id.into(),
                        Ok(None) => return RequestError::not_found().into_http_response(),
                        Err(err) => return err.into_http_response(),
                    }
                } else {
                    None
                };

                self.housekeeper_request(Event::Purge(PurgeType::Account(account_id)))
                    .await
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }

    async fn housekeeper_request(&self, event: Event) -> HttpResponse {
        match self.inner.housekeeper_tx.send(event).await {
            Ok(_) => JsonResponse::new(json!({
                "data": (),
            }))
            .into_http_response(),
            Err(_) => {
                tracing::error!("Failed to send housekeeper event");
                RequestError::internal_server_error().into_http_response()
            }
        }
    }
}
