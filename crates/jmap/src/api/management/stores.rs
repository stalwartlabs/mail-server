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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::manager::webadmin::Resource;
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
                    if let Ok(account_id) = id.parse::<u32>() {
                        account_id.into()
                    } else {
                        return RequestError::invalid_parameters().into_http_response();
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
