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

use http_body_util::combinators::BoxBody;
use hyper::{body::Bytes, Method};
use jmap_proto::error::request::RequestError;
use serde_json::json;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, JsonResponse},
    JMAP,
};

impl JMAP {
    pub async fn handle_manage_store(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
    ) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        match (path.get(1).copied(), req.method()) {
            (Some("maintenance"), &Method::GET) => {
                match self
                    .core
                    .storage
                    .data
                    .purge_blobs(self.core.storage.blob.clone())
                    .await
                {
                    Ok(_) => match self.core.storage.data.purge_store().await {
                        Ok(_) => JsonResponse::new(json!({
                            "data": (),
                        }))
                        .into_http_response(),
                        Err(err) => err.into_http_response(),
                    },
                    Err(err) => err.into_http_response(),
                }
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }
}
