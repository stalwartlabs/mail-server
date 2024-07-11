/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::str::FromStr;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use common::enterprise::undelete::DeletedBlob;
use directory::backend::internal::manage::ManageDirectory;
use hyper::Method;
use jmap_proto::{error::request::RequestError, types::collection::Collection};
use mail_parser::{DateTime, MessageParser};
use serde_json::json;
use store::write::{BatchBuilder, BlobOp, ValueClass};
use utils::{url_params::UrlParams, BlobHash};

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    email::ingest::{IngestEmail, IngestSource},
    mailbox::INBOX_ID,
    JMAP,
};

#[derive(serde::Deserialize)]
struct UndeleteRequest<H, C, T> {
    hash: H,
    collection: C,
    #[serde(rename = "restoreTime")]
    time: T,
    #[serde(rename = "cancelDeletion")]
    #[serde(default)]
    cancel_deletion: Option<T>,
}

#[derive(serde::Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
enum UndeleteResponse {
    Success,
    NotFound,
    Error { reason: String },
}

impl JMAP {
    pub async fn handle_enterprise_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        match path.get(1).copied().unwrap_or_default() {
            "undelete" => self.handle_undelete_api_request(req, path, body).await,
            _ => RequestError::not_found().into_http_response(),
        }
    }

    async fn handle_undelete_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        match (path.get(2).copied(), req.method()) {
            (Some(account_name), &Method::GET) => {
                match self.core.storage.data.get_account_id(account_name).await {
                    Ok(Some(account_id)) => match self.core.list_deleted(account_id).await {
                        Ok(mut deleted) => {
                            let params = UrlParams::new(req.uri().query());
                            let limit = params.parse::<usize>("limit").unwrap_or_default();
                            let mut offset = params
                                .parse::<usize>("page")
                                .unwrap_or_default()
                                .saturating_sub(1)
                                * limit;

                            // Sort ascending by deleted_at
                            let total = deleted.len();
                            deleted.sort_by(|a, b| a.deleted_at.cmp(&b.deleted_at));
                            let mut results =
                                Vec::with_capacity(if limit > 0 { limit } else { total });

                            for blob in deleted {
                                if offset == 0 {
                                    results.push(DeletedBlob {
                                        hash: URL_SAFE_NO_PAD.encode(blob.hash.as_slice()),
                                        size: blob.size,
                                        deleted_at: DateTime::from_timestamp(
                                            blob.deleted_at as i64,
                                        )
                                        .to_rfc3339(),
                                        expires_at: DateTime::from_timestamp(
                                            blob.expires_at as i64,
                                        )
                                        .to_rfc3339(),
                                        collection: Collection::from(blob.collection).to_string(),
                                    });
                                    if results.len() == limit {
                                        break;
                                    }
                                } else {
                                    offset -= 1;
                                }
                            }

                            JsonResponse::new(json!({
                                    "data":{
                                        "items": results,
                                        "total": total,
                                    },
                            }))
                            .into_http_response()
                        }
                        Err(err) => err.into_http_response(),
                    },
                    Ok(None) => RequestError::not_found().into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            (Some(account_name), &Method::POST) => {
                match self.core.storage.data.get_account_id(account_name).await {
                    Ok(Some(account_id)) => {
                        match serde_json::from_slice::<Vec<UndeleteRequest<String, String, String>>>(
                            body.as_deref().unwrap_or_default(),
                        )
                        .ok()
                        .and_then(|request| {
                            request.into_iter().map(|request| {
                                UndeleteRequest {
                                    hash: BlobHash::try_from_hash_slice(
                                        URL_SAFE_NO_PAD
                                            .decode(request.hash.as_bytes())
                                            .ok()?
                                            .as_slice(),
                                    )
                                    .ok()?,
                                    collection: Collection::from_str(
                                        request.collection.as_str(),
                                    )
                                    .ok()?,
                                    time: DateTime::parse_rfc3339(request.time.as_str())?
                                        .to_timestamp(),
                                    cancel_deletion: if let Some(cancel_deletion) = request.cancel_deletion {
                                        DateTime::parse_rfc3339(cancel_deletion.as_str())?
                                        .to_timestamp().into()
                                    } else {
                                        None
                                    }
                                }
                                .into()
                            }).collect::<Option<Vec<_>>>()
                        }) {
                            Some(requests) => {
                                let mut results = Vec::with_capacity(requests.len());
                                let mut batch = BatchBuilder::new();
                                batch.with_account_id(account_id);
                                for request in requests {
                                    match request.collection {
                                        Collection::Email => {
                                            match self.get_blob(&request.hash, 0..usize::MAX).await
                                            {
                                                Ok(Some(bytes)) => {
                                                    match self
                                                        .email_ingest(IngestEmail {
                                                            raw_message: &bytes,
                                                            message: MessageParser::new().parse(&bytes),
                                                            account_id,
                                                            account_quota: 0,
                                                            mailbox_ids: vec![INBOX_ID],
                                                            keywords: vec![],
                                                            received_at: (request.time as u64).into(),
                                                            source: IngestSource::Smtp,
                                                            encrypt: false,
                                                        })
                                                        .await
                                                    {
                                                        Ok(_) => {
                                                            results.push(UndeleteResponse::Success);
                                                            if let Some(cancel_deletion) = request.cancel_deletion {
                                                                batch.clear(ValueClass::Blob(BlobOp::Reserve { hash: request.hash, until: cancel_deletion as u64 }));
                                                            }
                                                        },
                                                        Err(mut err) if err.matches(trc::Cause::Ingest) => {
                                                            results.push(UndeleteResponse::Error { reason: err.take_value(trc::Key::Reason)
                                                                .and_then(|v| v.into_string())
                                                                .unwrap().into_owned() });
                                                        }
                                                        Err(_) => {
                                                            return RequestError::internal_server_error().into_http_response();
                                                        },
                                                    }
                                                }
                                                Ok(None) => {
                                                    results.push(UndeleteResponse::NotFound);
                                                },
                                                Err(_) => {
                                                    return RequestError::internal_server_error().into_http_response();
                                                },
                                            }
                                        }
                                        _ => {
                                            results.push(UndeleteResponse::Error {
                                                reason: "Unsupported collection".to_string(),
                                            });
                                        }
                                    }
                                }

                                // Commit batch
                                if !batch.is_empty() {
                                    match self.core.storage.data.write(batch.build()).await {
                                        Ok(_) => (),
                                        Err(err) => return err.into_http_response(),
                                    }
                                }

                                JsonResponse::new(json!({
                                    "data": results,
                                }))
                                .into_http_response()
                            },
                            None => RequestError::invalid_parameters().into_http_response(),
                        }
                    }
                    Ok(None) => RequestError::not_found().into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }
}
