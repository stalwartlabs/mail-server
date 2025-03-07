/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    parser::{DavParser, tokenizer::Tokenizer},
    schema::{
        Namespace,
        request::{Acl, LockInfo, MkCol, PropFind, PropertyUpdate, Report},
        response::{BaseCondition, ErrorResponse},
    },
};
use directory::Permission;
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{StatusCode, header};

use crate::{
    DavError, DavMethod, DavResource,
    file::{
        acl::FileAclRequestHandler, changes::FileChangesRequestHandler,
        copy_move::FileCopyMoveRequestHandler, delete::FileDeleteRequestHandler,
        get::FileGetRequestHandler, lock::FileLockRequestHandler, mkcol::FileMkColRequestHandler,
        propfind::FilePropFindRequestHandler, proppatch::FilePropPatchRequestHandler,
        update::FileUpdateRequestHandler,
    },
};

pub trait DavRequestHandler: Sync + Send {
    fn handle_dav_request(
        &self,
        request: HttpRequest,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
        resource: DavResource,
        method: DavMethod,
    ) -> impl Future<Output = HttpResponse> + Send;
}

pub(crate) trait DavRequestDispatcher: Sync + Send {
    fn dispatch_dav_request(
        &self,
        request: &HttpRequest,
        access_token: Arc<AccessToken>,
        resource: DavResource,
        method: DavMethod,
        body: Vec<u8>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl DavRequestDispatcher for Server {
    async fn dispatch_dav_request(
        &self,
        request: &HttpRequest,
        access_token: Arc<AccessToken>,
        resource: DavResource,
        method: DavMethod,
        body: Vec<u8>,
    ) -> crate::Result<HttpResponse> {
        // Parse headers
        let mut headers = RequestHeaders::new(request.uri().path());
        for (key, value) in request.headers() {
            headers.parse(key.as_str(), value.to_str().unwrap_or_default());
        }

        // Dispatch
        let todo = "lock tokens, headers, etc";
        match resource {
            DavResource::Card => {
                todo!()
            }
            DavResource::Cal => {
                todo!()
            }
            DavResource::Principal => {
                todo!()
            }
            DavResource::File => match method {
                DavMethod::PROPFIND => {
                    self.handle_file_propfind_request(
                        &access_token,
                        headers,
                        PropFind::parse(&mut Tokenizer::new(&body))?,
                    )
                    .await
                }
                DavMethod::PROPPATCH => {
                    self.handle_file_proppatch_request(
                        &access_token,
                        headers,
                        PropertyUpdate::parse(&mut Tokenizer::new(&body))?,
                    )
                    .await
                }
                DavMethod::MKCOL => {
                    self.handle_file_mkcol_request(
                        &access_token,
                        headers,
                        if !body.is_empty() {
                            Some(MkCol::parse(&mut Tokenizer::new(&body))?)
                        } else {
                            None
                        },
                    )
                    .await
                }
                DavMethod::GET => {
                    self.handle_file_get_request(&access_token, headers, false)
                        .await
                }
                DavMethod::HEAD => {
                    self.handle_file_get_request(&access_token, headers, true)
                        .await
                }
                DavMethod::DELETE => {
                    self.handle_file_delete_request(&access_token, headers)
                        .await
                }
                DavMethod::PUT | DavMethod::POST => {
                    self.handle_file_update_request(&access_token, headers, body, false)
                        .await
                }
                DavMethod::PATCH => {
                    self.handle_file_update_request(&access_token, headers, body, true)
                        .await
                }
                DavMethod::COPY => {
                    self.handle_file_copy_move_request(&access_token, headers, false)
                        .await
                }
                DavMethod::MOVE => {
                    self.handle_file_copy_move_request(&access_token, headers, true)
                        .await
                }
                DavMethod::LOCK => {
                    self.handle_file_lock_request(
                        &access_token,
                        headers,
                        LockInfo::parse(&mut Tokenizer::new(&body))?.into(),
                    )
                    .await
                }
                DavMethod::UNLOCK => {
                    self.handle_file_lock_request(&access_token, headers, None)
                        .await
                }
                DavMethod::ACL => {
                    self.handle_file_acl_request(
                        &access_token,
                        headers,
                        Acl::parse(&mut Tokenizer::new(&body))?,
                    )
                    .await
                }
                DavMethod::REPORT => match Report::parse(&mut Tokenizer::new(&body))? {
                    Report::SyncCollection(sync_collection) => {
                        self.handle_file_changes_request(&access_token, headers, sync_collection)
                            .await
                    }
                    _ => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                },
                DavMethod::OPTIONS => unreachable!(),
            },
        }
    }
}

impl DavRequestHandler for Server {
    async fn handle_dav_request(
        &self,
        mut request: HttpRequest,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
        resource: DavResource,
        method: DavMethod,
    ) -> HttpResponse {
        let body = if method.has_body()
            || request
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|len| len > 0)
        {
            if let Some(body) = fetch_body(
                &mut request,
                if !access_token.has_permission(Permission::UnlimitedUploads) {
                    self.core.dav.max_request_size
                } else {
                    0
                },
                session.session_id,
            )
            .await
            {
                body
            } else {
                trc::event!(
                    Limit(trc::LimitEvent::SizeRequest),
                    SpanId = session.session_id,
                    Contents = "Request body too large",
                );

                return HttpResponse::new(StatusCode::PAYLOAD_TOO_LARGE);
            }
        } else {
            Vec::new()
        };

        match self
            .dispatch_dav_request(&request, access_token, resource, method, body)
            .await
        {
            Ok(response) => response,
            Err(DavError::Internal(err)) => {
                let err_type = err.event_type();

                trc::error!(err.span_id(session.session_id));

                match err_type {
                    trc::EventType::Limit(
                        trc::LimitEvent::Quota | trc::LimitEvent::TenantQuota,
                    ) => HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_xml_body(
                            ErrorResponse::new(BaseCondition::QuotaNotExceeded)
                                .with_namespace(resource)
                                .to_string(),
                        )
                        .with_no_cache(),
                    trc::EventType::Store(trc::StoreEvent::AssertValueFailed) => {
                        HttpResponse::new(StatusCode::CONFLICT)
                    }
                    _ => HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR),
                }
            }
            Err(DavError::Parse(err)) => HttpResponse::new(StatusCode::BAD_REQUEST),
            Err(DavError::Condition(condition)) => {
                HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                    .with_xml_body(
                        ErrorResponse::new(condition)
                            .with_namespace(resource)
                            .to_string(),
                    )
                    .with_no_cache()
            }
            Err(DavError::Code(code)) => HttpResponse::new(code),
        }
    }
}

impl From<dav_proto::parser::Error> for DavError {
    fn from(err: dav_proto::parser::Error) -> Self {
        DavError::Parse(err)
    }
}

impl From<trc::Error> for DavError {
    fn from(err: trc::Error) -> Self {
        DavError::Internal(err)
    }
}

impl From<DavResource> for Namespace {
    fn from(value: DavResource) -> Self {
        match value {
            DavResource::Card => Namespace::CardDav,
            DavResource::Cal => Namespace::CalDav,
            DavResource::File | DavResource::Principal => Namespace::Dav,
        }
    }
}
