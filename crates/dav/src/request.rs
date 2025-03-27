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
        property::WebDavProperty,
        request::{Acl, LockInfo, MkCol, PropFind, PropertyUpdate, Report},
        response::{
            BaseCondition, ErrorResponse, PrincipalSearchProperty, PrincipalSearchPropertySet,
        },
    },
};
use directory::Permission;
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{StatusCode, header};

use crate::{
    DavError, DavMethod, DavResource,
    common::{
        DavQuery,
        acl::DavAclHandler,
        lock::{LockRequest, LockRequestHandler},
        propfind::PropFindRequestHandler,
        uri::DavUriResource,
    },
    file::{
        acl::FileAclRequestHandler, copy_move::FileCopyMoveRequestHandler,
        delete::FileDeleteRequestHandler, get::FileGetRequestHandler,
        mkcol::FileMkColRequestHandler, propfind::HandleFilePropFindRequest,
        proppatch::FilePropPatchRequestHandler, update::FileUpdateRequestHandler,
    },
    principal::{matching::PrincipalMatching, propsearch::PrincipalPropSearch},
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
        match method {
            DavMethod::PROPFIND => {
                self.handle_propfind_request(
                    &access_token,
                    headers,
                    PropFind::parse(&mut Tokenizer::new(&body))?,
                )
                .await
            }
            DavMethod::PROPPATCH => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_proppatch_request(
                        &access_token,
                        headers,
                        PropertyUpdate::parse(&mut Tokenizer::new(&body))?,
                    )
                    .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::MKCOL => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
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
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::GET => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_get_request(&access_token, headers, false)
                        .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::HEAD => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    #[cfg(debug_assertions)]
                    {
                        // Deal with Litmus bug
                        self.handle_file_get_request(
                            &access_token,
                            headers,
                            !request.headers().contains_key("x-litmus"),
                        )
                        .await
                    }

                    #[cfg(not(debug_assertions))]
                    {
                        self.handle_file_get_request(&access_token, headers, true)
                            .await
                    }
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::DELETE => {
                // Include any fragments in the URI
                if let Some(p) = request.uri().path_and_query() {
                    // TODO: Access to the fragment part is pending, see https://github.com/hyperium/http/issues/127
                    headers.uri = p.as_str();
                }

                match resource {
                    DavResource::Card => todo!(),
                    DavResource::Cal => todo!(),
                    DavResource::File => {
                        self.handle_file_delete_request(&access_token, headers)
                            .await
                    }
                    DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                }
            }
            DavMethod::PUT | DavMethod::POST => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_update_request(&access_token, headers, body, false)
                        .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::PATCH => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_update_request(&access_token, headers, body, true)
                        .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::COPY => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_copy_move_request(&access_token, headers, false)
                        .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::MOVE => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_copy_move_request(&access_token, headers, true)
                        .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::LOCK => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_lock_request(
                        &access_token,
                        headers,
                        if !body.is_empty() {
                            LockRequest::Lock(LockInfo::parse(&mut Tokenizer::new(&body))?)
                        } else {
                            LockRequest::Refresh
                        },
                    )
                    .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::UNLOCK => {
                self.handle_lock_request(&access_token, headers, LockRequest::Unlock)
                    .await
            }
            DavMethod::ACL => match resource {
                DavResource::Card => todo!(),
                DavResource::Cal => todo!(),
                DavResource::File => {
                    self.handle_file_acl_request(
                        &access_token,
                        headers,
                        Acl::parse(&mut Tokenizer::new(&body))?,
                    )
                    .await
                }
                DavResource::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::REPORT => match Report::parse(&mut Tokenizer::new(&body))? {
                Report::SyncCollection(sync_collection) => {
                    let uri = self
                        .validate_uri(&access_token, headers.uri)
                        .await
                        .and_then(|d| d.into_owned_uri())?;
                    match resource {
                        DavResource::Card => todo!(),
                        DavResource::Cal => todo!(),
                        DavResource::File => {
                            self.handle_file_propfind_request(
                                &access_token,
                                DavQuery::changes(uri, sync_collection, headers),
                            )
                            .await
                        }
                        DavResource::Principal => {
                            Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                        }
                    }
                }
                Report::AclPrincipalPropSet(report) => {
                    self.handle_acl_prop_set(&access_token, headers, report)
                        .await
                }
                Report::PrincipalMatch(report) => {
                    self.handle_principal_match(&access_token, headers, report)
                        .await
                }
                Report::PrincipalPropertySearch(report) => {
                    if resource == DavResource::Principal {
                        self.handle_principal_property_search(&access_token, report)
                            .await
                    } else {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
                Report::PrincipalSearchPropertySet => {
                    if resource == DavResource::Principal {
                        Ok(HttpResponse::new(StatusCode::OK).with_xml_body(
                            PrincipalSearchPropertySet::new(vec![PrincipalSearchProperty::new(
                                WebDavProperty::DisplayName,
                                "Account or Group name",
                            )])
                            .to_string(),
                        ))
                    } else {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
                Report::Addressbook(report) => todo!(),
                Report::AddressbookMultiGet(report) => todo!(),
                Report::CalendarQuery(report) => todo!(),
                Report::CalendarMultiGet(report) => todo!(),
                Report::FreeBusyQuery(report) => todo!(),
            },
            DavMethod::OPTIONS => unreachable!(),
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

        let std_body = std::str::from_utf8(&body).unwrap_or("[binary]").to_string();

        let result = match self
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
            Err(DavError::Parse(err)) => {
                if request
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|h| h.to_str().unwrap_or_default().contains("/xml"))
                {
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                } else {
                    HttpResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                }
            }
            Err(DavError::Condition(condition)) => HttpResponse::new(condition.code)
                .with_xml_body(
                    ErrorResponse::new(condition.condition)
                        .with_namespace(resource)
                        .to_string(),
                )
                .with_no_cache(),
            Err(DavError::Code(code)) => HttpResponse::new(code),
        };

        let c = println!(
            "------------------------------------------\n{:?} {} -> {:?}\nHeaders: {:?}\nBody: {}\nResponse headers: {:?}\nResponse: {}",
            method,
            request.uri().path(),
            result.status(),
            request.headers(),
            std_body,
            result.headers().unwrap(),
            match &result.body() {
                http_proto::HttpResponseBody::Text(t) => t,
                http_proto::HttpResponseBody::Empty => "[empty]",
                _ => "[binary]",
            }
        );

        result
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
