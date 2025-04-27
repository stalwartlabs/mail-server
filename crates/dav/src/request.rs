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
    xml_pretty_print,
};
use directory::Permission;
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{StatusCode, header};
use jmap_proto::types::collection::Collection;

use crate::{
    DavError, DavMethod, DavResourceName,
    calendar::{
        copy_move::CalendarCopyMoveRequestHandler, delete::CalendarDeleteRequestHandler,
        freebusy::CalendarFreebusyRequestHandler, get::CalendarGetRequestHandler,
        mkcol::CalendarMkColRequestHandler, proppatch::CalendarPropPatchRequestHandler,
        query::CalendarQueryRequestHandler, update::CalendarUpdateRequestHandler,
    },
    card::{
        copy_move::CardCopyMoveRequestHandler, delete::CardDeleteRequestHandler,
        get::CardGetRequestHandler, mkcol::CardMkColRequestHandler,
        proppatch::CardPropPatchRequestHandler, query::CardQueryRequestHandler,
        update::CardUpdateRequestHandler,
    },
    common::{
        DavQuery,
        acl::DavAclHandler,
        lock::{LockRequest, LockRequestHandler},
        propfind::PropFindRequestHandler,
        uri::DavUriResource,
    },
    file::{
        copy_move::FileCopyMoveRequestHandler, delete::FileDeleteRequestHandler,
        get::FileGetRequestHandler, mkcol::FileMkColRequestHandler,
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
        resource: DavResourceName,
        method: DavMethod,
    ) -> impl Future<Output = HttpResponse> + Send;
}

pub(crate) trait DavRequestDispatcher: Sync + Send {
    fn dispatch_dav_request(
        &self,
        request: &HttpRequest,
        access_token: Arc<AccessToken>,
        resource: DavResourceName,
        method: DavMethod,
        body: Vec<u8>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl DavRequestDispatcher for Server {
    async fn dispatch_dav_request(
        &self,
        request: &HttpRequest,
        access_token: Arc<AccessToken>,
        resource: DavResourceName,
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
            DavMethod::GET | DavMethod::HEAD => match resource {
                DavResourceName::Card => {
                    self.handle_card_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    self.handle_calendar_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::File => {
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
                        self.handle_file_get_request(
                            &access_token,
                            headers,
                            matches!(method, DavMethod::HEAD),
                        )
                        .await
                    }
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::REPORT => match Report::parse(&mut Tokenizer::new(&body))? {
                Report::SyncCollection(sync_collection) => {
                    let uri = self
                        .validate_uri(&access_token, headers.uri)
                        .await
                        .and_then(|d| d.into_owned_uri())?;
                    match resource {
                        DavResourceName::Card | DavResourceName::Cal | DavResourceName::File => {
                            self.handle_dav_query(
                                &access_token,
                                DavQuery::changes(uri, sync_collection, headers),
                            )
                            .await
                        }
                        DavResourceName::Principal => {
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
                    if resource == DavResourceName::Principal {
                        self.handle_principal_property_search(&access_token, report)
                            .await
                    } else {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
                Report::PrincipalSearchPropertySet => {
                    if resource == DavResourceName::Principal {
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
                Report::AddressbookQuery(report) => {
                    self.handle_card_query_request(&access_token, headers, report)
                        .await
                }
                Report::AddressbookMultiGet(report) => {
                    self.handle_dav_query(
                        &access_token,
                        DavQuery::multiget(report, Collection::AddressBook, headers),
                    )
                    .await
                }
                Report::CalendarQuery(report) => {
                    self.handle_calendar_query_request(&access_token, headers, report)
                        .await
                }
                Report::CalendarMultiGet(report) => {
                    self.handle_dav_query(
                        &access_token,
                        DavQuery::multiget(report, Collection::Calendar, headers),
                    )
                    .await
                }
                Report::FreeBusyQuery(report) => {
                    self.handle_calendar_freebusy_request(&access_token, headers, report)
                        .await
                }
                Report::ExpandProperty(report) => {
                    let uri = self
                        .validate_uri(&access_token, headers.uri)
                        .await
                        .and_then(|d| d.into_owned_uri())?;
                    match resource {
                        DavResourceName::Card | DavResourceName::Cal | DavResourceName::File => {
                            self.handle_dav_query(
                                &access_token,
                                DavQuery::expand(uri, report, headers),
                            )
                            .await
                        }
                        DavResourceName::Principal => {
                            Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                        }
                    }
                }
            },
            DavMethod::PROPPATCH => {
                let request = PropertyUpdate::parse(&mut Tokenizer::new(&body))?;
                match resource {
                    DavResourceName::Card => {
                        self.handle_card_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Cal => {
                        self.handle_calendar_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::File => {
                        self.handle_file_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Principal => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::MKCOL => {
                let request = if !body.is_empty() {
                    Some(MkCol::parse(&mut Tokenizer::new(&body))?)
                } else {
                    None
                };

                match resource {
                    DavResourceName::Card => {
                        self.handle_card_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Cal => {
                        self.handle_calendar_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::File => {
                        self.handle_file_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Principal => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::DELETE => {
                // Include any fragments in the URI
                if let Some(p) = request.uri().path_and_query() {
                    // TODO: Access to the fragment part is pending, see https://github.com/hyperium/http/issues/127
                    headers.uri = p.as_str();
                }

                match resource {
                    DavResourceName::Card => {
                        self.handle_card_delete_request(&access_token, headers)
                            .await
                    }
                    DavResourceName::Cal => {
                        self.handle_calendar_delete_request(&access_token, headers)
                            .await
                    }
                    DavResourceName::File => {
                        self.handle_file_delete_request(&access_token, headers)
                            .await
                    }
                    DavResourceName::Principal => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::PUT | DavMethod::POST | DavMethod::PATCH => match resource {
                DavResourceName::Card => {
                    self.handle_card_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    self.handle_calendar_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::File => {
                    self.handle_file_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::COPY | DavMethod::MOVE => match resource {
                DavResourceName::Card => {
                    self.handle_card_copy_move_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::MOVE),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    self.handle_calendar_copy_move_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::MOVE),
                    )
                    .await
                }
                DavResourceName::File => {
                    self.handle_file_copy_move_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::MOVE),
                    )
                    .await
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::MKCALENDAR => match resource {
                DavResourceName::Cal => {
                    self.handle_calendar_mkcol_request(
                        &access_token,
                        headers,
                        Some(MkCol::parse(&mut Tokenizer::new(&body))?),
                    )
                    .await
                }
                _ => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::LOCK => match resource {
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                _ => {
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
            },
            DavMethod::UNLOCK => {
                self.handle_lock_request(&access_token, headers, LockRequest::Unlock)
                    .await
            }
            DavMethod::ACL => {
                let request = Acl::parse(&mut Tokenizer::new(&body))?;
                match resource {
                    DavResourceName::Card | DavResourceName::Cal | DavResourceName::File => {
                        self.handle_acl_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Principal => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
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
        resource: DavResourceName,
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

        let c = println!("------------------------------------------");

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
                                .with_namespace(match resource {
                                    DavResourceName::Card => Namespace::CardDav,
                                    DavResourceName::Cal => Namespace::CalDav,
                                    DavResourceName::File | DavResourceName::Principal => {
                                        Namespace::Dav
                                    }
                                })
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
                        .with_namespace(match resource {
                            DavResourceName::Card => Namespace::CardDav,
                            DavResourceName::Cal => Namespace::CalDav,
                            DavResourceName::File | DavResourceName::Principal => Namespace::Dav,
                        })
                        .to_string(),
                )
                .with_no_cache(),
            Err(DavError::Code(code)) => HttpResponse::new(code),
        };

        let c = println!(
            "{:?} {} -> {:?}\nHeaders: {:?}\nBody: {}\nResponse headers: {:?}\nResponse: {}",
            method,
            request.uri().path(),
            result.status(),
            request.headers(),
            std_body,
            result.headers().unwrap(),
            match &result.body() {
                http_proto::HttpResponseBody::Text(t) => xml_pretty_print(t),
                http_proto::HttpResponseBody::Empty => "[empty]".to_string(),
                _ => "[binary]".to_string(),
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
