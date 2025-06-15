/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

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
use common::{Server, auth::AccessToken};
use compact_str::{CompactString, ToCompactString};
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
use jmap_proto::types::collection::Collection;
use std::{sync::Arc, time::Instant};
use trc::{EventType, LimitEvent, StoreEvent, WebDavEvent};

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
        headers: &RequestHeaders<'_>,
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
        headers: &RequestHeaders<'_>,
        access_token: Arc<AccessToken>,
        resource: DavResourceName,
        method: DavMethod,
        body: Vec<u8>,
    ) -> crate::Result<HttpResponse> {
        // Dispatch
        match method {
            DavMethod::PROPFIND => {
                let request = PropFind::parse(&mut Tokenizer::new(&body))?;

                self.handle_propfind_request(&access_token, headers, request)
                    .await
            }
            DavMethod::GET | DavMethod::HEAD => match resource {
                DavResourceName::Card => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCardGet)?;

                    self.handle_card_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalGet)?;

                    self.handle_calendar_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::File => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavFileGet)?;

                    #[cfg(debug_assertions)]
                    {
                        // Deal with Litmus bug
                        self.handle_file_get_request(
                            &access_token,
                            headers,
                            matches!(method, DavMethod::HEAD)
                                && !request.headers().contains_key("x-litmus"),
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
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavSyncCollection)?;

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
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavPrincipalAcl)?;

                    self.handle_acl_prop_set(&access_token, headers, report)
                        .await
                }
                Report::PrincipalMatch(report) => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavPrincipalMatch)?;

                    self.handle_principal_match(&access_token, headers, report)
                        .await
                }
                Report::PrincipalPropertySearch(report) => {
                    if resource == DavResourceName::Principal {
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavPrincipalSearch)?;

                        self.handle_principal_property_search(&access_token, report)
                            .await
                    } else {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
                Report::PrincipalSearchPropertySet => {
                    if resource == DavResourceName::Principal {
                        // Validate permissions
                        access_token
                            .assert_has_permission(Permission::DavPrincipalSearchPropSet)?;

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
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCardQuery)?;

                    self.handle_card_query_request(&access_token, headers, report)
                        .await
                }
                Report::AddressbookMultiGet(report) => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCardMultiGet)?;

                    self.handle_dav_query(
                        &access_token,
                        DavQuery::multiget(report, Collection::AddressBook, headers),
                    )
                    .await
                }
                Report::CalendarQuery(report) => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalQuery)?;

                    self.handle_calendar_query_request(&access_token, headers, report)
                        .await
                }
                Report::CalendarMultiGet(report) => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalMultiGet)?;

                    self.handle_dav_query(
                        &access_token,
                        DavQuery::multiget(report, Collection::Calendar, headers),
                    )
                    .await
                }
                Report::FreeBusyQuery(report) => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalFreeBusyQuery)?;

                    self.handle_calendar_freebusy_request(&access_token, headers, report)
                        .await
                }
                Report::ExpandProperty(report) => {
                    let uri = self
                        .validate_uri(&access_token, headers.uri)
                        .await
                        .and_then(|d| d.into_owned_uri())?;

                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavExpandProperty)?;

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
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavCardPropPatch)?;

                        self.handle_card_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Cal => {
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavCalPropPatch)?;

                        self.handle_calendar_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::File => {
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavFilePropPatch)?;

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
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavCardMkCol)?;

                        self.handle_card_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Cal => {
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavCalMkCol)?;

                        self.handle_calendar_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::File => {
                        // Validate permissions
                        access_token.assert_has_permission(Permission::DavFileMkCol)?;

                        self.handle_file_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Principal => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::DELETE => match resource {
                DavResourceName::Card => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCardDelete)?;

                    self.handle_card_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::Cal => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalDelete)?;

                    self.handle_calendar_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::File => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavFileDelete)?;

                    self.handle_file_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::PUT | DavMethod::POST | DavMethod::PATCH => match resource {
                DavResourceName::Card => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCardPut)?;

                    self.handle_card_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalPut)?;

                    self.handle_calendar_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::File => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavFilePut)?;

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
            DavMethod::COPY | DavMethod::MOVE => {
                let is_move = matches!(method, DavMethod::MOVE);
                match resource {
                    DavResourceName::Card => {
                        // Validate permissions
                        access_token.assert_has_permission(if is_move {
                            Permission::DavCardMove
                        } else {
                            Permission::DavCardCopy
                        })?;

                        self.handle_card_copy_move_request(&access_token, headers, is_move)
                            .await
                    }
                    DavResourceName::Cal => {
                        // Validate permissions
                        access_token.assert_has_permission(if is_move {
                            Permission::DavCalMove
                        } else {
                            Permission::DavCalCopy
                        })?;
                        self.handle_calendar_copy_move_request(&access_token, headers, is_move)
                            .await
                    }
                    DavResourceName::File => {
                        // Validate permissions
                        access_token.assert_has_permission(if is_move {
                            Permission::DavFileMove
                        } else {
                            Permission::DavFileCopy
                        })?;

                        self.handle_file_copy_move_request(&access_token, headers, is_move)
                            .await
                    }
                    DavResourceName::Principal => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::MKCALENDAR => match resource {
                DavResourceName::Cal => {
                    // Validate permissions
                    access_token.assert_has_permission(Permission::DavCalMkCol)?;

                    self.handle_calendar_mkcol_request(
                        &access_token,
                        headers,
                        Some(MkCol::parse(&mut Tokenizer::new(&body))?),
                    )
                    .await
                }
                _ => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::LOCK => {
                // Validate permissions
                access_token.assert_has_permission(match resource {
                    DavResourceName::File => Permission::DavFileLock,
                    DavResourceName::Cal => Permission::DavCalLock,
                    DavResourceName::Card => Permission::DavCardLock,
                    _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                })?;

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
            DavMethod::UNLOCK => {
                // Validate permissions
                access_token.assert_has_permission(match resource {
                    DavResourceName::File => Permission::DavFileLock,
                    DavResourceName::Cal => Permission::DavCalLock,
                    DavResourceName::Card => Permission::DavCardLock,
                    _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                })?;

                self.handle_lock_request(&access_token, headers, LockRequest::Unlock)
                    .await
            }
            DavMethod::ACL => {
                // Validate permissions
                access_token.assert_has_permission(match resource {
                    DavResourceName::File => Permission::DavFileAcl,
                    DavResourceName::Cal => Permission::DavCalAcl,
                    DavResourceName::Card => Permission::DavCardAcl,
                    _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                })?;

                self.handle_acl_request(
                    &access_token,
                    headers,
                    Acl::parse(&mut Tokenizer::new(&body))?,
                )
                .await
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
                    self.core.groupware.max_request_size
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

        //let c = println!("------------------------------------------");
        //let std_body = std::str::from_utf8(&body).unwrap_or("[binary]").to_string();

        // Parse headers
        let mut headers = RequestHeaders::new(request.uri().path());
        for (key, value) in request.headers() {
            headers.parse(key.as_str(), value.to_str().unwrap_or_default());
        }

        let start_time = Instant::now();
        match self
            .dispatch_dav_request(&request, &headers, access_token, resource, method, body)
            .await
        {
            Ok(response) => {
                let event = WebDavEvent::from(method);

                trc::event!(
                    WebDav(event),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Details = &headers,
                    Result = response.status().as_u16(),
                    Elapsed = start_time.elapsed(),
                );

                response
            }
            Err(DavError::Internal(err)) => {
                let err_type = err.event_type();

                trc::error!(
                    err.span_id(session.session_id)
                        .ctx(trc::Key::Url, headers.uri.to_compact_string())
                        .ctx(trc::Key::Type, resource.name())
                        .ctx(trc::Key::Elapsed, start_time.elapsed())
                );

                match err_type {
                    EventType::Limit(LimitEvent::Quota | LimitEvent::TenantQuota) => {
                        HttpResponse::new(StatusCode::PRECONDITION_FAILED)
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
                            .with_no_cache()
                    }
                    EventType::Store(StoreEvent::AssertValueFailed) => {
                        HttpResponse::new(StatusCode::CONFLICT)
                    }
                    EventType::Security(_) => HttpResponse::new(StatusCode::FORBIDDEN),
                    _ => HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR),
                }
            }
            Err(DavError::Parse(err)) => {
                let result = if headers.content_type.is_some_and(|h| h.contains("/xml")) {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::UNSUPPORTED_MEDIA_TYPE
                };

                trc::event!(
                    WebDav(WebDavEvent::Error),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Details = &headers,
                    Result = result.as_u16(),
                    Reason = err.to_compact_string(),
                    Elapsed = start_time.elapsed(),
                );

                HttpResponse::new(result)
            }
            Err(DavError::Condition(condition)) => {
                let event = WebDavEvent::from(method);

                trc::event!(
                    WebDav(event),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Details = &headers,
                    Result = condition.code.as_u16(),
                    Reason = CompactString::const_new(condition.condition.display_name()),
                    Elapsed = start_time.elapsed(),
                );

                HttpResponse::new(condition.code)
                    .with_xml_body(
                        ErrorResponse::new(condition.condition)
                            .with_namespace(match resource {
                                DavResourceName::Card => Namespace::CardDav,
                                DavResourceName::Cal => Namespace::CalDav,
                                DavResourceName::File | DavResourceName::Principal => {
                                    Namespace::Dav
                                }
                            })
                            .to_string(),
                    )
                    .with_no_cache()
            }
            Err(DavError::Code(code)) => {
                let event = WebDavEvent::from(method);

                trc::event!(
                    WebDav(event),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Details = &headers,
                    Result = code.as_u16(),
                    Elapsed = start_time.elapsed(),
                );

                HttpResponse::new(code)
            }
        }

        /*let c = println!(
            "{:?} {} -> {:?}\nHeaders: {:?}\nBody: {}\nResponse headers: {:?}\nResponse: {}",
            method,
            request.uri().path(),
            result.status(),
            request.headers(),
            std_body,
            result.headers().unwrap(),
            match &result.body() {
                http_proto::HttpResponseBody::Text(t) => dav_proto::xml_pretty_print(t),
                http_proto::HttpResponseBody::Empty => "[empty]".to_string(),
                _ => "[binary]".to_string(),
            }
        );

        result*/
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
