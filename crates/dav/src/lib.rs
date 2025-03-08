/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod calendar;
pub mod card;
pub mod common;
pub mod file;
pub mod principal;
pub mod request;

use dav_proto::schema::response::Condition;
use http_proto::HttpResponse;
use hyper::{Method, StatusCode};
use jmap_proto::types::collection::Collection;

pub(crate) type Result<T> = std::result::Result<T, DavError>;

#[derive(Debug, Clone, Copy)]
pub enum DavResource {
    Card,
    Cal,
    File,
    Principal,
}

#[derive(Debug, Clone, Copy)]
pub enum DavMethod {
    GET,
    PUT,
    POST,
    DELETE,
    HEAD,
    PATCH,
    PROPFIND,
    PROPPATCH,
    REPORT,
    MKCOL,
    COPY,
    MOVE,
    LOCK,
    UNLOCK,
    OPTIONS,
    ACL,
}

pub(crate) enum DavError {
    Parse(dav_proto::parser::Error),
    Internal(trc::Error),
    Condition(Condition),
    Code(StatusCode),
}

impl From<DavResource> for Collection {
    fn from(value: DavResource) -> Self {
        match value {
            DavResource::Card => Collection::AddressBook,
            DavResource::Cal => Collection::Calendar,
            DavResource::File => Collection::FileNode,
            DavResource::Principal => Collection::Principal,
        }
    }
}

impl DavResource {
    pub fn parse(service: &str) -> Option<Self> {
        hashify::tiny_map!(service.as_bytes(),
            "card" => DavResource::Card,
            "cal" => DavResource::Cal,
            "file" => DavResource::File,
            "pal" => DavResource::Principal,
        )
    }

    pub fn into_options_response(self) -> HttpResponse {
        let todo = "true";
        HttpResponse::new(StatusCode::OK)
            .with_header("DAV", "1, 2, 3, access-control, calendar-access")
    }
}

impl DavMethod {
    pub fn parse(method: &Method) -> Option<Self> {
        match *method {
            Method::GET => Some(DavMethod::GET),
            Method::PUT => Some(DavMethod::PUT),
            Method::DELETE => Some(DavMethod::DELETE),
            Method::OPTIONS => Some(DavMethod::OPTIONS),
            Method::POST => Some(DavMethod::POST),
            Method::PATCH => Some(DavMethod::PATCH),
            Method::HEAD => Some(DavMethod::HEAD),
            _ => {
                hashify::tiny_map!(method.as_str().as_bytes(),
                    "PROPFIND" => DavMethod::PROPFIND,
                    "PROPPATCH" => DavMethod::PROPPATCH,
                    "REPORT" => DavMethod::REPORT,
                    "MKCOL" => DavMethod::MKCOL,
                    "COPY" => DavMethod::COPY,
                    "MOVE" => DavMethod::MOVE,
                    "LOCK" => DavMethod::LOCK,
                    "UNLOCK" => DavMethod::UNLOCK,
                    "ACL" => DavMethod::ACL
                )
            }
        }
    }

    #[inline]
    pub fn has_body(self) -> bool {
        matches!(
            self,
            DavMethod::PUT
                | DavMethod::POST
                | DavMethod::PATCH
                | DavMethod::PROPPATCH
                | DavMethod::PROPFIND
                | DavMethod::REPORT
                | DavMethod::LOCK
                | DavMethod::ACL
        )
    }
}
