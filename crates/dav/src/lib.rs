/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod request;

use http_proto::HttpResponse;
use hyper::{Method, StatusCode};

#[derive(Debug, Clone, Copy)]
pub enum DavResource {
    Card,
    Cal,
    File,
}

#[derive(Debug, Clone, Copy)]
pub enum DavMethod {
    GET,
    PUT,
    POST,
    DELETE,
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
}

impl DavResource {
    pub fn parse(service: &str) -> Option<Self> {
        hashify::tiny_map!(service.as_bytes(),
            "card" => DavResource::Card,
            "cal" => DavResource::Cal,
            "file" => DavResource::File
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
            _ => {
                hashify::tiny_map!(method.as_str().as_bytes(),
                    "PROPFIND" => DavMethod::PROPFIND,
                    "PROPPATCH" => DavMethod::PROPPATCH,
                    "REPORT" => DavMethod::REPORT,
                    "MKCOL" => DavMethod::MKCOL,
                    "COPY" => DavMethod::COPY,
                    "MOVE" => DavMethod::MOVE,
                    "LOCK" => DavMethod::LOCK,
                    "UNLOCK" => DavMethod::UNLOCK
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
                | DavMethod::MKCOL
                | DavMethod::COPY
                | DavMethod::MOVE
        )
    }
}
