/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod context;
pub mod request;
pub mod response;

pub use form_urlencoded;

use std::{net::IpAddr, sync::Arc};

use common::listener::ServerInstance;
use hyper::StatusCode;

pub type HttpRequest = hyper::Request<hyper::body::Incoming>;

pub struct JsonResponse<T: serde::Serialize> {
    status: StatusCode,
    inner: T,
    no_cache: bool,
}

pub struct HtmlResponse {
    status: StatusCode,
    body: String,
}

pub enum HttpResponseBody {
    Text(String),
    Binary(Vec<u8>),
    Stream(http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>),
    WebsocketUpgrade(String),
    Empty,
}

pub struct HttpResponse {
    status: StatusCode,
    builder: hyper::http::response::Builder,
    body: HttpResponseBody,
}

pub struct HttpContext<'x> {
    pub session: &'x HttpSessionData,
    pub req: &'x HttpRequest,
}

pub struct HttpSessionData {
    pub instance: Arc<ServerInstance>,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub is_tls: bool,
    pub session_id: u64,
}

pub struct DownloadResponse {
    pub filename: String,
    pub content_type: String,
    pub blob: Vec<u8>,
}

pub struct JsonProblemResponse(pub StatusCode);

impl<T: serde::Serialize> JsonResponse<T> {
    pub fn new(inner: T) -> Self {
        JsonResponse {
            inner,
            status: StatusCode::OK,
            no_cache: false,
        }
    }

    pub fn with_status(status: StatusCode, inner: T) -> Self {
        JsonResponse {
            inner,
            status,
            no_cache: false,
        }
    }

    pub fn no_cache(mut self) -> Self {
        self.no_cache = true;
        self
    }
}

impl HtmlResponse {
    pub fn new(body: String) -> Self {
        HtmlResponse {
            body,
            status: StatusCode::OK,
        }
    }

    pub fn with_status(status: StatusCode, body: String) -> Self {
        HtmlResponse { body, status }
    }
}

pub trait ToHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}
