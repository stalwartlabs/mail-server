/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::manager::webadmin::Resource;
use http_body_util::{BodyExt, Full};
use hyper::{
    StatusCode,
    body::Bytes,
    header::{self, HeaderName, HeaderValue},
};
use serde_json::json;

use crate::{
    DownloadResponse, HtmlResponse, HttpResponse, HttpResponseBody, JsonProblemResponse,
    JsonResponse, ToHttpResponse,
};

impl HttpResponse {
    pub fn new(status: StatusCode) -> Self {
        HttpResponse {
            status,
            builder: hyper::Response::builder().status(status),
            body: HttpResponseBody::Empty,
        }
    }

    pub fn with_content_type<V>(mut self, content_type: V) -> Self
    where
        V: TryInto<HeaderValue>,
        <V as TryInto<HeaderValue>>::Error: Into<hyper::http::Error>,
    {
        self.builder = self.builder.header(header::CONTENT_TYPE, content_type);
        self
    }

    pub fn with_status_code(mut self, status: StatusCode) -> Self {
        self.status = status;
        self.builder = self.builder.status(status);
        self
    }

    pub fn with_content_length(mut self, content_length: usize) -> Self {
        self.builder = self.builder.header(header::CONTENT_LENGTH, content_length);
        self
    }

    pub fn with_etag(mut self, etag: String) -> Self {
        self.builder = self.builder.header(header::ETAG, etag);
        self
    }

    pub fn with_etag_opt(self, etag: Option<String>) -> Self {
        if let Some(etag) = etag {
            self.with_etag(etag)
        } else {
            self
        }
    }

    pub fn with_last_modified(mut self, last_modified: String) -> Self {
        self.builder = self.builder.header(header::LAST_MODIFIED, last_modified);
        self
    }

    pub fn with_lock_token(mut self, token_uri: &str) -> Self {
        self.builder = self.builder.header("Lock-Token", format!("<{token_uri}>"));
        self
    }

    pub fn with_header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        <K as TryInto<HeaderName>>::Error: Into<hyper::http::Error>,
        V: TryInto<HeaderValue>,
        <V as TryInto<HeaderValue>>::Error: Into<hyper::http::Error>,
    {
        self.builder = self.builder.header(name, value);
        self
    }

    pub fn with_xml_body(self, body: impl Into<String>) -> Self {
        self.with_text_body(body)
            .with_content_type("application/xml; charset=utf-8")
    }

    pub fn with_text_body(mut self, body: impl Into<String>) -> Self {
        let body = body.into();
        let body_len = body.len();
        self.body = HttpResponseBody::Text(body);
        self.with_content_length(body_len)
    }

    pub fn with_binary_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        let body_len = body.len();
        self.body = HttpResponseBody::Binary(body);
        self.with_content_length(body_len)
    }

    pub fn with_stream_body(
        mut self,
        stream: http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>,
    ) -> Self {
        self.body = HttpResponseBody::Stream(stream);
        self
    }

    pub fn with_websocket_upgrade(mut self, derived_key: String) -> Self {
        self.body = HttpResponseBody::WebsocketUpgrade(derived_key);
        self
    }

    pub fn with_content_disposition<V>(mut self, content_disposition: V) -> Self
    where
        V: TryInto<HeaderValue>,
        <V as TryInto<HeaderValue>>::Error: Into<hyper::http::Error>,
    {
        self.builder = self
            .builder
            .header(header::CONTENT_DISPOSITION, content_disposition);
        self
    }

    pub fn with_cache_control<V>(mut self, cache_control: V) -> Self
    where
        V: TryInto<HeaderValue>,
        <V as TryInto<HeaderValue>>::Error: Into<hyper::http::Error>,
    {
        self.builder = self.builder.header(header::CACHE_CONTROL, cache_control);
        self
    }

    pub fn with_no_store(mut self) -> Self {
        self.builder = self
            .builder
            .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate");
        self
    }

    pub fn with_no_cache(mut self) -> Self {
        self.builder = self.builder.header(header::CACHE_CONTROL, "no-cache");
        self
    }

    pub fn with_location<V>(mut self, location: V) -> Self
    where
        V: TryInto<HeaderValue>,
        <V as TryInto<HeaderValue>>::Error: Into<hyper::http::Error>,
    {
        self.builder = self.builder.header(header::LOCATION, location);
        self
    }

    pub fn size(&self) -> usize {
        match &self.body {
            HttpResponseBody::Text(value) => value.len(),
            HttpResponseBody::Binary(value) => value.len(),
            _ => 0,
        }
    }

    pub fn build(
        self,
    ) -> hyper::Response<http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>>
    {
        match self.body {
            HttpResponseBody::Text(body) => self.builder.body(
                Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            ),
            HttpResponseBody::Binary(body) => self.builder.body(
                Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            ),
            HttpResponseBody::Empty => self.builder.header(header::CONTENT_LENGTH, 0).body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            ),
            HttpResponseBody::Stream(stream) => self.builder.body(stream),
            HttpResponseBody::WebsocketUpgrade(derived_key) => self
                .builder
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket")
                .header("Sec-WebSocket-Accept", &derived_key)
                .header("Sec-WebSocket-Protocol", "jmap")
                .body(
                    Full::new(Bytes::from("Switching to WebSocket protocol"))
                        .map_err(|never| match never {})
                        .boxed(),
                ),
        }
        .unwrap()
    }

    pub fn body(&self) -> &HttpResponseBody {
        &self.body
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> Option<&hyper::HeaderMap<HeaderValue>> {
        self.builder.headers_ref()
    }
}

impl<T: serde::Serialize> ToHttpResponse for JsonResponse<T> {
    fn into_http_response(self) -> HttpResponse {
        let response = HttpResponse::new(self.status)
            .with_content_type("application/json; charset=utf-8")
            .with_text_body(serde_json::to_string(&self.inner).unwrap_or_default());

        if self.no_cache {
            response.with_no_store()
        } else {
            response
        }
    }
}

impl ToHttpResponse for DownloadResponse {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new(StatusCode::OK)
            .with_content_type(self.content_type)
            .with_content_disposition(format!(
                "attachment; filename=\"{}\"",
                self.filename.replace('\"', "\\\"")
            ))
            .with_cache_control("private, immutable, max-age=31536000")
            .with_binary_body(self.blob)
    }
}

impl ToHttpResponse for Resource<Vec<u8>> {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new(StatusCode::OK)
            .with_content_type(self.content_type.as_ref())
            .with_binary_body(self.contents)
    }
}

impl ToHttpResponse for HtmlResponse {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new(self.status)
            .with_content_type("text/html; charset=utf-8")
            .with_text_body(self.body)
    }
}

impl ToHttpResponse for JsonProblemResponse {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new(self.0)
            .with_content_type("application/problem+json")
            .with_text_body(
                serde_json::to_string(&json!(
                    {
                        "type": "about:blank",
                        "title": self.0.canonical_reason().unwrap_or_default(),
                        "status": self.0.as_u16(),
                        "detail": self.0.canonical_reason().unwrap_or_default(),
                    }
                ))
                .unwrap_or_default(),
            )
    }
}
