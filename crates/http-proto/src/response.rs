/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use std::borrow::Cow;

use common::manager::webadmin::Resource;
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes, header};
use serde_json::json;

use crate::{
    DownloadResponse, HtmlResponse, HttpResponse, HttpResponseBody, JsonProblemResponse,
    JsonResponse, ToHttpResponse,
};

impl HttpResponse {
    pub fn new_empty(status: StatusCode) -> Self {
        HttpResponse {
            status,
            content_type: "".into(),
            content_disposition: "".into(),
            cache_control: "".into(),
            body: HttpResponseBody::Empty,
        }
    }

    pub fn new_text(
        status: StatusCode,
        content_type: impl Into<Cow<'static, str>>,
        body: impl Into<String>,
    ) -> Self {
        HttpResponse {
            status,
            content_type: content_type.into(),
            content_disposition: "".into(),
            cache_control: "".into(),
            body: HttpResponseBody::Text(body.into()),
        }
    }

    pub fn new_binary(
        status: StatusCode,
        content_type: impl Into<Cow<'static, str>>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        HttpResponse {
            status,
            content_type: content_type.into(),
            content_disposition: "".into(),
            cache_control: "".into(),
            body: HttpResponseBody::Binary(body.into()),
        }
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
        let builder = hyper::Response::builder().status(self.status);

        match self.body {
            HttpResponseBody::Text(body) => builder
                .header(header::CONTENT_TYPE, self.content_type.as_ref())
                .body(
                    Full::new(Bytes::from(body))
                        .map_err(|never| match never {})
                        .boxed(),
                ),
            HttpResponseBody::Binary(body) => {
                let mut builder = builder.header(header::CONTENT_TYPE, self.content_type.as_ref());

                if !self.content_disposition.is_empty() {
                    builder = builder.header(
                        header::CONTENT_DISPOSITION,
                        self.content_disposition.as_ref(),
                    );
                }

                if !self.cache_control.is_empty() {
                    builder = builder.header(header::CACHE_CONTROL, self.cache_control.as_ref());
                }

                builder.body(
                    Full::new(Bytes::from(body))
                        .map_err(|never| match never {})
                        .boxed(),
                )
            }
            HttpResponseBody::Empty => builder.body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            ),
            HttpResponseBody::Stream(stream) => builder
                .header(header::CONTENT_TYPE, self.content_type.as_ref())
                .header(header::CACHE_CONTROL, self.cache_control.as_ref())
                .body(stream),
            HttpResponseBody::WebsocketUpgrade(derived_key) => builder
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
}

impl<T: serde::Serialize> ToHttpResponse for JsonResponse<T> {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse {
            status: self.status,
            content_type: "application/json; charset=utf-8".into(),
            content_disposition: "".into(),
            cache_control: if !self.no_cache {
                ""
            } else {
                "no-store, no-cache, must-revalidate"
            }
            .into(),
            body: HttpResponseBody::Text(serde_json::to_string(&self.inner).unwrap_or_default()),
        }
    }
}

impl ToHttpResponse for DownloadResponse {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse {
            status: StatusCode::OK,
            content_type: self.content_type.into(),
            content_disposition: format!(
                "attachment; filename=\"{}\"",
                self.filename.replace('\"', "\\\"")
            )
            .into(),
            cache_control: "private, immutable, max-age=31536000".into(),
            body: HttpResponseBody::Binary(self.blob),
        }
    }
}

impl ToHttpResponse for Resource<Vec<u8>> {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new_binary(StatusCode::OK, self.content_type, self.contents)
    }
}

impl ToHttpResponse for HtmlResponse {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new_text(self.status, "text/html; charset=utf-8", self.body)
    }
}

impl ToHttpResponse for JsonProblemResponse {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new_text(
            self.0,
            "application/problem+json",
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
