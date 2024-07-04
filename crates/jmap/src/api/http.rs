/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc};

use common::{
    expr::{functions::ResolveVariable, *},
    listener::{ServerInstance, SessionData, SessionManager, SessionStream},
    manager::webadmin::Resource,
    Core,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{self, Bytes},
    header::{self, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
    Method, StatusCode,
};
use hyper_util::rt::TokioIo;
use jmap_proto::{
    error::request::{RequestError, RequestLimitError},
    request::{capability::Session, Request},
    response::Response,
    types::{blob::BlobId, id::Id},
};

use crate::{
    auth::oauth::OAuthMetadata,
    blob::{DownloadResponse, UploadResponse},
    services::state,
    JmapInstance, JMAP,
};

use super::{HtmlResponse, HttpRequest, HttpResponse, JmapSessionManager, JsonResponse};

pub struct HttpSessionData {
    pub instance: Arc<ServerInstance>,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub is_tls: bool,
}

impl JMAP {
    pub async fn parse_http_request(
        &self,
        mut req: HttpRequest,
        session: HttpSessionData,
    ) -> HttpResponse {
        let mut path = req.uri().path().split('/');
        path.next();

        match path.next().unwrap_or_default() {
            "jmap" => {
                // Authenticate request
                let (_in_flight, access_token) =
                    match self.authenticate_headers(&req, session.remote_ip).await {
                        Ok(Some(session)) => session,
                        Ok(None) => {
                            return if req.method() != Method::OPTIONS {
                                RequestError::unauthorized().into_http_response()
                            } else {
                                StatusCode::NO_CONTENT.into_http_response()
                            }
                        }
                        Err(err) => return err.into_http_response(),
                    };

                match (path.next().unwrap_or_default(), req.method()) {
                    ("", &Method::POST) => {
                        return match fetch_body(
                            &mut req,
                            if !access_token.is_super_user() {
                                self.core.jmap.upload_max_size
                            } else {
                                0
                            },
                        )
                        .await
                        .ok_or_else(|| RequestError::limit(RequestLimitError::SizeRequest))
                        .and_then(|bytes| {
                            //let c = println!("<- {}", String::from_utf8_lossy(&bytes));

                            Request::parse(
                                &bytes,
                                self.core.jmap.request_max_calls,
                                self.core.jmap.request_max_size,
                            )
                        }) {
                            Ok(request) => {
                                match self
                                    .handle_request(request, access_token, &session.instance)
                                    .await
                                {
                                    Ok(response) => {
                                        /*let c = println!(
                                            "-> {}",
                                            serde_json::to_string_pretty(&response).unwrap()
                                        );*/

                                        response.into_http_response()
                                    }
                                    Err(err) => err.into_http_response(),
                                }
                            }
                            Err(err) => err.into_http_response(),
                        };
                    }
                    ("download", &Method::GET) => {
                        if let (Some(_), Some(blob_id), Some(name)) = (
                            path.next().and_then(|p| Id::from_bytes(p.as_bytes())),
                            path.next().and_then(BlobId::from_base32),
                            path.next(),
                        ) {
                            return match self.blob_download(&blob_id, &access_token).await {
                                Ok(Some(blob)) => DownloadResponse {
                                    filename: name.to_string(),
                                    content_type: req
                                        .uri()
                                        .query()
                                        .and_then(|q| {
                                            form_urlencoded::parse(q.as_bytes())
                                                .find(|(k, _)| k == "accept")
                                                .map(|(_, v)| v.into_owned())
                                        })
                                        .unwrap_or("application/octet-stream".to_string()),
                                    blob,
                                }
                                .into_http_response(),
                                Ok(None) => RequestError::not_found().into_http_response(),
                                Err(_) => {
                                    RequestError::internal_server_error().into_http_response()
                                }
                            };
                        }
                    }
                    ("upload", &Method::POST) => {
                        if let Some(account_id) =
                            path.next().and_then(|p| Id::from_bytes(p.as_bytes()))
                        {
                            return match fetch_body(
                                &mut req,
                                if !access_token.is_super_user() {
                                    self.core.jmap.upload_max_size
                                } else {
                                    0
                                },
                            )
                            .await
                            {
                                Some(bytes) => {
                                    match self
                                        .blob_upload(
                                            account_id,
                                            req.headers()
                                                .get(CONTENT_TYPE)
                                                .and_then(|h| h.to_str().ok())
                                                .unwrap_or("application/octet-stream"),
                                            &bytes,
                                            access_token,
                                        )
                                        .await
                                    {
                                        Ok(response) => response.into_http_response(),
                                        Err(err) => err.into_http_response(),
                                    }
                                }
                                None => RequestError::limit(RequestLimitError::SizeUpload)
                                    .into_http_response(),
                            };
                        }
                    }
                    ("eventsource", &Method::GET) => {
                        return self.handle_event_source(req, access_token).await
                    }
                    ("ws", &Method::GET) => {
                        return self
                            .upgrade_websocket_connection(
                                req,
                                access_token,
                                session.instance.clone(),
                            )
                            .await;
                    }
                    (_, &Method::OPTIONS) => {
                        return StatusCode::NO_CONTENT.into_http_response();
                    }
                    _ => (),
                }
            }
            ".well-known" => match (path.next().unwrap_or_default(), req.method()) {
                ("jmap", &Method::GET) => {
                    // Authenticate request
                    let (_in_flight, access_token) =
                        match self.authenticate_headers(&req, session.remote_ip).await {
                            Ok(Some(session)) => session,
                            Ok(None) => return RequestError::unauthorized().into_http_response(),
                            Err(err) => return err.into_http_response(),
                        };

                    return match self
                        .handle_session_resource(
                            session.resolve_url(&self.core).await,
                            access_token,
                        )
                        .await
                    {
                        Ok(session) => session.into_http_response(),
                        Err(err) => err.into_http_response(),
                    };
                }
                ("oauth-authorization-server", &Method::GET) => {
                    // Limit anonymous requests
                    return match self.is_anonymous_allowed(&session.remote_ip).await {
                        Ok(_) => JsonResponse::new(OAuthMetadata::new(
                            session.resolve_url(&self.core).await,
                        ))
                        .into_http_response(),
                        Err(err) => err.into_http_response(),
                    };
                }
                ("acme-challenge", &Method::GET) if self.core.has_acme_http_providers() => {
                    if let Some(token) = path.next() {
                        return match self
                            .core
                            .storage
                            .lookup
                            .key_get::<String>(format!("acme:{token}").into_bytes())
                            .await
                        {
                            Ok(Some(proof)) => Resource {
                                content_type: "text/plain",
                                contents: proof.into_bytes(),
                            }
                            .into_http_response(),
                            Ok(None) => RequestError::not_found().into_http_response(),
                            Err(err) => err.into_http_response(),
                        };
                    }
                }
                ("mta-sts.txt", &Method::GET) => {
                    if let Some(policy) = self.core.build_mta_sts_policy() {
                        return Resource {
                            content_type: "text/plain",
                            contents: policy.to_string().into_bytes(),
                        }
                        .into_http_response();
                    } else {
                        return RequestError::not_found().into_http_response();
                    }
                }
                ("mail-v1.xml", &Method::GET) => {
                    return self.handle_autoconfig_request(&req).await;
                }
                ("autoconfig", &Method::GET) => {
                    if path.next().unwrap_or_default() == "mail"
                        && path.next().unwrap_or_default() == "config-v1.1.xml"
                    {
                        return self.handle_autoconfig_request(&req).await;
                    }
                }
                (_, &Method::OPTIONS) => {
                    return StatusCode::NO_CONTENT.into_http_response();
                }
                _ => (),
            },
            "auth" => match (path.next().unwrap_or_default(), req.method()) {
                ("device", &Method::POST) => {
                    return match self.is_anonymous_allowed(&session.remote_ip).await {
                        Ok(_) => {
                            self.handle_device_auth(&mut req, session.resolve_url(&self.core).await)
                                .await
                        }
                        Err(err) => err.into_http_response(),
                    }
                }
                ("token", &Method::POST) => {
                    return match self.is_anonymous_allowed(&session.remote_ip).await {
                        Ok(_) => self.handle_token_request(&mut req).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                (_, &Method::OPTIONS) => {
                    return StatusCode::NO_CONTENT.into_http_response();
                }
                _ => (),
            },
            "api" => {
                // Allow CORS preflight requests
                if req.method() == Method::OPTIONS {
                    return StatusCode::NO_CONTENT.into_http_response();
                }

                // Authenticate user
                return match self.authenticate_headers(&req, session.remote_ip).await {
                    Ok(Some((_, access_token))) => {
                        let body = fetch_body(&mut req, 1024 * 1024).await;
                        self.handle_api_manage_request(&req, body, access_token)
                            .await
                    }
                    Ok(None) => RequestError::unauthorized().into_http_response(),
                    Err(err) => err.into_http_response(),
                };
            }
            "mail" => {
                if req.method() == Method::GET
                    && path.next().unwrap_or_default() == "config-v1.1.xml"
                {
                    return self.handle_autoconfig_request(&req).await;
                }
            }
            "autodiscover" => {
                if req.method() == Method::POST
                    && path.next().unwrap_or_default() == "autodiscover.xml"
                {
                    return self
                        .handle_autodiscover_request(fetch_body(&mut req, 8192).await)
                        .await;
                }
            }
            "robots.txt" => {
                return Resource {
                    content_type: "text/plain",
                    contents: b"User-agent: *\nDisallow: /\n".to_vec(),
                }
                .into_http_response();
            }
            "healthz" => match path.next().unwrap_or_default() {
                "live" => {
                    return StatusCode::OK.into_http_response();
                }
                "ready" => {
                    return {
                        if !self.core.storage.data.is_none() {
                            StatusCode::OK
                        } else {
                            StatusCode::SERVICE_UNAVAILABLE
                        }
                    }
                    .into_http_response();
                }
                _ => (),
            },
            _ => {
                let path = req.uri().path();
                return match self
                    .inner
                    .webadmin
                    .get(path.strip_prefix('/').unwrap_or(path))
                    .await
                {
                    Ok(resource) if !resource.is_empty() => resource.into_http_response(),
                    Err(err) => err.into_http_response(),
                    _ => RequestError::not_found().into_http_response(),
                };
            }
        }
        RequestError::not_found().into_http_response()
    }
}

impl JmapInstance {
    async fn handle_session<T: SessionStream>(self, session: SessionData<T>) {
        let span = session.span;
        let _in_flight = session.in_flight;
        let is_tls = session.stream.is_tls();

        if let Err(http_err) = http1::Builder::new()
            .keep_alive(true)
            .serve_connection(
                TokioIo::new(session.stream),
                service_fn(|req: hyper::Request<body::Incoming>| {
                    let jmap_instance = self.clone();
                    let span = span.clone();
                    let instance = session.instance.clone();

                    async move {
                        tracing::debug!(
                            parent: &span,
                            event = "request",
                            uri = req.uri().to_string(),
                        );
                        let jmap = JMAP::from(jmap_instance);

                        // Obtain remote IP
                        let remote_ip = if !jmap.core.jmap.http_use_forwarded {
                            session.remote_ip
                        } else if let Some(forwarded_for) = req
                            .headers()
                            .get(header::FORWARDED)
                            .or_else(|| req.headers().get("X-Forwarded-For"))
                            .and_then(|h| h.to_str().ok())
                            .and_then(|h| h.parse::<IpAddr>().ok())
                        {
                            forwarded_for
                        } else {
                            tracing::warn!(
                                "Warning: No remote address found in request, using remote ip."
                            );
                            session.remote_ip
                        };

                        // Parse HTTP request
                        let mut response = jmap
                            .parse_http_request(
                                req,
                                HttpSessionData {
                                    instance,
                                    local_ip: session.local_ip,
                                    local_port: session.local_port,
                                    remote_ip,
                                    remote_port: session.remote_port,
                                    is_tls,
                                },
                            )
                            .await;

                        // Add custom headers
                        if !jmap.core.jmap.http_headers.is_empty() {
                            let headers = response.headers_mut();

                            for (header, value) in &jmap.core.jmap.http_headers {
                                headers.insert(header.clone(), value.clone());
                            }
                        }

                        Ok::<_, hyper::Error>(response)
                    }
                }),
            )
            .with_upgrades()
            .await
        {
            tracing::debug!(
                parent: &span,
                event = "error",
                context = "http",
                reason = %http_err,
            );
        }
    }
}

impl SessionManager for JmapSessionManager {
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        self.inner.handle_session(session)
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {
            let _ = self
                .inner
                .jmap_inner
                .state_tx
                .send(state::Event::Stop)
                .await;
        }
    }
}

impl ResolveVariable for HttpSessionData {
    fn resolve_variable(&self, variable: u32) -> common::expr::Variable<'_> {
        match variable {
            V_REMOTE_IP => self.remote_ip.to_string().into(),
            V_REMOTE_PORT => self.remote_port.into(),
            V_LOCAL_IP => self.local_ip.to_string().into(),
            V_LOCAL_PORT => self.local_port.into(),
            V_TLS => self.is_tls.into(),
            V_PROTOCOL => if self.is_tls { "https" } else { "http" }.into(),
            V_LISTENER => self.instance.id.as_str().into(),
            _ => common::expr::Variable::default(),
        }
    }
}

impl HttpSessionData {
    pub async fn resolve_url(&self, core: &Core) -> String {
        core.eval_if(&core.network.url, self)
            .await
            .unwrap_or_else(|| {
                format!(
                    "http{}://{}:{}",
                    if self.is_tls { "s" } else { "" },
                    self.local_ip,
                    self.local_port
                )
            })
    }
}

pub async fn fetch_body(req: &mut HttpRequest, max_size: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    while let Some(Ok(frame)) = req.frame().await {
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() <= max_size || max_size == 0 {
                bytes.extend_from_slice(data);
            } else {
                return None;
            }
        }
    }
    bytes.into()
}

pub trait ToHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl<T: serde::Serialize> ToHttpResponse for JsonResponse<T> {
    fn into_http_response(self) -> HttpResponse {
        hyper::Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(
                Full::new(Bytes::from(serde_json::to_string(&self.inner).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for store::Error {
    fn into_http_response(self) -> HttpResponse {
        tracing::error!(context = "store", error = %self, "Database error");

        RequestError::internal_server_error().into_http_response()
    }
}

impl ToHttpResponse for std::io::Error {
    fn into_http_response(self) -> HttpResponse {
        tracing::error!(context = "i/o", error = %self, "I/O error");

        RequestError::internal_server_error().into_http_response()
    }
}

impl ToHttpResponse for serde_json::Error {
    fn into_http_response(self) -> HttpResponse {
        RequestError::blank(
            StatusCode::BAD_REQUEST.as_u16(),
            "Invalid parameters",
            format!("Failed to deserialize JSON: {self}"),
        )
        .into_http_response()
    }
}

impl<T: serde::Serialize> JsonResponse<T> {
    pub fn new(inner: T) -> Self {
        JsonResponse {
            inner,
            status: StatusCode::OK,
        }
    }

    pub fn with_status(status: StatusCode, inner: T) -> Self {
        JsonResponse { inner, status }
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

impl ToHttpResponse for Response {
    fn into_http_response(self) -> HttpResponse {
        //let c = println!("-> {}", serde_json::to_string_pretty(&self).unwrap());
        JsonResponse::new(self).into_http_response()
    }
}

impl ToHttpResponse for Session {
    fn into_http_response(self) -> HttpResponse {
        //let c = println!("-> {}", serde_json::to_string_pretty(&self).unwrap());
        JsonResponse::new(self).into_http_response()
    }
}

impl ToHttpResponse for DownloadResponse {
    fn into_http_response(self) -> HttpResponse {
        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, self.content_type)
            .header(
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}\"",
                    self.filename.replace('\"', "\\\"")
                ),
            )
            .header(
                header::CACHE_CONTROL,
                "private, immutable, max-age=31536000",
            )
            .body(
                Full::new(Bytes::from(self.blob))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for Resource<Vec<u8>> {
    fn into_http_response(self) -> HttpResponse {
        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, self.content_type)
            .body(
                Full::new(Bytes::from(self.contents))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for UploadResponse {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

impl ToHttpResponse for RequestError {
    fn into_http_response(self) -> HttpResponse {
        hyper::Response::builder()
            .status(StatusCode::from_u16(self.status).unwrap())
            .header(header::CONTENT_TYPE, "application/problem+json")
            .body(
                Full::new(Bytes::from(serde_json::to_string(&self).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for HtmlResponse {
    fn into_http_response(self) -> HttpResponse {
        hyper::Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(
                Full::new(Bytes::from(self.body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for StatusCode {
    fn into_http_response(self) -> HttpResponse {
        hyper::Response::builder()
            .status(self)
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}
