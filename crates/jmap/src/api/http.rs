use std::{net::IpAddr, sync::Arc};

use http_body_util::{BodyExt, Full};
use hyper::{
    body::{self, Bytes},
    header::{self, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
    Method, StatusCode,
};
use jmap_proto::{
    error::request::{RequestError, RequestLimitError},
    response::Response,
    types::{blob::BlobId, id::Id},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use utils::listener::{ServerInstance, SessionData, SessionManager};

use crate::{
    auth::oauth::OAuthMetadata,
    blob::{DownloadResponse, UploadResponse},
    JMAP,
};

use super::{session::Session, HtmlResponse, HttpResponse, JsonResponse};

impl JMAP {
    pub async fn parse_request(
        &self,
        req: &mut hyper::Request<hyper::body::Incoming>,
        remote_ip: IpAddr,
        instance: &ServerInstance,
    ) -> HttpResponse {
        let mut path = req.uri().path().split('/');
        path.next();

        match path.next().unwrap_or("") {
            "jmap" => {
                // Authenticate request
                let (_in_flight, acl_token) = match self.authenticate_headers(req, remote_ip).await
                {
                    Ok(Some(session)) => session,
                    Ok(None) => return RequestError::unauthorized().into_http_response(),
                    Err(err) => return err.into_http_response(),
                };

                match (path.next().unwrap_or(""), req.method()) {
                    ("", &Method::POST) => {
                        return match fetch_body(req, self.config.request_max_size).await {
                            Ok(bytes) => {
                                //let delete = "fd";
                                //println!("<- {}", String::from_utf8_lossy(&bytes));

                                match self.handle_request(&bytes, acl_token).await {
                                    Ok(response) => response.into_http_response(),
                                    Err(err) => err.into_http_response(),
                                }
                            }
                            Err(err) => err.into_http_response(),
                        };
                    }
                    ("download", &Method::GET) => {
                        if let (Some(account_id), Some(blob_id), Some(name)) = (
                            path.next().and_then(|p| Id::from_bytes(p.as_bytes())),
                            path.next().and_then(BlobId::from_base32),
                            path.next(),
                        ) {
                            return match self.blob_download(&blob_id, &acl_token).await {
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
                                Err(err) => {
                                    tracing::error!(event = "error",
                                                    context = "blob_store",
                                                    account_id = account_id.document_id(),
                                                    blob_id = ?blob_id,
                                                    error = ?err,
                                                    "Failed to download blob");
                                    RequestError::internal_server_error().into_http_response()
                                }
                            };
                        }
                    }
                    ("upload", &Method::POST) => {
                        if let Some(account_id) =
                            path.next().and_then(|p| Id::from_bytes(p.as_bytes()))
                        {
                            return match fetch_body(req, self.config.upload_max_size).await {
                                Ok(bytes) => {
                                    match self
                                        .blob_upload(
                                            account_id,
                                            req.headers()
                                                .get(CONTENT_TYPE)
                                                .and_then(|h| h.to_str().ok())
                                                .unwrap_or("application/octet-stream"),
                                            &bytes,
                                        )
                                        .await
                                    {
                                        Ok(response) => response.into_http_response(),
                                        Err(err) => err.into_http_response(),
                                    }
                                }
                                Err(err) => err.into_http_response(),
                            };
                        }
                    }
                    ("eventsource", &Method::GET) => {
                        return self.handle_event_source(req, acl_token).await
                    }
                    ("ws", &Method::GET) => {
                        todo!()
                    }
                    _ => (),
                }
            }
            ".well-known" => match (path.next().unwrap_or(""), req.method()) {
                ("jmap", &Method::GET) => {
                    // Authenticate request
                    let (_in_flight, acl_token) =
                        match self.authenticate_headers(req, remote_ip).await {
                            Ok(Some(session)) => session,
                            Ok(None) => return RequestError::unauthorized().into_http_response(),
                            Err(err) => return err.into_http_response(),
                        };

                    return match self.handle_session_resource(instance, acl_token).await {
                        Ok(session) => session.into_http_response(),
                        Err(err) => err.into_http_response(),
                    };
                }
                ("oauth-authorization-server", &Method::GET) => {
                    let remote_addr = self.build_remote_addr(req, remote_ip);
                    // Limit anonymous requests
                    return match self.is_anonymous_allowed(remote_addr) {
                        Ok(_) => JsonResponse::new(OAuthMetadata::new(&instance.data))
                            .into_http_response(),
                        Err(err) => err.into_http_response(),
                    };
                }
                _ => (),
            },
            "auth" => {
                let remote_addr = self.build_remote_addr(req, remote_ip);

                match (path.next().unwrap_or(""), req.method()) {
                    ("", &Method::GET) => {
                        return match self.is_anonymous_allowed(remote_addr) {
                            Ok(_) => self.handle_user_device_auth(req).await,
                            Err(err) => err.into_http_response(),
                        }
                    }
                    ("", &Method::POST) => {
                        return match self.is_auth_allowed(remote_addr) {
                            Ok(_) => self.handle_user_device_auth_post(req).await,
                            Err(err) => err.into_http_response(),
                        }
                    }
                    ("code", &Method::GET) => {
                        return match self.is_anonymous_allowed(remote_addr) {
                            Ok(_) => self.handle_user_code_auth(req).await,
                            Err(err) => err.into_http_response(),
                        }
                    }
                    ("code", &Method::POST) => {
                        return match self.is_auth_allowed(remote_addr) {
                            Ok(_) => self.handle_user_code_auth_post(req).await,
                            Err(err) => err.into_http_response(),
                        }
                    }
                    ("device", &Method::POST) => {
                        return match self.is_anonymous_allowed(remote_addr) {
                            Ok(_) => self.handle_device_auth(req, instance).await,
                            Err(err) => err.into_http_response(),
                        }
                    }
                    ("token", &Method::POST) => {
                        return match self.is_anonymous_allowed(remote_addr) {
                            Ok(_) => self.handle_token_request(req).await,
                            Err(err) => err.into_http_response(),
                        }
                    }
                    _ => (),
                }
            }
            _ => (),
        }
        RequestError::not_found().into_http_response()
    }
}

impl SessionManager for super::SessionManager {
    fn spawn(&self, session: SessionData<TcpStream>) {
        let jmap = self.inner.clone();

        tokio::spawn(async move {
            if let Some(tls_acceptor) = &session.instance.tls_acceptor {
                let span = session.span;
                match tls_acceptor.accept(session.stream).await {
                    Ok(stream) => {
                        handle_request(
                            jmap,
                            SessionData {
                                stream,
                                local_ip: session.local_ip,
                                remote_ip: session.remote_ip,
                                span,
                                in_flight: session.in_flight,
                                instance: session.instance,
                            },
                        )
                        .await;
                    }
                    Err(err) => {
                        tracing::debug!(
                            parent: &span,
                            context = "tls",
                            event = "error",
                            "Failed to accept TLS connection: {}",
                            err
                        );
                    }
                }
            } else {
                handle_request(jmap, session).await;
            }
        });
    }
}

async fn handle_request<T: AsyncRead + AsyncWrite + Unpin + 'static>(
    jmap: Arc<JMAP>,
    session: SessionData<T>,
) {
    let span = session.span;
    let _in_flight = session.in_flight;

    if let Err(http_err) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            session.stream,
            service_fn(|mut req: hyper::Request<body::Incoming>| {
                let jmap = jmap.clone();
                let span = span.clone();
                let instance = session.instance.clone();

                async move {
                    let response = jmap
                        .parse_request(&mut req, session.remote_ip, &instance)
                        .await;

                    tracing::debug!(
                        parent: &span,
                        event = "request",
                        uri = req.uri().to_string(),
                        status = response.status().to_string(),
                    );

                    Ok::<_, hyper::Error>(response)
                }
            }),
        )
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

pub async fn fetch_body(
    req: &mut hyper::Request<hyper::body::Incoming>,
    max_size: usize,
) -> Result<Vec<u8>, RequestError> {
    let mut bytes = Vec::with_capacity(1024);
    while let Some(Ok(frame)) = req.frame().await {
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() <= max_size {
                bytes.extend_from_slice(data);
            } else {
                return Err(RequestError::limit(RequestLimitError::Size));
            }
        }
    }
    Ok(bytes)
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
        //let delete = "";
        //println!("-> {}", serde_json::to_string_pretty(&self).unwrap());
        JsonResponse::new(self).into_http_response()
    }
}

impl ToHttpResponse for Session {
    fn into_http_response(self) -> HttpResponse {
        //let delete = "";
        //println!("-> {}", serde_json::to_string_pretty(&self).unwrap());
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
