/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{net::IpAddr, sync::Arc};

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
    request::Request,
    response::Response,
    types::{blob::BlobId, id::Id},
};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use utils::listener::{ServerInstance, SessionData, SessionManager};

use crate::{
    auth::{oauth::OAuthMetadata, AccessToken},
    blob::{DownloadResponse, UploadResponse},
    services::state,
    websocket::upgrade::upgrade_websocket_connection,
    JMAP,
};

use super::{
    session::Session, HtmlResponse, HttpRequest, HttpResponse, JmapSessionManager, JsonResponse,
};

pub async fn parse_jmap_request(
    jmap: Arc<JMAP>,
    mut req: HttpRequest,
    remote_ip: IpAddr,
    instance: Arc<ServerInstance>,
) -> HttpResponse {
    let mut path = req.uri().path().split('/');
    path.next();

    match path.next().unwrap_or("") {
        "jmap" => {
            // Authenticate request
            let (_in_flight, access_token) = match jmap.authenticate_headers(&req, remote_ip).await
            {
                Ok(Some(session)) => session,
                Ok(None) => return RequestError::unauthorized().into_http_response(),
                Err(err) => return err.into_http_response(),
            };

            match (path.next().unwrap_or(""), req.method()) {
                ("", &Method::POST) => {
                    return match fetch_body(&mut req, jmap.config.request_max_size, &access_token)
                        .await
                        .ok_or_else(|| RequestError::limit(RequestLimitError::SizeRequest))
                        .and_then(|bytes| {
                            Request::parse(
                                &bytes,
                                jmap.config.request_max_calls,
                                jmap.config.request_max_size,
                            )
                        }) {
                        Ok(request) => {
                            //let _ = println!("<- {}", String::from_utf8_lossy(&bytes));

                            match jmap.handle_request(request, access_token, &instance).await {
                                Ok(response) => response.into_http_response(),
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
                        return match jmap.blob_download(&blob_id, &access_token).await {
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
                            Err(_) => RequestError::internal_server_error().into_http_response(),
                        };
                    }
                }
                ("upload", &Method::POST) => {
                    if let Some(account_id) = path.next().and_then(|p| Id::from_bytes(p.as_bytes()))
                    {
                        return match fetch_body(
                            &mut req,
                            jmap.config.upload_max_size,
                            &access_token,
                        )
                        .await
                        {
                            Some(bytes) => {
                                match jmap
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
                    return jmap.handle_event_source(req, access_token).await
                }
                ("ws", &Method::GET) => {
                    return upgrade_websocket_connection(jmap, req, access_token, instance.clone())
                        .await;
                }
                _ => (),
            }
        }
        ".well-known" => match (path.next().unwrap_or(""), req.method()) {
            ("jmap", &Method::GET) => {
                // Authenticate request
                let (_in_flight, access_token) =
                    match jmap.authenticate_headers(&req, remote_ip).await {
                        Ok(Some(session)) => session,
                        Ok(None) => return RequestError::unauthorized().into_http_response(),
                        Err(err) => return err.into_http_response(),
                    };

                return match jmap.handle_session_resource(instance, access_token).await {
                    Ok(session) => session.into_http_response(),
                    Err(err) => err.into_http_response(),
                };
            }
            ("oauth-authorization-server", &Method::GET) => {
                let remote_addr = jmap.build_remote_addr(&req, remote_ip);
                // Limit anonymous requests
                return match jmap.is_anonymous_allowed(remote_addr) {
                    Ok(_) => {
                        JsonResponse::new(OAuthMetadata::new(&instance.data)).into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                };
            }
            _ => (),
        },
        "auth" => {
            let remote_addr = jmap.build_remote_addr(&req, remote_ip);

            match (path.next().unwrap_or(""), req.method()) {
                ("", &Method::GET) => {
                    return match jmap.is_anonymous_allowed(remote_addr) {
                        Ok(_) => jmap.handle_user_device_auth(&mut req).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                ("", &Method::POST) => {
                    return match jmap.is_auth_allowed(remote_addr) {
                        Ok(_) => jmap.handle_user_device_auth_post(&mut req).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                ("code", &Method::GET) => {
                    return match jmap.is_anonymous_allowed(remote_addr) {
                        Ok(_) => jmap.handle_user_code_auth(&mut req).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                ("code", &Method::POST) => {
                    return match jmap.is_auth_allowed(remote_addr) {
                        Ok(_) => jmap.handle_user_code_auth_post(&mut req).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                ("device", &Method::POST) => {
                    return match jmap.is_anonymous_allowed(remote_addr) {
                        Ok(_) => jmap.handle_device_auth(&mut req, instance).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                ("token", &Method::POST) => {
                    return match jmap.is_anonymous_allowed(remote_addr) {
                        Ok(_) => jmap.handle_token_request(&mut req).await,
                        Err(err) => err.into_http_response(),
                    }
                }
                _ => (),
            }
        }

        "admin" => {
            // Make sure the user is a superuser
            match jmap.authenticate_headers(&req, remote_ip).await {
                Ok(Some((_, access_token))) if access_token.is_super_user() => (),
                Ok(_) => return RequestError::unauthorized().into_http_response(),
                Err(err) => return err.into_http_response(),
            }

            match (
                path.next().unwrap_or(""),
                path.next().unwrap_or(""),
                req.method(),
            ) {
                ("account", "delete", &Method::GET) => {
                    return if let Some(account_name) = path.next() {
                        if let Ok(Some(account_id)) = jmap.try_get_account_id(account_name).await {
                            match jmap.delete_account(account_name, account_id).await {
                                Ok(_) => JsonResponse::new(Value::String("success".into()))
                                    .into_http_response(),
                                Err(err) => RequestError::blank(
                                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                    "Account deletion failed",
                                    err.to_string(),
                                )
                                .into_http_response(),
                            }
                        } else {
                            RequestError::blank(
                                StatusCode::NOT_FOUND.as_u16(),
                                "Not found",
                                "Account not found.",
                            )
                            .into_http_response()
                        }
                    } else {
                        RequestError::blank(
                            StatusCode::BAD_REQUEST.as_u16(),
                            "Invalid parameters",
                            "Expected account name",
                        )
                        .into_http_response()
                    };
                }
                ("account", "rename", &Method::GET) => {
                    return if let (Some(account_name), Some(new_account_name)) =
                        (path.next(), path.next())
                    {
                        match (
                            jmap.try_get_account_id(account_name).await,
                            jmap.try_get_account_id(new_account_name).await,
                        ) {
                            (Ok(Some(account_id)), Ok(None)) => {
                                match jmap
                                    .rename_account(new_account_name, account_name, account_id)
                                    .await
                                {
                                    Ok(_) => JsonResponse::new(Value::String("success".into()))
                                        .into_http_response(),
                                    Err(err) => RequestError::blank(
                                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                        "Account rename failed",
                                        err.to_string(),
                                    )
                                    .into_http_response(),
                                }
                            }
                            (Ok(None), _) => RequestError::blank(
                                StatusCode::NOT_FOUND.as_u16(),
                                "Not found",
                                "Account not found.",
                            )
                            .into_http_response(),
                            (_, Ok(Some(_))) => RequestError::blank(
                                StatusCode::BAD_REQUEST.as_u16(),
                                "Invalid parameters",
                                "New account name already exists.",
                            )
                            .into_http_response(),
                            _ => RequestError::internal_server_error().into_http_response(),
                        }
                    } else {
                        RequestError::blank(
                            StatusCode::BAD_REQUEST.as_u16(),
                            "Invalid parameters",
                            "Expected old and new account names",
                        )
                        .into_http_response()
                    };
                }
                ("blob", "purge", &Method::GET) => {
                    return match jmap.store.purge_tmp_blobs(jmap.config.upload_tmp_ttl).await {
                        Ok(_) => {
                            JsonResponse::new(Value::String("success".into())).into_http_response()
                        }
                        Err(err) => RequestError::blank(
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                            "Purge blob failed",
                            err.to_string(),
                        )
                        .into_http_response(),
                    };
                }
                (path_1 @ ("queue" | "report"), path_2, &Method::GET) => {
                    return jmap
                        .smtp
                        .handle_manage_request(req.uri(), req.method(), path_1, path_2)
                        .await;
                }
                _ => (),
            }
        }
        _ => (),
    }
    RequestError::not_found().into_http_response()
}

impl SessionManager for JmapSessionManager {
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
                                remote_port: session.remote_port,
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

    fn shutdown(&self) {
        let jmap = self.inner.clone();
        tokio::spawn(async move {
            let _ = jmap.state_tx.send(state::Event::Stop).await;
        });
    }
}

async fn handle_request<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    jmap: Arc<JMAP>,
    session: SessionData<T>,
) {
    let span = session.span;
    let _in_flight = session.in_flight;

    if let Err(http_err) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(session.stream),
            service_fn(|req: hyper::Request<body::Incoming>| {
                let jmap = jmap.clone();
                let span = span.clone();
                let instance = session.instance.clone();

                async move {
                    tracing::debug!(
                        parent: &span,
                        event = "request",
                        uri = req.uri().to_string(),
                    );

                    let response = parse_jmap_request(jmap, req, session.remote_ip, instance).await;

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

pub async fn fetch_body(
    req: &mut HttpRequest,
    max_size: usize,
    access_token: &AccessToken,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    while let Some(Ok(frame)) = req.frame().await {
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() <= max_size || max_size == 0 || access_token.is_super_user()
            {
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
