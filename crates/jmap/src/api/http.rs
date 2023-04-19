use std::sync::Arc;

use http_body_util::{combinators::BoxBody, BodyExt, Full};
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
    blob::{DownloadResponse, UploadResponse},
    JMAP,
};

use super::session::Session;

impl JMAP {
    pub async fn parse_request(
        &self,
        req: &mut hyper::Request<hyper::body::Incoming>,
        instance: &ServerInstance,
    ) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let mut path = req.uri().path().split('/');
        path.next();
        match path.next().unwrap_or("") {
            "jmap" => match (path.next().unwrap_or(""), req.method()) {
                ("", &Method::POST) => {
                    return match fetch_body(req, self.config.request_max_size).await {
                        Ok(bytes) => match self.handle_request(&bytes).await {
                            Ok(response) => response.into_http_response(),
                            Err(err) => err.into_http_response(),
                        },
                        Err(err) => err.into_http_response(),
                    }
                }
                ("download", &Method::GET) => {
                    if let (Some(account_id), Some(blob_id), Some(name)) = (
                        path.next().and_then(|p| Id::from_bytes(p.as_bytes())),
                        path.next()
                            .and_then(|p| BlobId::from_iter(&mut p.as_bytes().iter())),
                        path.next(),
                    ) {
                        return match self.blob_download(&blob_id, account_id.document_id()).await {
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
                    if let Some(account_id) = path.next().and_then(|p| Id::from_bytes(p.as_bytes()))
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
                    todo!()
                }
                ("ws", &Method::GET) => {
                    todo!()
                }
                _ => (),
            },
            ".well-known" => match (path.next().unwrap_or(""), req.method()) {
                ("jmap", &Method::GET) => {
                    return match self.handle_session_resource(instance).await {
                        Ok(session) => session.into_http_response(),
                        Err(err) => err.into_http_response(),
                    };
                }
                ("oauth-authorization-server", &Method::GET) => {
                    todo!()
                }
                _ => (),
            },
            "auth" => match (path.next().unwrap_or(""), req.method()) {
                ("", &Method::GET) => {
                    todo!()
                }
                ("", &Method::POST) => {
                    todo!()
                }
                ("code", &Method::GET) => {
                    todo!()
                }
                ("code", &Method::POST) => {
                    todo!()
                }
                ("device", &Method::POST) => {
                    todo!()
                }
                ("token", &Method::POST) => {
                    todo!()
                }
                _ => (),
            },
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

    fn max_concurrent(&self) -> u64 {
        self.inner.config.request_max_concurrent_total
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
                    let response = jmap.parse_request(&mut req, &instance).await;

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

async fn fetch_body(
    req: &mut hyper::Request<hyper::body::Incoming>,
    max_size: usize,
) -> Result<Vec<u8>, RequestError> {
    let mut bytes = Vec::with_capacity(1024);
    while let Some(Ok(frame)) = req.frame().await {
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() < max_size {
                bytes.extend_from_slice(data);
            } else {
                return Err(RequestError::limit(RequestLimitError::Size));
            }
        }
    }
    Ok(bytes)
}

trait ToHttpResponse {
    fn into_http_response(self) -> hyper::Response<BoxBody<Bytes, hyper::Error>>;
}

impl ToHttpResponse for Response {
    fn into_http_response(self) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let delete = "";
        println!("-> {}", serde_json::to_string_pretty(&self).unwrap());
        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(
                Full::new(Bytes::from(serde_json::to_string(&self).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for Session {
    fn into_http_response(self) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let delete = "";
        println!("-> {}", serde_json::to_string_pretty(&self).unwrap());
        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(
                Full::new(Bytes::from(serde_json::to_string(&self).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for DownloadResponse {
    fn into_http_response(self) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
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
    fn into_http_response(self) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let delete = "";
        println!("-> {}", serde_json::to_string_pretty(&self).unwrap());

        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(
                Full::new(Bytes::from(serde_json::to_string(&self).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl ToHttpResponse for RequestError {
    fn into_http_response(self) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let delete = "";
        println!("-> {}", serde_json::to_string_pretty(&self).unwrap());

        hyper::Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(
                Full::new(Bytes::from(serde_json::to_string(&self).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}
