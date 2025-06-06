/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc};

use common::{
    Inner, KV_ACME, Server,
    auth::{AccessToken, oauth::GrantType},
    core::BuildServer,
    ipc::StateEvent,
    listener::{SessionData, SessionManager, SessionStream},
    manager::webadmin::Resource,
};
use dav::{DavMethod, request::DavRequestHandler};
use directory::Permission;
use groupware::DavResourceName;
use http_proto::{
    DownloadResponse, HttpContext, HttpRequest, HttpResponse, HttpResponseBody, HttpSessionData,
    JsonProblemResponse, ToHttpResponse, form_urlencoded, request::fetch_body,
};
use hyper::{
    Method, StatusCode, body,
    header::{self, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use jmap::{
    api::{
        ToJmapHttpResponse, event_source::EventSourceHandler, request::RequestHandler,
        session::SessionHandler,
    },
    blob::{download::BlobDownload, upload::BlobUpload},
    websocket::upgrade::WebSocketUpgrade,
};
use jmap_proto::{
    request::{Request, capability::Session},
    types::{blob::BlobId, id::Id},
};
use store::dispatch::lookup::KeyValue;
use trc::SecurityEvent;
use utils::url_params::UrlParams;

use crate::{
    HttpSessionManager,
    auth::{
        authenticate::{Authenticator, HttpHeaders},
        oauth::{
            FormData, auth::OAuthApiHandler, openid::OpenIdHandler,
            registration::ClientRegistrationHandler, token::TokenHandler,
        },
    },
    autoconfig::Autoconfig,
    form::FormHandler,
    management::{ManagementApi, ToManageHttpResponse, troubleshoot::TroubleshootApi},
};

pub trait ParseHttp: Sync + Send {
    fn parse_http_request(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ParseHttp for Server {
    async fn parse_http_request(
        &self,
        mut req: HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let mut path = req.uri().path().split('/');
        path.next();

        // Validate endpoint access
        let ctx = HttpContext::new(&session, &req);
        match ctx.has_endpoint_access(self).await {
            StatusCode::OK => (),
            status => {
                // Allow loopback address to avoid lockouts
                if !session.remote_ip.is_loopback() {
                    return Ok(JsonProblemResponse(status).into_http_response());
                }
            }
        }

        match path.next().unwrap_or_default() {
            "jmap" => {
                match (path.next().unwrap_or_default(), req.method()) {
                    ("", &Method::POST) => {
                        // Authenticate request
                        let (_in_flight, access_token) =
                            self.authenticate_headers(&req, &session, false).await?;

                        let request = fetch_body(
                            &mut req,
                            if !access_token.has_permission(Permission::UnlimitedUploads) {
                                self.core.jmap.upload_max_size
                            } else {
                                0
                            },
                            session.session_id,
                        )
                        .await
                        .ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())
                        .and_then(|bytes| {
                            Request::parse(
                                &bytes,
                                self.core.jmap.request_max_calls,
                                self.core.jmap.request_max_size,
                            )
                        })?;

                        return Ok(self
                            .handle_jmap_request(request, access_token, &session)
                            .await
                            .into_http_response());
                    }
                    ("download", &Method::GET) => {
                        // Authenticate request
                        let (_in_flight, access_token) =
                            self.authenticate_headers(&req, &session, false).await?;

                        if let (Some(_), Some(blob_id), Some(name)) = (
                            path.next().and_then(|p| Id::from_bytes(p.as_bytes())),
                            path.next().and_then(BlobId::from_base32),
                            path.next(),
                        ) {
                            return match self.blob_download(&blob_id, &access_token).await? {
                                Some(blob) => Ok(DownloadResponse {
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
                                .into_http_response()),
                                None => Err(trc::ResourceEvent::NotFound.into_err()),
                            };
                        }
                    }
                    ("upload", &Method::POST) => {
                        // Authenticate request
                        let (_in_flight, access_token) =
                            self.authenticate_headers(&req, &session, false).await?;

                        if let Some(account_id) =
                            path.next().and_then(|p| Id::from_bytes(p.as_bytes()))
                        {
                            return match fetch_body(
                                &mut req,
                                if !access_token.has_permission(Permission::UnlimitedUploads) {
                                    self.core.jmap.upload_max_size
                                } else {
                                    0
                                },
                                session.session_id,
                            )
                            .await
                            {
                                Some(bytes) => Ok(self
                                    .blob_upload(
                                        account_id,
                                        req.headers()
                                            .get(CONTENT_TYPE)
                                            .and_then(|h| h.to_str().ok())
                                            .unwrap_or("application/octet-stream"),
                                        &bytes,
                                        access_token,
                                    )
                                    .await?
                                    .into_http_response()),
                                None => Err(trc::LimitEvent::SizeUpload.into_err()),
                            };
                        }
                    }
                    ("eventsource", &Method::GET) => {
                        // Authenticate request
                        let (_in_flight, access_token) =
                            self.authenticate_headers(&req, &session, false).await?;

                        return self.handle_event_source(req, access_token).await;
                    }
                    ("ws", &Method::GET) => {
                        // Authenticate request
                        let (_in_flight, access_token) =
                            self.authenticate_headers(&req, &session, false).await?;

                        return self
                            .upgrade_websocket_connection(req, access_token, session)
                            .await;
                    }
                    ("session", &Method::GET) => {
                        return if req.headers().contains_key(header::AUTHORIZATION) {
                            // Authenticate request
                            let (_in_flight, access_token) =
                                self.authenticate_headers(&req, &session, false).await?;

                            self.handle_session_resource(
                                ctx.resolve_response_url(self).await,
                                access_token,
                            )
                            .await
                            .map(|s| s.into_http_response())
                        } else {
                            Ok(Session::new(
                                ctx.resolve_response_url(self).await,
                                &self.core.jmap.capabilities,
                            )
                            .into_http_response())
                        };
                    }
                    (_, &Method::OPTIONS) => {
                        return Ok(JsonProblemResponse(StatusCode::NO_CONTENT).into_http_response());
                    }
                    _ => (),
                }
            }
            "dav" => {
                let response = match (
                    path.next().and_then(DavResourceName::parse),
                    DavMethod::parse(req.method()),
                ) {
                    (Some(_), Some(DavMethod::OPTIONS)) => HttpResponse::new(StatusCode::OK)
                        .with_header(
                            "DAV",
                            concat!(
                                "1, 2, 3, access-control, extended-mkcol, calendar-access, ",
                                "calendar-no-timezone, addressbook"
                            ),
                        )
                        .with_header(
                            "Allow",
                            concat!(
                                "OPTIONS, GET, HEAD, POST, PUT, DELETE, COPY, MOVE, MKCALENDAR, ",
                                "MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, REPORT, ACL"
                            ),
                        ),
                    (Some(resource), Some(method)) => {
                        // Authenticate request
                        let (_in_flight, access_token) =
                            self.authenticate_headers(&req, &session, false).await?;

                        self.handle_dav_request(req, access_token, &session, resource, method)
                            .await
                    }
                    (_, None) => HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED),
                    (None, _) => HttpResponse::new(StatusCode::NOT_FOUND),
                };

                return Ok(response);
            }
            ".well-known" => match (path.next().unwrap_or_default(), req.method()) {
                ("jmap", &Method::GET) => {
                    return Ok(HttpResponse::new(StatusCode::TEMPORARY_REDIRECT)
                        .with_no_cache()
                        .with_location("/jmap/session"));
                }
                ("caldav", _) => {
                    return Ok(HttpResponse::new(StatusCode::TEMPORARY_REDIRECT)
                        .with_no_cache()
                        .with_location(DavResourceName::Cal.base_path()));
                }
                ("carddav", _) => {
                    return Ok(HttpResponse::new(StatusCode::TEMPORARY_REDIRECT)
                        .with_no_cache()
                        .with_location(DavResourceName::Card.base_path()));
                }
                ("oauth-authorization-server", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self.handle_oauth_metadata(req, session).await;
                }
                ("openid-configuration", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self.handle_oidc_metadata(req, session).await;
                }
                ("acme-challenge", &Method::GET) if self.has_acme_http_providers() => {
                    if let Some(token) = path.next() {
                        return match self
                            .core
                            .storage
                            .lookup
                            .key_get::<String>(KeyValue::<()>::build_key(KV_ACME, token))
                            .await?
                        {
                            Some(proof) => Ok(Resource::new("text/plain", proof.into_bytes())
                                .into_http_response()),
                            None => Err(trc::ResourceEvent::NotFound.into_err()),
                        };
                    }
                }
                ("mta-sts.txt", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return if let Some(policy) = self.build_mta_sts_policy() {
                        Ok(Resource::new("text/plain", policy.to_string().into_bytes())
                            .into_http_response())
                    } else {
                        Err(trc::ResourceEvent::NotFound.into_err())
                    };
                }
                ("mail-v1.xml", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self.handle_autoconfig_request(&req).await;
                }
                ("autoconfig", &Method::GET) => {
                    if path.next().unwrap_or_default() == "mail"
                        && path.next().unwrap_or_default() == "config-v1.1.xml"
                    {
                        // Limit anonymous requests
                        self.is_http_anonymous_request_allowed(&session.remote_ip)
                            .await?;

                        return self.handle_autoconfig_request(&req).await;
                    }
                }
                (_, &Method::OPTIONS) => {
                    return Ok(JsonProblemResponse(StatusCode::NO_CONTENT).into_http_response());
                }
                _ => (),
            },
            "auth" => match (path.next().unwrap_or_default(), req.method()) {
                ("device", &Method::POST) => {
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self.handle_device_auth(&mut req, session).await;
                }
                ("token", &Method::POST) => {
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self.handle_token_request(&mut req, session).await;
                }
                ("introspect", &Method::POST) => {
                    // Authenticate request
                    let (_in_flight, access_token) =
                        self.authenticate_headers(&req, &session, false).await?;

                    return self
                        .handle_token_introspect(&mut req, &access_token, session.session_id)
                        .await;
                }
                ("userinfo", &Method::GET) => {
                    // Authenticate request
                    let (_in_flight, access_token) =
                        self.authenticate_headers(&req, &session, false).await?;

                    return self.handle_userinfo_request(&access_token).await;
                }
                ("register", &Method::POST) => {
                    return self
                        .handle_oauth_registration_request(&mut req, session)
                        .await;
                }
                ("jwks.json", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return Ok(self.core.oauth.oidc_jwks.clone().into_http_response());
                }
                (_, &Method::OPTIONS) => {
                    return Ok(JsonProblemResponse(StatusCode::NO_CONTENT).into_http_response());
                }
                _ => (),
            },
            "api" => {
                // Allow CORS preflight requests
                if req.method() == Method::OPTIONS {
                    return Ok(JsonProblemResponse(StatusCode::NO_CONTENT).into_http_response());
                }

                // Authenticate user
                match self.authenticate_headers(&req, &session, true).await {
                    Ok((_, access_token)) => {
                        return self
                            .handle_api_manage_request(&mut req, access_token, &session)
                            .await;
                    }
                    Err(err) => {
                        if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
                            let params = UrlParams::new(req.uri().query());
                            let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();

                            let (grant_type, token) = match (
                                path.first().copied(),
                                path.get(1).copied(),
                                params.get("token"),
                            ) {
                                // SPDX-SnippetBegin
                                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                                // SPDX-License-Identifier: LicenseRef-SEL
                                #[cfg(feature = "enterprise")]
                                (Some("telemetry"), Some("traces"), Some(token))
                                    if self.core.is_enterprise_edition() =>
                                {
                                    (GrantType::LiveTracing, token)
                                }
                                #[cfg(feature = "enterprise")]
                                (Some("telemetry"), Some("metrics"), Some(token))
                                    if self.core.is_enterprise_edition() =>
                                {
                                    (GrantType::LiveMetrics, token)
                                }
                                // SPDX-SnippetEnd
                                (Some("troubleshoot"), _, Some(token)) => {
                                    (GrantType::Troubleshoot, token)
                                }
                                _ => return Err(err),
                            };
                            let token_info =
                                self.validate_access_token(grant_type.into(), token).await?;

                            return match grant_type {
                                // SPDX-SnippetBegin
                                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                                // SPDX-License-Identifier: LicenseRef-SEL
                                #[cfg(feature = "enterprise")]
                                GrantType::LiveTracing | GrantType::LiveMetrics => {
                                    use crate::management::enterprise::telemetry::TelemetryApi;
                                    self.handle_telemetry_api_request(
                                        &req,
                                        path,
                                        &AccessToken::from_id(token_info.account_id)
                                            .with_permission(Permission::MetricsLive)
                                            .with_permission(Permission::TracingLive),
                                    )
                                    .await
                                }
                                // SPDX-SnippetEnd
                                GrantType::Troubleshoot => {
                                    self.handle_troubleshoot_api_request(
                                        &req,
                                        path,
                                        &AccessToken::from_id(token_info.account_id)
                                            .with_permission(Permission::Troubleshoot),
                                        None,
                                    )
                                    .await
                                }
                                _ => unreachable!(),
                            };
                        }

                        return Err(err);
                    }
                }
            }
            "mail" => {
                if req.method() == Method::GET
                    && path.next().unwrap_or_default() == "config-v1.1.xml"
                {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self.handle_autoconfig_request(&req).await;
                }
            }
            "autodiscover" => {
                if req.method() == Method::POST
                    && path.next().unwrap_or_default() == "autodiscover.xml"
                {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(&session.remote_ip)
                        .await?;

                    return self
                        .handle_autodiscover_request(
                            fetch_body(&mut req, 8192, session.session_id).await,
                        )
                        .await;
                }
            }
            "robots.txt" => {
                // Limit anonymous requests
                self.is_http_anonymous_request_allowed(&session.remote_ip)
                    .await?;

                return Ok(
                    Resource::new("text/plain", b"User-agent: *\nDisallow: /\n".to_vec())
                        .into_http_response(),
                );
            }
            "healthz" => {
                // Limit anonymous requests
                self.is_http_anonymous_request_allowed(&session.remote_ip)
                    .await?;

                match path.next().unwrap_or_default() {
                    "live" => {
                        return Ok(JsonProblemResponse(StatusCode::OK).into_http_response());
                    }
                    "ready" => {
                        return Ok(JsonProblemResponse({
                            if !self.core.storage.data.is_none() {
                                StatusCode::OK
                            } else {
                                StatusCode::SERVICE_UNAVAILABLE
                            }
                        })
                        .into_http_response());
                    }
                    _ => (),
                }
            }
            "metrics" => match path.next().unwrap_or_default() {
                "prometheus" => {
                    if let Some(prometheus) = &self.core.metrics.prometheus {
                        if let Some(auth) = &prometheus.auth {
                            if req
                                .authorization_basic()
                                .is_none_or(|secret| secret != auth)
                            {
                                return Err(trc::AuthEvent::Failed
                                    .into_err()
                                    .details("Invalid or missing credentials.")
                                    .caused_by(trc::location!()));
                            }
                        }

                        return Ok(Resource::new(
                            "text/plain; version=0.0.4",
                            self.export_prometheus_metrics().await?.into_bytes(),
                        )
                        .into_http_response());
                    }
                }
                "otel" => {
                    // Reserved for future use
                }
                _ => (),
            },
            #[cfg(feature = "enterprise")]
            "logo.svg" if self.is_enterprise_edition() => {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                match self
                    .logo_resource(
                        req.headers()
                            .get(header::HOST)
                            .and_then(|h| h.to_str().ok())
                            .map(|h| h.rsplit_once(':').map_or(h, |(h, _)| h))
                            .unwrap_or_default(),
                    )
                    .await
                {
                    Ok(Some(resource)) => {
                        return Ok(resource.into_http_response());
                    }
                    Ok(None) => (),
                    Err(err) => {
                        trc::error!(err.span_id(session.session_id));
                    }
                }

                let resource = self.inner.data.webadmin.get("logo.svg").await?;

                if !resource.is_empty() {
                    return Ok(resource.into_http_response());
                }

                // SPDX-SnippetEnd
            }
            "form" => {
                if let Some(form) = &self.core.network.contact_form {
                    match *req.method() {
                        Method::POST => {
                            self.is_http_anonymous_request_allowed(&session.remote_ip)
                                .await?;

                            let form_data =
                                FormData::from_request(&mut req, form.max_size, session.session_id)
                                    .await?;

                            return self.handle_contact_form(&session, form, form_data).await;
                        }
                        Method::OPTIONS => {
                            return Ok(
                                JsonProblemResponse(StatusCode::NO_CONTENT).into_http_response()
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                let path = req.uri().path();
                let resource = self
                    .inner
                    .data
                    .webadmin
                    .get(path.strip_prefix('/').unwrap_or(path))
                    .await?;

                if !resource.is_empty() {
                    return Ok(resource.into_http_response());
                }
            }
        }

        // Block dangerous URLs
        let path = req.uri().path();
        if self.is_http_banned_path(path, session.remote_ip).await? {
            trc::event!(
                Security(SecurityEvent::ScanBan),
                SpanId = session.session_id,
                RemoteIp = session.remote_ip,
                Path = path.to_string(),
            );
        }

        Err(trc::ResourceEvent::NotFound.into_err())
    }
}

async fn handle_session<T: SessionStream>(inner: Arc<Inner>, session: SessionData<T>) {
    let _in_flight = session.in_flight;
    let is_tls = session.stream.is_tls();

    if let Err(http_err) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(session.stream),
            service_fn(|req: hyper::Request<body::Incoming>| {
                let instance = session.instance.clone();
                let inner = inner.clone();

                async move {
                    let server = inner.build_server();

                    // Obtain remote IP
                    let remote_ip = if !server.core.jmap.http_use_forwarded {
                        trc::event!(
                            Http(trc::HttpEvent::RequestUrl),
                            SpanId = session.session_id,
                            Url = req.uri().to_string(),
                        );

                        session.remote_ip
                    } else if let Some(forwarded_for) = req
                        .headers()
                        .get(header::FORWARDED)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|h| {
                            let h = h.to_ascii_lowercase();
                            h.split_once("for=").and_then(|(_, rest)| {
                                let mut start_ip = usize::MAX;
                                let mut end_ip = usize::MAX;

                                for (pos, ch) in rest.char_indices() {
                                    match ch {
                                        '0'..='9' | 'a'..='f' | ':' | '.' => {
                                            if start_ip == usize::MAX {
                                                start_ip = pos;
                                            }
                                            end_ip = pos;
                                        }
                                        '"' | '[' | ' ' if start_ip == usize::MAX => {}
                                        _ => {
                                            break;
                                        }
                                    }
                                }

                                rest.get(start_ip..=end_ip)
                                    .and_then(|h| h.parse::<IpAddr>().ok())
                            })
                        })
                        .or_else(|| {
                            req.headers()
                                .get("X-Forwarded-For")
                                .and_then(|h| h.to_str().ok())
                                .map(|h| h.split_once(',').map_or(h, |(ip, _)| ip).trim())
                                .and_then(|h| h.parse::<IpAddr>().ok())
                        })
                    {
                        // Check if the forwarded IP has been blocked
                        if server.is_ip_blocked(&forwarded_for) {
                            trc::event!(
                                Security(trc::SecurityEvent::IpBlocked),
                                ListenerId = instance.id.clone(),
                                RemoteIp = forwarded_for,
                                SpanId = session.session_id,
                            );

                            return Ok::<_, hyper::Error>(
                                JsonProblemResponse(StatusCode::FORBIDDEN)
                                    .into_http_response()
                                    .build(),
                            );
                        }

                        trc::event!(
                            Http(trc::HttpEvent::RequestUrl),
                            SpanId = session.session_id,
                            RemoteIp = forwarded_for,
                            Url = req.uri().to_string(),
                        );

                        forwarded_for
                    } else {
                        trc::event!(
                            Http(trc::HttpEvent::XForwardedMissing),
                            SpanId = session.session_id,
                        );
                        session.remote_ip
                    };

                    // Parse HTTP request
                    let response = match Box::pin(server.parse_http_request(
                        req,
                        HttpSessionData {
                            instance,
                            local_ip: session.local_ip,
                            local_port: session.local_port,
                            remote_ip,
                            remote_port: session.remote_port,
                            is_tls,
                            session_id: session.session_id,
                        },
                    ))
                    .await
                    {
                        Ok(response) => response,
                        Err(err) => {
                            let response = err.into_http_response();
                            trc::error!(err.span_id(session.session_id));
                            response
                        }
                    };

                    trc::event!(
                        Http(trc::HttpEvent::ResponseBody),
                        SpanId = session.session_id,
                        Contents = match response.body() {
                            HttpResponseBody::Text(value) =>
                                trc::Value::String(value.as_str().into()),
                            HttpResponseBody::Binary(_) =>
                                trc::Value::String("[binary data]".into()),
                            HttpResponseBody::Stream(_) => trc::Value::String("[stream]".into()),
                            _ => trc::Value::None,
                        },
                        Code = response.status().as_u16(),
                        Size = response.size(),
                    );

                    // Build response
                    let mut response = response.build();

                    // Add custom headers
                    if !server.core.jmap.http_headers.is_empty() {
                        let headers = response.headers_mut();

                        for (header, value) in &server.core.jmap.http_headers {
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
        match inner
            .build_server()
            .is_scanner_fail2banned(session.remote_ip)
            .await
        {
            Ok(true) => {
                trc::event!(
                    Security(SecurityEvent::ScanBan),
                    SpanId = session.session_id,
                    RemoteIp = session.remote_ip,
                    Reason = http_err.to_string(),
                );
            }
            Ok(false) => {
                trc::event!(
                    Http(trc::HttpEvent::Error),
                    SpanId = session.session_id,
                    Reason = http_err.to_string(),
                );
            }
            Err(err) => {
                trc::error!(
                    err.span_id(session.session_id)
                        .details("Failed to check for fail2ban")
                );
            }
        }
    }
}

impl SessionManager for HttpSessionManager {
    fn handle<T: SessionStream>(self, session: SessionData<T>) -> impl Future<Output = ()> + Send {
        handle_session(self.inner, session)
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {
            let _ = self.inner.ipc.state_tx.send(StateEvent::Stop).await;
        }
    }
}
