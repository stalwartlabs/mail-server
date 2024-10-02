/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::sync::Arc;

use ahash::AHashMap;
use base64::{engine::general_purpose, Engine};
use common::{config::server::Listeners, listener::SessionData, Core, Data, Inner};
use directory::{backend::internal::PrincipalField, QueryBy};
use hyper::{body, server::conn::http1, service::service_fn, Method, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use jmap::api::{
    http::{fetch_body, ToHttpResponse},
    HttpResponse, JsonResponse,
};
use mail_send::Credentials;
use serde_json::json;
use tokio::sync::watch;
use trc::{AuthEvent, EventType};
use utils::config::Config;

use crate::{add_test_certs, directory::DirectoryTest, AssertConfig};

static TEST_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

#[tokio::test]
async fn oidc_directory() {
    // Obtain directory handle
    let mut config = DirectoryTest::new("rocksdb".into()).await;

    // Spawn mock OIDC server
    let _tx = spawn_mock_http_server(Arc::new(|req: HttpMessage| {
        let success_response = JsonResponse::new(json!({
            "email": "john@example.org",
            "preferred_username": "jdoe",
            "name": "John Doe",
        }))
        .into_http_response();

        match (req.method.clone(), req.uri.path().split('/').nth(1)) {
            (Method::GET, Some("userinfo")) => match req.headers.get("authorization") {
                Some(auth) if auth == &format!("Bearer {TEST_TOKEN}") => success_response,
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            (Method::POST, Some("introspect-none")) => {
                assert!(req.headers.get("authorization").is_none());
                if req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) {
                    success_response
                } else {
                    StatusCode::UNAUTHORIZED.into_http_response()
                }
            }
            (Method::POST, Some("introspect-user-token")) => match req.headers.get("authorization")
            {
                Some(auth)
                    if auth == &format!("Bearer {TEST_TOKEN}")
                        && req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) =>
                {
                    success_response
                }
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            (Method::POST, Some("introspect-token")) => match req.headers.get("authorization") {
                Some(auth)
                    if auth == "Bearer token_of_gratitude"
                        && req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) =>
                {
                    success_response
                }
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            (Method::POST, Some("introspect-basic")) => match req.headers.get("authorization") {
                Some(auth)
                    if auth
                        == &format!(
                            "Basic {}",
                            general_purpose::STANDARD.encode("myuser:mypass".as_bytes())
                        )
                        && req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) =>
                {
                    success_response
                }
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            _ => panic!("Unexpected request: {:?}", req),
        }
    }))
    .await;

    for test in [
        "oidc-userinfo",
        "oidc-introspect-none",
        "oidc-introspect-user-token",
        "oidc-introspect-token",
        "oidc-introspect-basic",
    ] {
        println!("Running OIDC test {test:?}...");
        let directory = config.directories.directories.remove(test).unwrap();

        // Test an invalid token
        let err = directory
            .query(
                QueryBy::Credentials(&Credentials::OAuthBearer {
                    token: "invalid_or_expired_token".to_string(),
                }),
                false,
            )
            .await
            .unwrap_err();
        assert!(
            err.matches(EventType::Auth(AuthEvent::Failed)),
            "Unexpected error: {:?}",
            err
        );

        // Test a valid token
        let principal = directory
            .query(
                QueryBy::Credentials(&Credentials::OAuthBearer {
                    token: TEST_TOKEN.to_string(),
                }),
                false,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.name(), "jdoe");
        assert_eq!(
            principal.get_str(PrincipalField::Emails),
            Some("john@example.org")
        );
        assert_eq!(principal.description(), Some("John Doe"));
    }
}

const MOCK_HTTP_SERVER: &str = r#"
[server]
hostname = "'oidc.example.org'"
http.url = "'https://127.0.0.1:9090'"

[server.listener.jmap]
bind = ['127.0.0.1:9090']
protocol = 'http'
tls.implicit = true

[server.socket]
reuse-addr = true

[certificate.default]
cert = '%{file:{CERT}}%'
private-key = '%{file:{PK}}%'
default = true
"#;

#[derive(Clone)]
pub struct HttpSessionManager {
    inner: HttpRequestHandler,
}

pub type HttpRequestHandler = Arc<dyn Fn(HttpMessage) -> HttpResponse + Sync + Send>;

#[derive(Debug)]
pub struct HttpMessage {
    method: Method,
    headers: AHashMap<String, String>,
    uri: Uri,
    body: Option<Vec<u8>>,
}

impl HttpMessage {
    pub fn get_url_encoded(&self, key: &str) -> Option<String> {
        form_urlencoded::parse(self.body.as_ref()?.as_slice())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

pub async fn spawn_mock_http_server(
    handler: HttpRequestHandler,
) -> (watch::Sender<bool>, watch::Receiver<bool>) {
    // Start mock push server
    let mut settings = Config::new(add_test_certs(MOCK_HTTP_SERVER)).unwrap();
    settings.resolve_all_macros().await;
    let mock_inner = Arc::new(Inner {
        shared_core: Core::parse(&mut settings, Default::default(), Default::default())
            .await
            .into_shared(),
        data: Data::parse(&mut settings),
        ..Default::default()
    });
    settings.errors.clear();
    settings.warnings.clear();
    let mut servers = Listeners::parse(&mut settings);
    servers.parse_tcp_acceptors(&mut settings, mock_inner.clone());

    // Start JMAP server
    servers.bind_and_drop_priv(&mut settings);
    settings.assert_no_errors();
    servers.spawn(|server, acceptor, shutdown_rx| {
        server.spawn(
            HttpSessionManager {
                inner: handler.clone(),
            },
            mock_inner.clone(),
            acceptor,
            shutdown_rx,
        );
    })
}

impl common::listener::SessionManager for HttpSessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: common::listener::SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let sender = self.inner;
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(session.stream),
                    service_fn(|mut req: hyper::Request<body::Incoming>| {
                        let sender = sender.clone();

                        async move {
                            let response = sender(HttpMessage {
                                method: req.method().clone(),
                                uri: req.uri().clone(),
                                headers: req
                                    .headers()
                                    .iter()
                                    .map(|(k, v)| {
                                        (k.as_str().to_lowercase(), v.to_str().unwrap().to_string())
                                    })
                                    .collect(),
                                body: fetch_body(&mut req, 1024 * 1024, 0).await,
                            });

                            Ok::<_, hyper::Error>(response.build())
                        }
                    }),
                )
                .await;
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}
