/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashMap;
use common::{Caches, Core, Data, Inner, config::server::Listeners, listener::SessionData};
use http_proto::{HttpResponse, request::fetch_body};
use hyper::{Method, Uri, body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::sync::watch;
use utils::config::Config;

use crate::{AssertConfig, add_test_certs};

const MOCK_HTTP_SERVER: &str = r#"
[server]
hostname = "'oidc.example.org'"

[http]
url = "'https://127.0.0.1:9090'"

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
    pub method: Method,
    pub headers: AHashMap<String, String>,
    pub uri: Uri,
    pub body: Option<Vec<u8>>,
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
        cache: Caches::parse(&mut settings),
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
