/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::server::{ServerProtocol, Servers},
    Core,
};
use jmap::{api::JmapSessionManager, JMAP};
use store::{BlobStore, Store, Stores};
use tokio::sync::{mpsc, watch};

use ::smtp::core::{Inner, Session, SmtpInstance, SmtpSessionManager, SMTP};
use utils::config::Config;

use crate::AssertConfig;

use super::{
    add_test_certs,
    session::{DummyIo, TestSession},
    QueueReceiver, ReportReceiver, TempDir, TestSMTP,
};

pub mod dane;
pub mod extensions;
pub mod fallback_relay;
pub mod ip_lookup;
pub mod lmtp;
pub mod mta_sts;
pub mod smtp;
pub mod throttle;
pub mod tls;

const CONFIG: &str = r#"
[session.connect]
hostname = "'mx.example.org'"
greeting = "'Test SMTP instance'"

[server.listener.smtp-debug]
bind = ['127.0.0.1:9925']
protocol = 'smtp'

[server.listener.lmtp-debug]
bind = ['127.0.0.1:9924']
protocol = 'lmtp'
tls.implicit = true

[server.listener.management-debug]
bind = ['127.0.0.1:9980']
protocol = 'http'
tls.implicit = true

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = 'default'

[certificate.default]
cert = '%{file:{CERT}}%'
private-key = '%{file:{PK}}%'

[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/queue.db"

"#;

pub struct TestServer {
    pub instance: SmtpInstance,
    pub temp_dir: TempDir,
    pub qr: QueueReceiver,
    pub rr: ReportReceiver,
}

impl TestServer {
    pub async fn new(name: &str, config: impl AsRef<str>, with_receiver: bool) -> TestServer {
        let temp_dir = TempDir::new(name, true);
        let mut config =
            Config::new(temp_dir.update_config(add_test_certs(CONFIG) + config.as_ref())).unwrap();
        config.resolve_all_macros().await;
        let stores = Stores::parse_all(&mut config).await;
        let core = Core::parse(&mut config, stores, Default::default()).await;
        let mut inner = Inner::default();
        let qr = if with_receiver {
            inner.init_test_queue(&core)
        } else {
            QueueReceiver {
                store: Store::default(),
                blob_store: BlobStore::default(),
                queue_rx: mpsc::channel(1).1,
            }
        };
        let rr = if with_receiver {
            inner.init_test_report()
        } else {
            ReportReceiver {
                report_rx: mpsc::channel(1).1,
            }
        };

        TestServer {
            instance: SmtpInstance::new(core.into_shared(), inner),
            temp_dir,
            qr,
            rr,
        }
    }

    pub async fn start(&self, protocols: &[ServerProtocol]) -> watch::Sender<bool> {
        // Spawn listeners
        let mut config = Config::new(CONFIG).unwrap();
        let mut servers = Servers::parse(&mut config);
        servers.parse_tcp_acceptors(&mut config, self.instance.core.clone());

        // Filter out protocols
        servers
            .servers
            .retain(|server| protocols.contains(&server.protocol));

        // Start servers
        servers.bind_and_drop_priv(&mut config);
        let instance = self.instance.clone();
        let smtp_manager = SmtpSessionManager::new(instance.clone());
        let jmap = JMAP::init(
            &mut config,
            mpsc::channel(1).1,
            instance.core.clone(),
            instance.inner.clone(),
        )
        .await;
        let jmap_manager = JmapSessionManager::new(jmap);
        config.assert_no_errors();

        servers
            .spawn(|server, acceptor, shutdown_rx| {
                match &server.protocol {
                    ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                        smtp_manager.clone(),
                        instance.core.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                    ServerProtocol::Http => server.spawn(
                        jmap_manager.clone(),
                        instance.core.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                    ServerProtocol::Imap | ServerProtocol::Pop3 | ServerProtocol::ManageSieve => {
                        unreachable!()
                    }
                };
            })
            .0
    }

    pub fn new_session(&self) -> Session<DummyIo> {
        Session::test(self.build_smtp())
    }

    pub fn build_smtp(&self) -> SMTP {
        SMTP::from(self.instance.clone())
    }
}
