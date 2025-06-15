/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{path::PathBuf, sync::Arc, time::Duration};

use common::{
    Caches, Core, Data, Inner, Server,
    config::{
        server::{Listeners, ServerProtocol},
        telemetry::Telemetry,
    },
    core::BuildServer,
    manager::{
        boot::build_ipc,
        config::{ConfigManager, Patterns},
    },
};
use http::HttpSessionManager;
use imap::core::ImapSessionManager;
use imap_proto::ResponseType;
use jmap_client::client::{Client, Credentials};
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use services::{SpawnServices, broadcast::subscriber::spawn_broadcast_subscriber};
use smtp::{SpawnQueueManager, core::SmtpSessionManager};
use store::Stores;
use tokio::sync::watch;
use utils::config::Config;

use crate::{
    AssertConfig, TEST_USERS, add_test_certs,
    directory::internal::TestInternalDirectory,
    imap::{ImapConnection, Type},
    jmap::enterprise::EnterpriseCore,
};

pub mod broadcast;
pub mod stress;

pub const NUM_NODES: usize = 3;

#[tokio::test(flavor = "multi_thread")]
pub async fn cluster_tests() {
    let params = init_cluster_tests(true).await;
    //stress::test(params.server.clone(), params.client).await;
    broadcast::test(&params).await;
}

#[allow(dead_code)]
pub struct ClusterTest {
    servers: Vec<Server>,
    shutdown_txs: Vec<watch::Sender<bool>>,
}

async fn init_cluster_tests(delete_if_exists: bool) -> ClusterTest {
    // Load and parse config
    let store_id = std::env::var("STORE").expect(
        "Missing store type. Try running `STORE=<store_type> PUBSUB=<pubsub_type> cargo test`",
    );
    let pubsub_id = std::env::var("PUBSUB").expect(
        "Missing store type. Try running `STORE=<store_type> PUBSUB=<pubsub_type> cargo test`",
    );
    let mut pubsub_config = match pubsub_id.as_str() {
        "nats" => Config::new(SERVER_NATS).unwrap(),
        "redis" => Config::new(SERVER_REDIS).unwrap(),
        _ => panic!("Unsupported pubsub type: {}", pubsub_id),
    };

    // Build configs
    let mut configs = Vec::with_capacity(NUM_NODES);
    for node_id in 0..NUM_NODES {
        let mut config = Config::new(
            add_test_certs(SERVER)
                .replace("{STORE}", &store_id)
                .replace("{PUBSUB}", &pubsub_id)
                .replace("{NODE_ID}", &node_id.to_string())
                .replace(
                    "{LEVEL}",
                    &std::env::var("LOG").unwrap_or_else(|_| "disable".to_string()),
                ),
        )
        .unwrap();
        config.resolve_all_macros().await;
        configs.push(config);
    }

    // Build stores
    let stores = Stores::parse_all(configs.first_mut().unwrap(), false).await;

    // Build servers
    let mut servers = Vec::with_capacity(NUM_NODES);
    let mut shutdown_txs = Vec::with_capacity(NUM_NODES);
    for config in configs {
        let mut stores = stores.clone();
        stores.pubsub_stores = Stores::parse(&mut pubsub_config).await.pubsub_stores;
        let (server, shutdown_tx) = build_server(config, stores).await;
        servers.push(server);
        shutdown_txs.push(shutdown_tx);
    }

    let store = servers.first().unwrap().store().clone();
    if delete_if_exists {
        store.destroy().await;
    }

    // Create test users
    for (account, secret, name, email) in TEST_USERS {
        let _account_id = store
            .create_test_user(account, secret, name, &[email])
            .await;
    }

    ClusterTest {
        servers,
        shutdown_txs,
    }
}

impl ClusterTest {
    pub async fn jmap_client(&self, login: &str, node_id: u32) -> Client {
        Client::new()
            .credentials(Credentials::basic(login, find_account_secret(login)))
            .timeout(Duration::from_secs(3600))
            .accept_invalid_certs(true)
            .connect(&format!("https://127.0.0.1:1800{node_id}"))
            .await
            .unwrap()
    }

    pub async fn imap_client(&self, login: &str, node_id: u32) -> ImapConnection {
        let mut conn = ImapConnection::connect_to(b"A1 ", format!("127.0.0.1:1900{node_id}")).await;
        conn.assert_read(Type::Untagged, ResponseType::Ok).await;
        conn.authenticate(login, find_account_secret(login)).await;
        conn
    }

    pub fn server(&self, node_id: usize) -> &Server {
        self.servers
            .get(node_id)
            .unwrap_or_else(|| panic!("No server found for node ID: {}", node_id))
    }
}

fn find_account_secret(login: &str) -> &str {
    TEST_USERS
        .iter()
        .find(|(account, _, _, _)| account == &login)
        .map(|(_, secret, _, _)| secret)
        .unwrap_or_else(|| panic!("No account found for login: {}", login))
}

async fn build_server(mut config: Config, stores: Stores) -> (Server, watch::Sender<bool>) {
    // Parse servers
    let mut servers = Listeners::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Parse core
    let config_manager = ConfigManager {
        cfg_local: Default::default(),
        cfg_local_path: PathBuf::new(),
        cfg_local_patterns: Patterns::parse(&mut config).into(),
        cfg_store: config
            .value("storage.data")
            .and_then(|id| stores.stores.get(id))
            .cloned()
            .unwrap_or_default(),
    };
    let tracers = Telemetry::parse(&mut config, &stores);
    let core = Core::parse(&mut config, stores, config_manager)
        .await
        .enable_enterprise();
    let data = Data::parse(&mut config);
    let cache = Caches::parse(&mut config);
    let (ipc, mut ipc_rxs) = build_ipc(&mut config, true);
    let inner = Arc::new(Inner {
        shared_core: core.into_shared(),
        data,
        ipc,
        cache,
    });

    // Parse acceptors
    servers.parse_tcp_acceptors(&mut config, inner.clone());

    // Enable tracing
    tracers.enable(true);

    // Start services
    config.assert_no_errors();
    ipc_rxs.spawn_queue_manager(inner.clone());
    ipc_rxs.spawn_services(inner.clone());

    // Spawn servers
    let (shutdown_tx, shutdown_rx) = servers.spawn(|server, acceptor, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                SmtpSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Http => server.spawn(
                HttpSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Pop3 => server.spawn(
                Pop3SessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
        };
    });

    // Start broadcast subscriber
    spawn_broadcast_subscriber(inner.clone(), shutdown_rx);

    (inner.build_server(), shutdown_tx)
}

const SERVER: &str = r#"
[server]
hostname = "'server{NODE_ID}.example.org'"

[http]
url = "'https://127.0.0.1:800{NODE_ID}'"

[cluster]
node-id = {NODE_ID}

[server.listener.http]
bind = ["127.0.0.1:1800{NODE_ID}"]
protocol = "http"
max-connections = 81920
tls.implicit = true

[server.listener.imap]
bind = ["127.0.0.1:1900{NODE_ID}"]
protocol = "imap"
max-connections = 81920

[server.listener.lmtp]
bind = ['127.0.0.1:1700{NODE_ID}']
protocol = 'lmtp'
tls.implicit = false

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = "default"

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = [ { if = "!is_empty(authenticated_as)", then = true }, 
          { else = false } ]
directory = "'{STORE}'"

[session.rcpt.errors]
total = 5
wait = "1ms"

[session.auth]
mechanisms = "[plain, login, oauthbearer]"
directory = "'{STORE}'"

[resolver]
type = "system"

[queue.outbound]
next-hop = [ { if = "rcpt_domain == 'example.com'", then = "'local'" }, 
             { if = "contains(['remote.org', 'foobar.com', 'test.com', 'other_domain.com'], rcpt_domain)", then = "'mock-smtp'" },
             { else = false } ]

[store."foundationdb"]
type = "foundationdb"

[store."postgresql"]
type = "postgresql"
host = "localhost"
port = 5432
database = "stalwart"
user = "postgres"
password = "mysecretpassword"

[store."mysql"]
type = "mysql"
host = "localhost"
port = 3307
database = "stalwart"
user = "root"
password = "password"

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[storage]
data = "{STORE}"
fts = "{STORE}"
blob = "{STORE}"
lookup = "{STORE}"
directory = "{STORE}"
pubsub = "{PUBSUB}"

[directory."{STORE}"]
type = "internal"
store = "{STORE}"

[imap.auth]
allow-plain-text = true

[oauth]
key = "parerga_und_paralipomena"

[spam-filter]
enable = false

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
disabled-events = ["network.*", "telemetry.webhook-error", "http.request-body", 
                   "eval.result", "store.*", "dkim.*", "queue.*", "delivery.*",
                   "*.raw-input", "*.raw-output" ]
"#;

const SERVER_NATS: &str = r#"
[store."nats"]
type = "nats"
urls = "127.0.0.1:4444"
"#;

const SERVER_REDIS: &str = r#"
[store."redis"]
type = "redis"
urls = "redis://127.0.0.1"
redis-type = "single"

"#;
