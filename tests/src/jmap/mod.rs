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

use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::{
    engine::general_purpose::{self, STANDARD},
    Engine,
};
use common::{
    config::server::{ServerProtocol, Servers},
    manager::config::{ConfigManager, Patterns},
    webhooks::manager::spawn_webhook_manager,
    Core, Ipc, IPC_CHANNEL_BUFFER,
};
use hyper::{header::AUTHORIZATION, Method};
use imap::core::{ImapSessionManager, IMAP};
use jmap::{api::JmapSessionManager, services::housekeeper::Event, JMAP};
use jmap_client::client::{Client, Credentials};
use jmap_proto::{error::request::RequestError, types::id::Id};
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use reqwest::header;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use smtp::core::{SmtpSessionManager, SMTP};

use store::{
    roaring::RoaringBitmap,
    write::{key::DeserializeBigEndian, AnyKey},
    IterateParams, Stores, SUBSPACE_PROPERTY,
};
use tokio::sync::{mpsc, watch};
use utils::config::Config;
use webhooks::{spawn_mock_webhook_endpoint, MockWebhookEndpoint};

use crate::{add_test_certs, directory::DirectoryStore, store::TempDir, AssertConfig};

pub mod auth_acl;
pub mod auth_limits;
pub mod auth_oauth;
pub mod blob;
pub mod crypto;
pub mod delivery;
pub mod email_changes;
pub mod email_copy;
pub mod email_get;
pub mod email_parse;
pub mod email_query;
pub mod email_query_changes;
pub mod email_search_snippet;
pub mod email_set;
pub mod email_submission;
pub mod event_source;
pub mod mailbox;
pub mod purge;
pub mod push_subscription;
pub mod quota;
pub mod sieve_script;
pub mod stress_test;
pub mod thread_get;
pub mod thread_merge;
pub mod vacation_response;
pub mod webhooks;
pub mod websocket;

const SERVER: &str = r#"
[server]
hostname = "'jmap.example.org'"
http.url = "'https://127.0.0.1:8899'"

[server.listener.jmap]
bind = ["127.0.0.1:8899"]
protocol = "http"
max-connections = 81920
tls.implicit = true

[server.listener.imap]
bind = ["127.0.0.1:9991"]
protocol = "imap"
max-connections = 81920

[server.listener.lmtp-debug]
bind = ['127.0.0.1:11200']
greeting = 'Test LMTP instance'
protocol = 'lmtp'
tls.implicit = false

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = "default"

[authentication]
fail2ban = "101/5s"
rate-limit = "100/2s"

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = [ { if = "!is_empty(authenticated_as)", then = true }, 
          { else = false } ]
directory = "'auth'"

[session.rcpt.errors]
total = 5
wait = "1ms"

[queue]
path = "{TMP}"
hash = 64

[report]
path = "{TMP}"
hash = 64

[resolver]
type = "system"

[queue.outbound]
next-hop = [ { if = "rcpt_domain == 'example.com'", then = "'local'" }, 
             { if = "contains(['remote.org', 'foobar.com', 'test.com', 'other_domain.com'], rcpt_domain)", then = "'mock-smtp'" },
             { else = false } ]

[remote."mock-smtp"]
address = "localhost"
port = 9999
protocol = "smtp"

[remote."mock-smtp".tls]
implicit = false
allow-invalid-certs = true

[session.extensions]
future-release = [ { if = "!is_empty(authenticated_as)", then = "99999999d"},
                   { else = false } ]

[store."sqlite"]
type = "sqlite"
path = "{TMP}/sqlite.db"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/rocks.db"

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

[store."elastic"]
type = "elasticsearch"
url = "https://localhost:9200"
user = "elastic"
password = "changeme"
tls.allow-invalid-certs = true
disable = true

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[storage]
data = "{STORE}"
fts = "{STORE}"
blob = "{STORE}"
lookup = "{STORE}"
directory = "auth"

[spam.header]
is-spam  = "X-Spam-Status: Yes"

[jmap.protocol.get]
max-objects = 100000

[jmap.protocol.set]
max-objects = 100000

[jmap.protocol.request]
max-concurrent = 8

[jmap.protocol.upload]
max-size = 5000000
max-concurrent = 4
ttl = "1m"

[jmap.protocol.upload.quota]
files = 3
size = 50000

[jmap.rate-limit]
account = "1000/1m"
anonymous = "100/1m"

[jmap.event-source]
throttle = "500ms"

[jmap.web-sockets]
throttle = "500ms"

[jmap.push]
throttle = "500ms"
attempts.interval = "500ms"

[jmap.email]
auto-expunge = "1s"

[jmap.protocol.changes]
max-history = "1s"

[store."auth"]
type = "sqlite"
path = "{TMP}/auth.db"

[store."auth".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ?"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || ? || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || ? LIMIT 1"

[directory."auth"]
type = "sql"
store = "auth"

[directory."auth".columns]
name = "name"
description = "description"
secret = "secret"
email = "address"
quota = "quota"
class = "type"

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"

[session.extensions]
expn = true
vrfy = true

[webhook."test"]
url = "http://127.0.0.1:8821/hook"
events = ["auth.success", "auth.failure", "auth.banned", "auth.error", 
          "message.accepted", "message.rejected", "message.appended", 
          "account.over-quota", "dsn", "double-bounce", "report.incoming.dmarc", 
          "report.incoming.tls", "report.incoming.arf", "report.outgoing"]
signature-key = "ovos-moles"
throttle = "100ms"

"#;

#[tokio::test(flavor = "multi_thread")]
pub async fn jmap_tests() {
    if let Ok(level) = std::env::var("LOG") {
        tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .parse(
                            format!("smtp={level},imap={level},jmap={level},store={level},utils={level},directory={level},common={level}"),
                        )
                        .unwrap(),
                )
                .finish(),
        )
        .unwrap();
    }

    let delete = true;
    let mut params = init_jmap_tests(
        &std::env::var("STORE")
            .expect("Missing store type. Try running `STORE=<store_type> cargo test`"),
        delete,
    )
    .await;

    webhooks::test(&mut params).await;
    email_query::test(&mut params, delete).await;
    email_get::test(&mut params).await;
    email_set::test(&mut params).await;
    email_parse::test(&mut params).await;
    email_search_snippet::test(&mut params).await;
    email_changes::test(&mut params).await;
    email_query_changes::test(&mut params).await;
    email_copy::test(&mut params).await;
    thread_get::test(&mut params).await;
    thread_merge::test(&mut params).await;
    mailbox::test(&mut params).await;
    delivery::test(&mut params).await;
    auth_acl::test(&mut params).await;
    auth_limits::test(&mut params).await;
    auth_oauth::test(&mut params).await;
    event_source::test(&mut params).await;
    push_subscription::test(&mut params).await;
    sieve_script::test(&mut params).await;
    vacation_response::test(&mut params).await;
    email_submission::test(&mut params).await;
    websocket::test(&mut params).await;
    quota::test(&mut params).await;
    crypto::test(&mut params).await;
    blob::test(&mut params).await;
    purge::test(&mut params).await;

    if delete {
        params.temp_dir.delete();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
pub async fn jmap_stress_tests() {
    if let Ok(level) = std::env::var("LOG") {
        tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .parse(
                            format!("smtp={level},imap={level},jmap={level},store={level},utils={level},directory={level},common={level}"),
                        )
                        .unwrap(),
                )
                .finish(),
        )
        .unwrap();
    }

    let params = init_jmap_tests(
        &std::env::var("STORE")
            .expect("Missing store type. Try running `STORE=<store_type> cargo test`"),
        true,
    )
    .await;
    stress_test::test(params.server.clone(), params.client).await;
    params.temp_dir.delete();
}

#[allow(dead_code)]
pub struct JMAPTest {
    server: Arc<JMAP>,
    client: Client,
    directory: DirectoryStore,
    temp_dir: TempDir,
    webhook: Arc<MockWebhookEndpoint>,
    shutdown_tx: watch::Sender<bool>,
}

pub async fn wait_for_index(server: &JMAP) {
    loop {
        let (tx, rx) = tokio::sync::oneshot::channel();
        server
            .inner
            .housekeeper_tx
            .send(Event::IndexIsActive(tx))
            .await
            .unwrap();
        if rx.await.unwrap() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else {
            break;
        }
    }
}

pub async fn assert_is_empty(server: Arc<JMAP>) {
    // Wait for pending FTS index tasks
    wait_for_index(&server).await;

    // Purge accounts
    emails_purge_tombstoned(&server).await;

    // Assert is empty
    server
        .core
        .storage
        .data
        .assert_is_empty(server.core.storage.blob.clone())
        .await;
}

pub async fn emails_purge_tombstoned(server: &JMAP) {
    let mut account_ids = RoaringBitmap::new();
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace: SUBSPACE_PROPERTY,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace: SUBSPACE_PROPERTY,
                    key: vec![u8::MAX, u8::MAX, u8::MAX, u8::MAX],
                },
            )
            .no_values(),
            |key, _| {
                account_ids.insert(key.deserialize_be_u32(0).unwrap());

                Ok(true)
            },
        )
        .await
        .unwrap();

    for account_id in account_ids {
        server.emails_purge_tombstoned(account_id).await.unwrap();
    }
}

async fn init_jmap_tests(store_id: &str, delete_if_exists: bool) -> JMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("jmap_tests", delete_if_exists);
    let mut config = Config::new(
        add_test_certs(SERVER)
            .replace("{STORE}", store_id)
            .replace("{TMP}", &temp_dir.path.display().to_string()),
    )
    .unwrap();
    config.resolve_all_macros().await;

    // Parse servers
    let mut servers = Servers::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Build stores
    let stores = Stores::parse_all(&mut config).await;

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
    let core = Core::parse(&mut config, stores, config_manager).await;
    let store = core.storage.data.clone();
    let shared_core = core.into_shared();

    // Parse acceptors
    servers.parse_tcp_acceptors(&mut config, shared_core.clone());

    // Spawn webhook manager
    let webhook_tx = spawn_webhook_manager(shared_core.clone());

    // Setup IPC channels
    let (delivery_tx, delivery_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let ipc = Ipc {
        delivery_tx,
        webhook_tx,
    };

    // Init servers
    let smtp = SMTP::init(&mut config, shared_core.clone(), ipc).await;
    let jmap = JMAP::init(
        &mut config,
        delivery_rx,
        shared_core.clone(),
        smtp.inner.clone(),
    )
    .await;
    let imap = IMAP::init(&mut config, jmap.clone()).await;
    config.assert_no_errors();

    // Spawn servers
    let (shutdown_tx, _) = servers.spawn(|server, acceptor, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                SmtpSessionManager::new(smtp.clone()),
                shared_core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Http => server.spawn(
                JmapSessionManager::new(jmap.clone()),
                shared_core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(imap.clone()),
                shared_core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Pop3 => server.spawn(
                Pop3SessionManager::new(imap.clone()),
                shared_core.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(imap.clone()),
                shared_core.clone(),
                acceptor,
                shutdown_rx,
            ),
        };
    });

    // Create tables
    let directory = DirectoryStore {
        store: shared_core
            .load()
            .storage
            .lookups
            .get("auth")
            .unwrap()
            .clone(),
    };
    directory.create_test_directory().await;
    directory
        .create_test_user("admin", "secret", "Superuser")
        .await;

    if delete_if_exists {
        store.destroy().await;
    }

    // Create client
    let mut client = Client::new()
        .credentials(Credentials::basic("admin", "secret"))
        .timeout(Duration::from_secs(3600))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    client.set_default_account_id(Id::new(1));

    JMAPTest {
        server: JMAP::from(jmap).into(),
        temp_dir,
        client,
        directory,
        shutdown_tx,
        webhook: spawn_mock_webhook_endpoint(),
    }
}

pub async fn jmap_raw_request(body: impl AsRef<str>, username: &str, secret: &str) -> String {
    let mut headers = header::HeaderMap::new();

    headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&format!(
            "Basic {}",
            general_purpose::STANDARD.encode(format!("{}:{}", username, secret))
        ))
        .unwrap(),
    );

    const BODY_TEMPLATE: &str = r#"{
        "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:quota" ],
        "methodCalls": $$
      }"#;

    String::from_utf8(
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(1000))
            .default_headers(headers)
            .build()
            .unwrap()
            .post("https://127.0.0.1:8899/jmap")
            .body(BODY_TEMPLATE.replace("$$", body.as_ref()))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

pub async fn jmap_json_request(
    body: impl AsRef<str>,
    username: &str,
    secret: &str,
) -> serde_json::Value {
    serde_json::from_str(&jmap_raw_request(body, username, secret).await).unwrap()
}

pub fn find_values(string: &str, name: &str) -> Vec<String> {
    let mut last_pos = 0;
    let mut values = Vec::new();

    while let Some(pos) = string[last_pos..].find(name) {
        let mut value = string[last_pos + pos + name.len()..]
            .split('"')
            .nth(1)
            .unwrap();
        if value.ends_with('\\') {
            value = &value[..value.len() - 1];
        }
        values.push(value.to_string());
        last_pos += pos + name.len();
    }

    values
}

pub fn replace_values(mut string: String, find: &[String], replace: &[String]) -> String {
    for (find, replace) in find.iter().zip(replace.iter()) {
        string = string.replace(find, replace);
    }
    string
}

pub fn replace_boundaries(string: String) -> String {
    let values = find_values(&string, "boundary=");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("boundary_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}

pub fn replace_blob_ids(string: String) -> String {
    let values = find_values(&string, "blobId\":");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("blob_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}

pub async fn test_account_login(login: &str, secret: &str) -> Client {
    Client::new()
        .credentials(Credentials::basic(login, secret))
        .timeout(Duration::from_secs(5))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap()
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Response<T> {
    RequestError(RequestError),
    Error { error: String, details: String },
    Data { data: T },
}

pub struct ManagementApi {
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for ManagementApi {
    fn default() -> Self {
        Self {
            port: 9980,
            username: "admin".to_string(),
            password: "secret".to_string(),
        }
    }
}

impl ManagementApi {
    pub fn new(port: u16, username: &str, password: &str) -> Self {
        Self {
            port,
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        query: &str,
        body: &impl Serialize,
    ) -> Result<Response<T>, String> {
        self.request_raw(
            Method::POST,
            query,
            Some(serde_json::to_string(body).unwrap()),
        )
        .await
        .map(|result| {
            serde_json::from_str::<Response<T>>(&result)
                .unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        query: &str,
    ) -> Result<Response<T>, String> {
        self.request_raw(method, query, None).await.map(|result| {
            serde_json::from_str::<Response<T>>(&result)
                .unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    async fn request_raw(
        &self,
        method: Method,
        query: &str,
        body: Option<String>,
    ) -> Result<String, String> {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(method, format!("https://127.0.0.1:{}{query}", self.port));

        if let Some(body) = body {
            request = request.body(body);
        }

        request
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{}", self.username, self.password).as_bytes())
                ),
            )
            .send()
            .await
            .map_err(|err| err.to_string())?
            .bytes()
            .await
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .map_err(|err| err.to_string())
    }
}

impl<T> Response<T> {
    pub fn unwrap_data(self) -> T {
        match self {
            Response::Data { data } => data,
            Response::Error { error, details } => {
                panic!("Expected data, found error {error:?}: {details:?}")
            }
            Response::RequestError(err) => {
                panic!("Expected data, found error {err:?}")
            }
        }
    }

    pub fn try_unwrap_data(self) -> Option<T> {
        match self {
            Response::Data { data } => Some(data),
            Response::RequestError(error) if error.status == 404 => None,
            Response::Error { error, details } => {
                panic!("Expected data, found error {error:?}: {details:?}")
            }
            Response::RequestError(err) => {
                panic!("Expected data, found error {err:?}")
            }
        }
    }

    pub fn unwrap_error(self) -> (String, String) {
        match self {
            Response::Error { error, details } => (error, details),
            Response::Data { .. } => panic!("Expected error, found data."),
            Response::RequestError(err) => {
                panic!("Expected error, found request error {err:?}")
            }
        }
    }
}
