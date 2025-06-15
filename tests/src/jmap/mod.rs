/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Debug, path::PathBuf, sync::Arc, time::Duration};

use base64::{
    Engine,
    engine::general_purpose::{self, STANDARD},
};
use common::{
    Caches, Core, Data, Inner, KV_BAYES_MODEL_GLOBAL, Server,
    auth::AccessToken,
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
use email::message::delete::EmailDeletion;
use enterprise::{EnterpriseCore, insert_test_metrics};
use http::HttpSessionManager;
use hyper::{Method, header::AUTHORIZATION};
use imap::core::ImapSessionManager;
use jmap_client::client::{Client, Credentials};
use jmap_proto::{error::request::RequestError, types::id::Id};
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use reqwest::header;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use services::SpawnServices;
use smtp::{SpawnQueueManager, core::SmtpSessionManager};

use store::{
    IterateParams, SUBSPACE_PROPERTY, Stores, ValueKey,
    roaring::RoaringBitmap,
    write::{AnyKey, TaskQueueClass, ValueClass, key::DeserializeBigEndian},
};
use tokio::sync::watch;
use utils::{BlobHash, config::Config};
use webhooks::{MockWebhookEndpoint, spawn_mock_webhook_endpoint};

use crate::{
    AssertConfig, add_test_certs, directory::internal::TestInternalDirectory, store::TempDir,
};

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
pub mod enterprise;
pub mod event_source;
pub mod mailbox;
pub mod permissions;
pub mod purge;
pub mod push_subscription;
pub mod quota;
pub mod sieve_script;
pub mod thread_get;
pub mod thread_merge;
pub mod vacation_response;
pub mod webhooks;
pub mod websocket;

#[tokio::test(flavor = "multi_thread")]
async fn jmap_tests() {
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
    permissions::test(&params).await;
    purge::test(&mut params).await;
    enterprise::test(&mut params).await;

    if delete {
        params.temp_dir.delete();
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn jmap_metric_tests() {
    let params = init_jmap_tests(
        &std::env::var("STORE")
            .expect("Missing store type. Try running `STORE=<store_type> cargo test`"),
        false,
    )
    .await;

    insert_test_metrics(params.server.core.clone()).await;
}

#[allow(dead_code)]
pub struct JMAPTest {
    server: Server,
    client: Client,
    temp_dir: TempDir,
    webhook: Arc<MockWebhookEndpoint>,
    shutdown_tx: watch::Sender<bool>,
}

pub async fn wait_for_index(server: &Server) {
    loop {
        let mut has_index_tasks = false;
        server
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey::<ValueClass> {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                            due: 0,
                            hash: BlobHash::default(),
                        }),
                    },
                    ValueKey::<ValueClass> {
                        account_id: u32::MAX,
                        collection: u8::MAX,
                        document_id: u32::MAX,
                        class: ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                            due: u64::MAX,
                            hash: BlobHash::default(),
                        }),
                    },
                )
                .ascending(),
                |_, _| {
                    has_index_tasks = true;

                    Ok(false)
                },
            )
            .await
            .unwrap();

        if has_index_tasks {
            tokio::time::sleep(Duration::from_millis(300)).await;
        } else {
            break;
        }
    }
}

pub async fn assert_is_empty(server: Server) {
    // Wait for pending FTS index tasks
    wait_for_index(&server).await;

    // Delete bayes model
    server
        .in_memory_store()
        .key_delete_prefix(&[KV_BAYES_MODEL_GLOBAL])
        .await
        .unwrap();

    // Purge accounts
    emails_purge_tombstoned(&server).await;

    // Assert is empty
    server
        .core
        .storage
        .data
        .assert_is_empty(server.core.storage.blob.clone())
        .await;

    // Clean cache
    server.inner.cache.messages.clear();
}

pub async fn emails_purge_tombstoned(server: &Server) {
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
        let do_add = server.inner.cache.access_tokens.get(&account_id).is_none();

        if do_add {
            server
                .inner
                .cache
                .access_tokens
                .insert(account_id, Arc::new(AccessToken::from_id(account_id)));
        }
        server.emails_purge_tombstoned(account_id).await.unwrap();
        if do_add {
            server.inner.cache.access_tokens.remove(&account_id);
        }
    }
}

async fn init_jmap_tests(store_id: &str, delete_if_exists: bool) -> JMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("jmap_tests", delete_if_exists);
    let mut config = Config::new(
        add_test_certs(SERVER)
            .replace("{STORE}", store_id)
            .replace("{TMP}", &temp_dir.path.display().to_string())
            .replace(
                "{LEVEL}",
                &std::env::var("LOG").unwrap_or_else(|_| "disable".to_string()),
            ),
    )
    .unwrap();
    config.resolve_all_macros().await;

    // Parse servers
    let mut servers = Listeners::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Build stores
    let stores = Stores::parse_all(&mut config, false).await;

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
    let store = core.storage.data.clone();
    let (ipc, mut ipc_rxs) = build_ipc(&mut config, false);
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
    let (shutdown_tx, _) = servers.spawn(|server, acceptor, shutdown_rx| {
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

    if delete_if_exists {
        store.destroy().await;
    }

    // Create tables
    inner
        .shared_core
        .load()
        .storage
        .data
        .create_test_user("admin", "secret", "Superuser", &[])
        .await;

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
        server: inner.build_server(),
        temp_dir,
        client,
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
    RequestError(RequestError<'static>),
    Error {
        error: String,
        details: Option<String>,
        item: Option<String>,
        reason: Option<String>,
    },
    Data {
        data: T,
    },
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

    pub async fn patch<T: DeserializeOwned>(
        &self,
        query: &str,
        body: &impl Serialize,
    ) -> Result<Response<T>, String> {
        self.request_raw(
            Method::PATCH,
            query,
            Some(serde_json::to_string(body).unwrap()),
        )
        .await
        .map(|result| {
            serde_json::from_str::<Response<T>>(&result)
                .unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn delete<T: DeserializeOwned>(&self, query: &str) -> Result<Response<T>, String> {
        self.request_raw(Method::DELETE, query, None)
            .await
            .map(|result| {
                serde_json::from_str::<Response<T>>(&result)
                    .unwrap_or_else(|err| panic!("{err}: {result}"))
            })
    }

    pub async fn get<T: DeserializeOwned>(&self, query: &str) -> Result<Response<T>, String> {
        self.request_raw(Method::GET, query, None)
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

impl<T: Debug> Response<T> {
    pub fn unwrap_data(self) -> T {
        match self {
            Response::Data { data } => data,
            Response::Error {
                error,
                details,
                reason,
                ..
            } => {
                panic!("Expected data, found error {error:?}: {details:?} {reason:?}")
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
            Response::Error {
                error,
                details,
                reason,
                ..
            } => {
                panic!("Expected data, found error {error:?}: {details:?} {reason:?}")
            }
            Response::RequestError(err) => {
                panic!("Expected data, found error {err:?}")
            }
        }
    }

    pub fn unwrap_error(self) -> (String, Option<String>, Option<String>) {
        match self {
            Response::Error {
                error,
                details,
                reason,
                ..
            } => (error, details, reason),
            Response::Data { data } => panic!("Expected error, found data: {data:?}"),
            Response::RequestError(err) => {
                panic!("Expected error, found request error {err:?}")
            }
        }
    }

    pub fn unwrap_request_error(self) -> RequestError<'static> {
        match self {
            Response::Error {
                error,
                details,
                reason,
                ..
            } => {
                panic!("Expected request error, found error {error:?}: {details:?} {reason:?}")
            }
            Response::Data { data } => panic!("Expected request error, found data: {data:?}"),
            Response::RequestError(err) => err,
        }
    }

    pub fn expect_request_error(self, value: &str) {
        let err = self.unwrap_request_error();
        if !err.detail.contains(value) && !err.title.as_ref().is_some_and(|t| t.contains(value)) {
            panic!("Expected request error containing {value:?}, found {err:?}")
        }
    }

    pub fn expect_error(self, value: &str) {
        let (error, details, reason) = self.unwrap_error();
        if !error.contains(value)
            && !details.as_ref().is_some_and(|d| d.contains(value))
            && !reason.as_ref().is_some_and(|r| r.contains(value))
        {
            panic!("Expected error containing {value:?}, found {error:?}: {details:?} {reason:?}")
        }
    }
}

const SERVER: &str = r#"
[server]
hostname = "'jmap.example.org'"

[http]
url = "'https://127.0.0.1:8899'"

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

[server.listener.pop3]
bind = ["127.0.0.1:4110"]
protocol = "pop3"
max-connections = 81920
tls.implicit = true

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = "default"

[server.fail2ban]
authentication = "100/5s"

[authentication]
rate-limit = "100/2s"

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

[session.data]
spam-filter = "recipients[0] != 'robert@example.com'"

[session.data.add-headers]
delivered-to = false

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
directory = "{STORE}"

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

[email]
auto-expunge = "1s"

[changes]
max-history = "1"

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

[directory."{STORE}"]
type = "internal"
store = "{STORE}"

[imap.auth]
allow-plain-text = true

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"

[oauth.client-registration]
anonymous = true
require = true

[oauth.oidc]
signature-key = '''-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDMXJI1bL3z8gaF
Ze/6493VjL+jHkFMP2Pc7fLwRF1fhkuIdYTp69LabzrSEJCRCz0UI2NHqPOgtOta
+zRHKAMr7c7Z6uKO0K+aXiQYHw4Y70uSG8CnmNl7kb4OM/CAcoO6fePmvBsyESfn
TmkJ5bfHEZQFDQEAoDlDjtjxuwYsAQQVQXuAydi8j8pyTWKAJ1RDgnUT+HbOub7j
JrQ7sPe6MPCjXv5N76v9RMHKktfYwRNMlkLkxImQU55+vlvghNztgFlIlJDFfNiy
UQPV5FTEZJli9BzMoj1JQK3sZyV8WV0W1zN41QQ+glAAC6+K7iTDPRMINBSwbHyn
6Lb9Q6U7AgMBAAECggEAB93qZ5xrhYgEFeoyKO4mUdGsu4qZyJB0zNeWGgdaXCfZ
zC4l8zFM+R6osix0EY6lXRtC95+6h9hfFQNa5FWseupDzmIQiEnim1EowjWef87l
Eayi0nDRB8TjqZKjR/aLOUhzrPlXHKrKEUk/RDkacCiDklwz9S0LIfLOSXlByBDM
/n/eczfX2gUATexMHSeIXs8vN2jpuiVv0r+FPXcRvqdzDZnYSzS8BJ9k6RYXVQ4o
NzCbfqgFIpVryB7nHgSTrNX9G7299If8/dXmesXWSFEJvvDSSpcBoINKbfgSlrxd
6ubjiotcEIBUSlbaanRrydwShhLHnXyupNAb7tlvyQKBgQDsIipSK4+H9FGl1rAk
Gg9DLJ7P/94sidhoq1KYnj/CxwGLoRq22khZEUYZkSvYXDu1Qkj9Avi3TRhw8uol
l2SK1VylL5FQvTLKhWB7b2hjrUd5llMRgS3/NIdLhOgDMB7w3UxJnCA/df/Rj+dM
WhkyS1f0x3t7XPLwWGurW0nJcwKBgQDdjhrNfabrK7OQvDpAvNJizuwZK9WUL7CD
rR0V0MpDGYW12BTEOY6tUK6XZgiRitAXf4EkEI6R0Q0bFzwDDLrg7TvGdTuzNeg/
8vm8IlRlOkrdihtHZI4uRB7Ytmz24vzywEBE0p6enA7v4oniscUks/KKmDGr0V90
yT9gIVrjGQKBgQCjnWC5otlHGLDiOgm+WhgtMWOxN9dYAQNkMyF+Alinu4CEoVKD
VGhA3sk1ufMpbW8pvw4X0dFIITFIQeift3DBCemxw23rBc2FqjkaDi3EszINO22/
eUTHyjvcxfCFFPi7aHsNnhJyJm7lY9Kegudmg/Ij93zGE7d5darVBuHvpQKBgBBY
YovUgFMLR1UfPeD2zUKy52I4BKrJFemxBNtOKw3mPSIcTfPoFymcMTVENs+eARoq
svlZK1uAo8ni3e+Pqd3cQrOyhHQFPxwwrdH+amGJemp7vOV4erDZH7l3Q/S27Fhw
bI1nSIKFGukBupB58wRxLiyha9C0QqmYC0/pRg5JAn8Rbj5tP26oVCXjZEfWJL8J
axxSxsGA4Vol6i6LYnVgZG+1ez2rP8vUORo1lRzmdeP4o1BSJf9TPwXkuppE5J+t
UZVKtYGlEn1RqwGNd8I9TiWvU84rcY9nsxlDR86xwKRWFvYqVOiGYtzRyewYRdjU
rTs9aqB3v1+OVxGxR6Na
-----END PRIVATE KEY-----
'''
signature-algorithm = "RS256"

[oauth.oidc-ignore]
signature-key = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggybcqc86ulFFiOon
WiYrLO4z8/kmkqvA7wGElBok9IqhRANCAAQxZK68FnQtHC0eyh8CA05xRIvxhVHn
0ymka6XBh9aFtW4wfeoKhTkSKjHc/zjh9Rr2dr3kvmYe80fMGhW4ycGA
-----END PRIVATE KEY-----
'''
signature-algorithm = "ES256"

[session.extensions]
expn = true
vrfy = true

[spam-filter]
enable = true

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
disabled-events = ["network.*", "telemetry.webhook-error", "http.request-body"]

[webhook."test"]
url = "http://127.0.0.1:8821/hook"
events = ["auth.*", "delivery.dsn*", "message-ingest.*", "security.authentication-ban"]
signature-key = "ovos-moles"
throttle = "100ms"

[sieve.untrusted.scripts."common"]
contents = '''
require "reject";

reject "Rejected from a global script.";
stop;
'''
"#;
