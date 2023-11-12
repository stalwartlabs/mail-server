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

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose, Engine};
use directory::config::ConfigDirectory;
use jmap::{api::JmapSessionManager, services::IPC_CHANNEL_BUFFER, JMAP};
use jmap_client::client::{Client, Credentials};
use jmap_proto::types::id::Id;
use reqwest::header;
use smtp::core::{SmtpSessionManager, SMTP};
use tokio::sync::{mpsc, watch};
use utils::{config::ServerProtocol, UnwrapFailure};

use crate::{
    add_test_certs,
    directory::sql::{add_to_group, create_test_directory, create_test_user},
    store::TempDir,
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
pub mod event_source;
pub mod mailbox;
pub mod push_subscription;
pub mod quota;
pub mod sieve_script;
pub mod stress_test;
pub mod thread_get;
pub mod thread_merge;
pub mod vacation_response;
pub mod websocket;

const SERVER: &str = r#"
[server]
hostname = "jmap.example.org"

[server.listener.jmap]
bind = ["127.0.0.1:8899"]
url = "https://127.0.0.1:8899"
protocol = "jmap"
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

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = [ { if = "authenticated-as", ne = "", then = true }, 
          { else = false } ]
directory = "sql"

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
next-hop = [ { if = "rcpt-domain", in-list = "local/domains", then = "local" }, 
             { if = "rcpt-domain", in-list = "local/remote-domains", then = "mock-smtp" },
             { else = false } ]

[remote."mock-smtp"]
address = "localhost"
port = 9999
protocol = "smtp"

[remote."mock-smtp".tls]
implicit = false
allow-invalid-certs = true

[session.extensions]
future-release = [ { if = "authenticated-as", ne = "", then = "99999999d"},
                   { else = false } ]

[store]
db.path = "{TMP}/sqlite.db"

[store.blob]
type = "local"

[store.blob.local]
path = "{TMP}"

[certificate.default]
cert = "file://{CERT}"
private-key = "file://{PK}"

[jmap]
directory = "sql"

[jmap.protocol]
set.max-objects = 100000

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
authentication = "100/2s"
anonymous = "100/1m"

[jmap.event-source]
throttle = "500ms"

[jmap.web-sockets]
throttle = "500ms"

[jmap.push]
throttle = "500ms"
attempts.interval = "500ms"

[directory."sql"]
type = "sql"
address = "sqlite::memory:"

[directory."sql".pool]
max-connections = 1

[directory."sql".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ?"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || ? || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || ? LIMIT 1"

[directory."sql".columns]
name = "name"
description = "description"
secret = "secret"
email = "address"
quota = "quota"
type = "type"

[directory."local"]
type = "memory"

[directory."local".lookup]
domains = ["example.com"]
remote-domains = ["remote.org", "foobar.com", "test.com", "other_domain.com"]

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"
"#;

#[tokio::test]
pub async fn jmap_tests() {
    let coco = 1;
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::WARN)
            .finish(),
    )
    .unwrap();

    let delete = true;
    let mut params = init_jmap_tests(delete).await;
    /*email_query::test(params.server.clone(), &mut params.client, delete).await;
    email_get::test(params.server.clone(), &mut params.client).await;
    email_set::test(params.server.clone(), &mut params.client).await;
    email_parse::test(params.server.clone(), &mut params.client).await;
    email_search_snippet::test(params.server.clone(), &mut params.client).await;
    email_changes::test(params.server.clone(), &mut params.client).await;
    email_query_changes::test(params.server.clone(), &mut params.client).await;
    email_copy::test(params.server.clone(), &mut params.client).await;
    thread_get::test(params.server.clone(), &mut params.client).await;
    thread_merge::test(params.server.clone(), &mut params.client).await;
    mailbox::test(params.server.clone(), &mut params.client).await;
    delivery::test(params.server.clone(), &mut params.client).await;
    auth_acl::test(params.server.clone(), &mut params.client).await;
    auth_limits::test(params.server.clone(), &mut params.client).await;
    auth_oauth::test(params.server.clone(), &mut params.client).await;
    event_source::test(params.server.clone(), &mut params.client).await;
    push_subscription::test(params.server.clone(), &mut params.client).await;
    sieve_script::test(params.server.clone(), &mut params.client).await;
    vacation_response::test(params.server.clone(), &mut params.client).await;
    email_submission::test(params.server.clone(), &mut params.client).await;
    websocket::test(params.server.clone(), &mut params.client).await;
    quota::test(params.server.clone(), &mut params.client).await;
    crypto::test(params.server.clone(), &mut params.client).await;*/
    blob::test(params.server.clone(), &mut params.client).await;

    if delete {
        params.temp_dir.delete();
    }
}

#[tokio::test]
#[ignore]
pub async fn jmap_stress_tests() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::WARN)
            .finish(),
    )
    .unwrap();

    let params = init_jmap_tests(true).await;
    stress_test::test(params.server.clone(), params.client).await;
    params.temp_dir.delete();
}

#[allow(dead_code)]
struct JMAPTest {
    server: Arc<JMAP>,
    client: Client,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_jmap_tests(delete_if_exists: bool) -> JMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("jmap_tests", delete_if_exists);
    let config = utils::config::Config::new(
        &add_test_certs(SERVER).replace("{TMP}", &temp_dir.path.display().to_string()),
    )
    .unwrap();
    let servers = config.parse_servers().unwrap();
    let directory = config.parse_directory().unwrap();

    // Start JMAP and SMTP servers
    servers.bind(&config);
    let (delivery_tx, delivery_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let smtp = SMTP::init(&config, &servers, &directory, delivery_tx)
        .await
        .failed("Invalid configuration file");
    let jmap = JMAP::init(&config, &directory, delivery_rx, smtp.clone())
        .await
        .failed("Invalid configuration file");
    let (shutdown_tx, _) = servers.spawn(|server, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                server.spawn(SmtpSessionManager::new(smtp.clone()), shutdown_rx)
            }
            ServerProtocol::Jmap => {
                server.spawn(JmapSessionManager::new(jmap.clone()), shutdown_rx)
            }
            _ => unreachable!(),
        };
    });

    // Create tables
    create_test_directory(jmap.directory.as_ref()).await;
    create_test_user(jmap.directory.as_ref(), "admin", "secret", "Superuser").await;
    add_to_group(jmap.directory.as_ref(), "admin", "superusers").await;

    if delete_if_exists {
        jmap.store.destroy().await;
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
        server: jmap,
        temp_dir,
        client,
        shutdown_tx,
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
