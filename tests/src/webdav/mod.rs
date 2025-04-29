/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig, add_test_certs, directory::internal::TestInternalDirectory,
    jmap::assert_is_empty, store::TempDir,
};
use ::managesieve::core::ManageSieveSessionManager;
use ::store::Stores;
use ahash::AHashMap;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{
    Caches, Core, Data, DavResource, DavResources, Inner, Server,
    config::{
        server::{Listeners, ServerProtocol},
        telemetry::Telemetry,
    },
    core::BuildServer,
    manager::boot::build_ipc,
};
use groupware::hierarchy::DavHierarchy;
use http::HttpSessionManager;
use hyper::{HeaderMap, Method, StatusCode, header::AUTHORIZATION};
use imap::core::ImapSessionManager;
use jmap_proto::types::collection::Collection;
use pop3::Pop3SessionManager;
use quick_xml::Reader;
use quick_xml::events::Event;
use services::SpawnServices;
use smtp::{SpawnQueueManager, core::SmtpSessionManager};
use std::str;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;
use utils::config::Config;

pub mod basic;
pub mod mkcol;
pub mod put_get;

const SERVER: &str = r#"
[server]
hostname = "webdav.example.org"
http.url = "'https://127.0.0.1:8899'"

[server.listener.webdav]
bind = ["127.0.0.1:8899"]
protocol = "http"
max-connections = 81920
tls.implicit = true

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

[session.data.add-headers]
delivered-to = false

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

[store."psql-replica"]
type = "sql-read-replica"
primary = "postgresql"
replicas = "postgresql"

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
password = "RtQ-Lu6+o4rxx=XJplVJ"
disable = true

[store."elastic".tls]
allow-invalid-certs = true

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[storage]
data = "{STORE}"
fts = "{STORE}"
blob = "{STORE}"
lookup = "{STORE}"
directory = "{STORE}"

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

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
disabled-events = ["network.*"]
 
"#;

#[allow(dead_code)]
pub struct WebDavTest {
    server: Server,
    clients: AHashMap<&'static str, DummyWebDavClient>,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_webdav_tests(store_id: &str, delete_if_exists: bool) -> WebDavTest {
    // Load and parse config
    let temp_dir = TempDir::new("webdav_tests", delete_if_exists);
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
    let tracers = Telemetry::parse(&mut config, &stores);
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let data = Data::parse(&mut config);
    let cache = Caches::parse(&mut config);

    let store = core.storage.data.clone();
    let (ipc, mut ipc_rxs) = build_ipc(&mut config);
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

    // Create test accounts
    let mut clients = AHashMap::new();
    for (account, secret, name, email) in [
        ("admin", "secret1", "Superuser", "admin@example,com"),
        ("john", "secret2", "John Doe", "jdoe@example.com"),
        ("jane", "secret3", "Jane Smith", "jane.smith@example.com"),
        ("bill", "secret4", "Bill Foobar", "bill@example,com"),
        ("mike", "secret5", "Mile Noquota", "mike@example,com"),
    ] {
        let account_id = store
            .create_test_user(account, secret, name, &[email])
            .await;
        clients.insert(
            account,
            DummyWebDavClient::new(account_id, account, secret, email),
        );
        if account == "mike" {
            store.set_test_quota(account, 10).await;
        }
    }
    store
        .create_test_group(
            "support@example.com",
            "Support Group",
            &["support@example.com"],
        )
        .await;
    store.add_to_group("jane", "support@example.com").await;

    WebDavTest {
        server: inner.build_server(),
        clients,
        temp_dir,
        shutdown_tx,
    }
}

#[tokio::test]
pub async fn webdav_tests() {
    // Prepare settings
    let start_time = Instant::now();
    let delete = true;
    let handle = init_webdav_tests(
        &std::env::var("STORE")
            .expect("Missing store type. Try running `STORE=<store_type> cargo test`"),
        delete,
    )
    .await;

    //basic::test(&handle).await;
    //put_get::test(&handle).await;
    mkcol::test(&handle).await;

    // Print elapsed time
    let elapsed = start_time.elapsed();
    println!(
        "Elapsed: {}.{:03}s",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    // Remove test data
    if delete {
        handle.temp_dir.delete();
    }
}

impl WebDavTest {
    pub fn client(&self, name: &'static str) -> &DummyWebDavClient {
        self.clients.get(name).unwrap()
    }

    pub async fn resources(&self, name: &'static str, collection: Collection) -> Arc<DavResources> {
        let account_id = self.client(name).account_id;
        let access_token = self.server.get_access_token(account_id).await.unwrap();
        self.server
            .fetch_dav_resources(&access_token, account_id, collection)
            .await
            .unwrap()
    }

    pub async fn assert_is_empty(&self) {
        assert_is_empty(self.server.clone()).await;
    }
}

#[allow(dead_code)]
pub struct DummyWebDavClient {
    account_id: u32,
    name: &'static str,
    email: &'static str,
    credentials: String,
}

pub struct DavResponse {
    headers: AHashMap<String, String>,
    status: StatusCode,
    body: Result<String, String>,
    xml: Vec<(String, String)>,
}

impl DummyWebDavClient {
    pub fn new(
        account_id: u32,
        name: &'static str,
        secret: &'static str,
        email: &'static str,
    ) -> Self {
        Self {
            account_id,
            name,
            email,
            credentials: format!(
                "Basic {}",
                STANDARD.encode(format!("{name}:{secret}").as_bytes())
            ),
        }
    }

    pub async fn request(&self, method: &str, query: &str, body: impl Into<String>) -> DavResponse {
        self.request_with_headers(method, query, [].into_iter(), body)
            .await
    }

    pub async fn request_with_headers(
        &self,
        method: &str,
        query: &str,
        headers: impl IntoIterator<Item = (&'static str, &str)>,
        body: impl Into<String>,
    ) -> DavResponse {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(
                Method::from_bytes(method.as_bytes()).unwrap(),
                format!("https://127.0.0.1:8899{query}"),
            );

        let body = body.into();
        if !body.is_empty() {
            request = request.body(body);
        }

        let mut request_headers = HeaderMap::new();
        for (key, value) in headers {
            request_headers.insert(key, value.parse().unwrap());
        }
        request_headers.insert(AUTHORIZATION, self.credentials.parse().unwrap());

        let response = request.headers(request_headers).send().await.unwrap();
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string().to_lowercase(),
                    v.to_str().unwrap().to_string(),
                )
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .map_err(|err| err.to_string());
        let xml = match &body {
            Ok(body) if body.starts_with("<?xml") => flatten_xml(body),
            _ => vec![],
        };

        DavResponse {
            headers,
            status,
            body,
            xml,
        }
    }

    pub async fn mkcol(
        &self,
        method: &str,
        path: &str,
        resource_types: impl IntoIterator<Item = &str>,
        properties: impl IntoIterator<Item = (&str, &str)>,
    ) -> DavResponse {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:mkcol xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" xmlns:B=\"urn:ietf:params:xml:ns:carddav\">",
            "<D:set><D:prop><D:resourcetype>"
        )
        .to_string();

        for resource_type in resource_types {
            request.push_str(&format!("<{resource_type}/>"));
        }

        request.push_str("</D:resourcetype>");

        for (key, value) in properties {
            request.push_str(&format!("<{key}>{value}</{key}>"));
        }
        request.push_str("</D:prop></D:set></D:mkcol>");

        if method == "MKCALENDAR" {
            request = request.replace("D:mkcol", "A:mkcalendar");
        }

        self.request(method, path, &request).await
    }

    pub async fn propfind(
        &self,
        path: &str,
        properties: impl IntoIterator<Item = &str>,
    ) -> DavResponse {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:propfind xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" xmlns:B=\"urn:ietf:params:xml:ns:carddav\">",
            "<D:prop>"
        )
        .to_string();

        for property in properties {
            request.push_str(&format!("<{property}/>"));
        }

        request.push_str("</D:prop></D:propfind>");

        self.request("PROPFIND", path, &request).await
    }

    pub async fn delete_default_containers(&self) {
        for col in ["card", "cal"] {
            self.request("DELETE", &format!("/dav/{col}/{}/default", self.name), "")
                .await
                .with_status(StatusCode::NO_CONTENT);
        }
    }
}

impl DavResponse {
    pub fn with_status(&self, status: StatusCode) -> &Self {
        if self.status != status {
            self.dump_response();
            panic!("Expected {status} but got {}", self.status)
        }
        self
    }

    pub fn with_redirect_to(&self, url: &str) -> &Self {
        self.with_status(StatusCode::TEMPORARY_REDIRECT)
            .with_header("location", url)
    }

    pub fn with_header(&self, header: &str, value: &str) -> &Self {
        if self.headers.get(header).is_some_and(|v| v == value) {
            self
        } else {
            self.dump_response();
            panic!("Header {header}:{value} not found.")
        }
    }

    pub fn with_body(&self, expect_body: impl AsRef<str>) -> &Self {
        let expect_body = expect_body.as_ref();
        if self.body.is_ok() {
            let body = self.body.as_ref().unwrap();
            if body != expect_body {
                self.dump_response();
                assert_eq!(body, &expect_body);
            }
            self
        } else {
            self.dump_response();
            panic!("Expected body {expect_body:?} but no body was returned.")
        }
    }

    pub fn header(&self, header: &str) -> &str {
        if let Some(value) = self.headers.get(header) {
            value
        } else {
            self.dump_response();
            panic!("Header {header} not found.")
        }
    }

    pub fn etag(&self) -> &str {
        self.header("etag")
    }

    fn dump_response(&self) {
        eprintln!("-------------------------------------");
        eprintln!("Status: {}", self.status);
        eprintln!("Headers:");
        for (key, value) in self.headers.iter() {
            eprintln!("  {}: {:?}", key, value);
        }
        if !self.xml.is_empty() {
            for (key, value) in self.xml.iter() {
                eprintln!("{} -> {:?}", key, value);
            }
        } else {
            eprintln!("Body: {:?}", self.body);
        }
    }

    fn find_keys(&self, name: &str) -> impl Iterator<Item = &str> {
        self.xml
            .iter()
            .filter(move |(key, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    // Poor man's XPath
    pub fn match_one(&self, query: &str, expect: impl AsRef<str>) -> &Self {
        let expect = expect.as_ref();
        if let Some(value) = self.find_keys(query).next() {
            if value != expect {
                self.dump_response();
                panic!("Expected {query} = {expect:?} but got {value:?}");
            }
        } else {
            self.dump_response();
            panic!("Key {query} not found.");
        }
        self
    }

    pub fn match_many<I, T>(&self, query: &str, expect: I) -> &Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let expect_owned: Vec<T> = expect.into_iter().collect();
        let expect = expect_owned.iter().map(|s| s.as_ref()).collect::<Vec<_>>();
        let found = self.find_keys(query).collect::<Vec<_>>();
        if expect != found {
            self.dump_response();
            panic!("Expected {query} = {expect:?} but got {found:?}");
        }
        self
    }

    pub fn with_failed_precondition(&self, precondition: &str, value: &str) -> &Self {
        let error = format!("D:error.{precondition}");
        if self.find_keys(&error).next().is_none_or(|v| v != value) {
            self.dump_response();
            panic!("Precondition {precondition} did not match.");
        }
        self
    }
}

pub trait DavResourcesTest {
    fn items(&self) -> Vec<DavResource>;
}

impl DavResourcesTest for DavResources {
    fn items(&self) -> Vec<DavResource> {
        self.paths.iter().cloned().collect()
    }
}

fn flatten_xml(xml: &str) -> Vec<(String, String)> {
    let mut reader = Reader::from_str(xml);

    let mut path: Vec<String> = Vec::new();
    let mut result: Vec<(String, String)> = Vec::new();
    let mut buf = Vec::new();
    let mut text_content: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf).unwrap() {
            Event::Start(ref e) => {
                let name = str::from_utf8(e.name().as_ref()).unwrap().to_string();
                path.push(name);
                for attr in e.attributes() {
                    let attr = attr.unwrap();
                    let key = str::from_utf8(attr.key.as_ref()).unwrap().to_string();
                    let value = attr.unescape_value().unwrap();
                    let value_str = value.trim().to_string();

                    result.push((format!("{}.[{}]", path.join("."), key), value_str));
                }
                text_content = None;
            }
            Event::Empty(ref e) => {
                let name = str::from_utf8(e.name().as_ref()).unwrap().to_string();
                result.push((format!("{}.{}", path.join("."), name), "".to_string()));
            }
            Event::Text(e) => {
                let text = e.unescape().unwrap();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    text_content = Some(trimmed.to_string());
                }
            }
            Event::CData(e) => {
                text_content = Some(std::str::from_utf8(e.as_ref()).unwrap().to_string());
            }
            Event::End(_) => {
                if let Some(text) = text_content.take() {
                    result.push((path.join("."), text));
                }

                if !path.is_empty() {
                    path.pop();
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    result
}

pub const TEST_VCARD_1: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:18F098B5-7383-4FD6-B482-48F2181D73AA
X-TEST:SEQ1
N:Coyote;Wile;E.;;
FN:Wile E. Coyote
ORG:ACME Inc.;
END:VCARD
"#;

pub const TEST_VCARD_2: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:6exhjr32bt783wwlr9u0sr8lfqse5x7zqc8y
X-TEST:SEQ1
FN:Joe Citizen
N:Citizen;Joe;;;
NICKNAME:human_being
EMAIL;TYPE=pref:jcitizen@foo.com
REV:20200411T072429Z
END:VCARD
"#;

pub const TEST_ICAL_1: &str = r#"BEGIN:VCALENDAR
SOURCE;VALUE=URI:http://calendar.example.com/event_with_html.ics
X-TEST:SEQ1
BEGIN:VEVENT
UID: 2371c2d9-a136-43b0-bba3-f6ab249ad46e
SUMMARY:What a nice present: 🎁
DTSTART;TZID=America/New_York:20190221T170000
DTEND;TZID=America/New_York:20190221T180000
LOCATION:Germany
DESCRIPTION:<html><body><h1>Title</h1><p><ul><li><b>first</b> Row </li><li><
 i>second</i> Row</li></ul></p></body></html>
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_ICAL_2: &str = r#"BEGIN:VCALENDAR
X-TEST:SEQ1
BEGIN:VEVENT
UID:0000001
SUMMARY:Treasure Hunting
DTSTART;TZID=America/Los_Angeles:20150706T120000
DTEND;TZID=America/Los_Angeles:20150706T130000
RRULE:FREQ=DAILY;COUNT=10
EXDATE;TZID=America/Los_Angeles:20150708T120000
EXDATE;TZID=America/Los_Angeles:20150710T120000
END:VEVENT
BEGIN:VEVENT
UID:0000001
SUMMARY:More Treasure Hunting
LOCATION:The other island
DTSTART;TZID=America/Los_Angeles:20150709T150000
DTEND;TZID=America/Los_Angeles:20150707T160000
RECURRENCE-ID;TZID=America/Los_Angeles:20150707T120000
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_FILE_1: &str = r#"this is a test file
with some text
and some more text

X-TEST:SEQ1
"#;

pub const TEST_FILE_2: &str = r#"another test file
with amazing content
and some more text

X-TEST:SEQ1
"#;

pub const TEST_VTIMEZONE_1: &str = r#"BEGIN:VCALENDAR
PRODID:-//Example Corp.//CalDAV Client//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:US-Eastern
LAST-MODIFIED:19870101T000000Z
BEGIN:STANDARD
DTSTART:19671029T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
TZNAME:Eastern Standard Time (US Canada)
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19870405T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
TZNAME:Eastern Daylight Time (US Canada)
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
"#;
