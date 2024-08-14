/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod append;
pub mod basic;
pub mod body_structure;
pub mod condstore;
pub mod copy_move;
pub mod fetch;
pub mod idle;
pub mod mailbox;
pub mod managesieve;
pub mod pop;
pub mod search;
pub mod store;
pub mod thread;

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use ::managesieve::core::ManageSieveSessionManager;
use common::{
    config::{
        server::{ServerProtocol, Servers},
        telemetry::Telemetry,
    },
    Core, Ipc, IPC_CHANNEL_BUFFER,
};

use ::store::Stores;
use ahash::AHashSet;
use directory::backend::internal::manage::ManageDirectory;
use imap::core::{ImapSessionManager, Inner, IMAP};
use imap_proto::ResponseType;
use jmap::{api::JmapSessionManager, JMAP};
use pop3::Pop3SessionManager;
use smtp::core::{SmtpSessionManager, SMTP};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, watch},
};
use utils::config::Config;

use crate::{add_test_certs, directory::DirectoryStore, store::TempDir, AssertConfig};

const SERVER: &str = r#"
[server]
hostname = "'imap.example.org'"

[server.listener.imap]
bind = ["127.0.0.1:9991"]
protocol = "imap"
max-connections = 81920

[server.listener.imaptls]
bind = ["127.0.0.1:9992"]
protocol = "imap"
max-connections = 81920
tls.implicit = true

[server.listener.sieve]
bind = ["127.0.0.1:4190"]
protocol = "managesieve"
max-connections = 81920
tls.implicit = true

[server.listener.pop3]
bind = ["127.0.0.1:4110"]
protocol = "pop3"
max-connections = 81920
tls.implicit = true

[server.listener.lmtp-debug]
bind = ['127.0.0.1:11201']
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
enable = false
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
password = "RtQ-Lu6+o4rxx=XJplVJ"
disable = true

[store."elastic".tls]
allow-invalid-certs = true

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[imap.protocol]
uidplus = true

[storage]
data = "{STORE}"
fts = "{STORE}"
blob = "{STORE}"
lookup = "{STORE}"
directory = "auth"

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

[jmap.folders.inbox]
name = "Inbox"
subscribe = false

[jmap.folders.sent]
name = "Sent Items"
subscribe = false

[jmap.folders.trash]
name = "Deleted Items"
subscribe = false

[jmap.folders.junk]
name = "Junk Mail"
subscribe = false

[jmap.folders.drafts]
name = "Drafts"
subscribe = false

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

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
disabled-events = ["network.*"]

"#;

#[allow(dead_code)]
pub struct IMAPTest {
    jmap: Arc<JMAP>,
    imap: Arc<Inner>,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_imap_tests(store_id: &str, delete_if_exists: bool) -> IMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("imap_tests", delete_if_exists);
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
    let mut servers = Servers::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Build stores
    let stores = Stores::parse_all(&mut config).await;

    // Parse core
    let tracers = Telemetry::parse(&mut config, &stores);
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let store = core.storage.data.clone();
    let shared_core = core.into_shared();

    // Parse acceptors
    servers.parse_tcp_acceptors(&mut config, shared_core.clone());

    // Enable tracing
    tracers.enable(true);

    // Setup IPC channels
    let (delivery_tx, delivery_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let ipc = Ipc { delivery_tx };

    // Init servers
    let smtp = SMTP::init(
        &mut config,
        shared_core.clone(),
        ipc,
        servers.span_id_gen.clone(),
    )
    .await;
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

    // Create tables and test accounts
    let lookup = DirectoryStore {
        store: shared_core
            .load()
            .storage
            .lookups
            .get("auth")
            .unwrap()
            .clone(),
    };
    lookup.create_test_directory().await;
    lookup
        .create_test_user("admin", "secret", "Superuser")
        .await;
    lookup
        .create_test_user_with_email("jdoe@example.com", "secret", "John Doe")
        .await;
    lookup
        .create_test_user_with_email("jane.smith@example.com", "secret", "Jane Smith")
        .await;
    lookup
        .create_test_user_with_email("foobar@example.com", "secret", "Bill Foobar")
        .await;
    lookup
        .create_test_user_with_email("popper@example.com", "secret", "Karl Popper")
        .await;
    lookup
        .create_test_group_with_email("support@example.com", "Support Group")
        .await;
    lookup
        .add_to_group("jane.smith@example.com", "support@example.com")
        .await;

    if delete_if_exists {
        store.destroy().await;
    }

    // Assign Id 0 to admin (required for some tests)
    store.get_or_create_account_id("admin").await.unwrap();

    IMAPTest {
        jmap: JMAP::from(jmap.clone()).into(),
        imap: imap.imap_inner,
        temp_dir,
        shutdown_tx,
    }
}

#[tokio::test]
pub async fn imap_tests() {
    // Prepare settings
    let start_time = Instant::now();
    let delete = true;
    let handle = init_imap_tests(
        &std::env::var("STORE")
            .expect("Missing store type. Try running `STORE=<store_type> cargo test`"),
        delete,
    )
    .await;

    // Connect to IMAP server
    let mut imap_check = ImapConnection::connect(b"_y ").await;
    let mut imap = ImapConnection::connect(b"_x ").await;
    for imap in [&mut imap, &mut imap_check] {
        imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    }

    // Unauthenticated tests
    basic::test(&mut imap, &mut imap_check).await;

    // Login
    for imap in [&mut imap, &mut imap_check] {
        imap.send("AUTHENTICATE PLAIN {32+}\r\nAGpkb2VAZXhhbXBsZS5jb20Ac2VjcmV0")
            .await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    }

    // Delete folders
    for mailbox in ["Drafts", "Junk Mail", "Sent Items"] {
        imap.send(&format!("DELETE \"{}\"", mailbox)).await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    }

    mailbox::test(&mut imap, &mut imap_check).await;
    append::test(&mut imap, &mut imap_check, &handle).await;
    search::test(&mut imap, &mut imap_check).await;
    fetch::test(&mut imap, &mut imap_check).await;
    store::test(&mut imap, &mut imap_check, &handle).await;
    copy_move::test(&mut imap, &mut imap_check).await;
    thread::test(&mut imap, &mut imap_check).await;
    idle::test(&mut imap, &mut imap_check).await;
    condstore::test(&mut imap, &mut imap_check).await;
    acl::test(&mut imap, &mut imap_check).await;

    // Logout
    for imap in [&mut imap, &mut imap_check] {
        imap.send("UNAUTHENTICATE").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;

        imap.send("LOGOUT").await;
        imap.assert_read(Type::Untagged, ResponseType::Bye).await;
    }

    // Run ManageSieve tests
    managesieve::test().await;

    // Run POP3 tests
    pop::test().await;

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

pub struct ImapConnection {
    tag: &'static [u8],
    reader: Lines<BufReader<ReadHalf<TcpStream>>>,
    writer: WriteHalf<TcpStream>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Tagged,
    Untagged,
    Continuation,
    Status,
}

impl ImapConnection {
    pub async fn connect(tag: &'static [u8]) -> Self {
        let (reader, writer) =
            tokio::io::split(TcpStream::connect("127.0.0.1:9991").await.unwrap());
        ImapConnection {
            tag,
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    pub async fn assert_read(&mut self, t: Type, rt: ResponseType) -> Vec<String> {
        let lines = self.read(t).await;
        let mut buf = Vec::with_capacity(10);
        buf.extend_from_slice(match t {
            Type::Tagged => self.tag,
            Type::Untagged | Type::Status => b"* ",
            Type::Continuation => b"+ ",
        });
        if !matches!(t, Type::Continuation | Type::Status) {
            rt.serialize(&mut buf);
        }
        if lines
            .last()
            .unwrap()
            .starts_with(&String::from_utf8(buf).unwrap())
        {
            lines
        } else {
            panic!("Expected {:?}/{:?} from server but got: {:?}", t, rt, lines);
        }
    }

    pub async fn assert_disconnect(&mut self) {
        match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
            Ok(Ok(None)) => {}
            Ok(Ok(Some(line))) => {
                panic!("Expected connection to be closed, but got {:?}", line);
            }
            Ok(Err(err)) => {
                panic!("Connection broken: {:?}", err);
            }
            Err(_) => panic!("Timeout while waiting for server response."),
        }
    }

    pub async fn read(&mut self, t: Type) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = line.starts_with(match t {
                        Type::Tagged => std::str::from_utf8(self.tag).unwrap(),
                        Type::Untagged | Type::Status => "* ",
                        Type::Continuation => "+ ",
                    });
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {}{:?}", std::str::from_utf8(self.tag).unwrap(), text);
        self.writer.write_all(self.tag).await.unwrap();
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_untagged(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}

pub trait AssertResult: Sized {
    fn assert_folders<'x>(
        self,
        expected: impl IntoIterator<Item = (&'x str, impl IntoIterator<Item = &'x str>)>,
        match_all: bool,
    ) -> Self;

    fn assert_response_code(self, code: &str) -> Self;
    fn assert_contains(self, text: &str) -> Self;
    fn assert_count(self, text: &str, occurrences: usize) -> Self;
    fn assert_equals(self, text: &str) -> Self;
    fn into_response_code(self) -> String;
    fn into_highest_modseq(self) -> String;
    fn into_uid_validity(self) -> String;
    fn into_append_uid(self) -> String;
    fn into_copy_uid(self) -> String;
    fn into_modseq(self) -> String;
}

impl AssertResult for Vec<String> {
    fn assert_folders<'x>(
        self,
        expected: impl IntoIterator<Item = (&'x str, impl IntoIterator<Item = &'x str>)>,
        match_all: bool,
    ) -> Self {
        let mut match_count = 0;
        'outer: for (mailbox_name, flags) in expected.into_iter() {
            for result in self.iter() {
                if result.contains(&format!("\"{}\"", mailbox_name)) {
                    for flag in flags {
                        if !flag.is_empty() && !result.contains(flag) {
                            panic!("Expected mailbox {} to have flag {}", mailbox_name, flag);
                        }
                    }
                    match_count += 1;
                    continue 'outer;
                }
            }
            panic!("Mailbox {} is not present.", mailbox_name);
        }
        if match_all && match_count != self.len() - 1 {
            panic!(
                "Expected {} mailboxes, but got {}",
                match_count,
                self.len() - 1
            );
        }
        self
    }

    fn assert_response_code(self, code: &str) -> Self {
        if !self.last().unwrap().contains(&format!("[{}]", code)) {
            panic!(
                "Response code {:?} not found, got {:?}",
                code,
                self.last().unwrap()
            );
        }
        self
    }

    fn assert_contains(self, text: &str) -> Self {
        for line in &self {
            if line.contains(text) {
                return self;
            }
        }
        panic!("Expected response to contain {:?}, got {:?}", text, self);
    }

    fn assert_count(self, text: &str, occurrences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurrences,
            "Expected {} occurrences of {:?}, found {} in {:?}.",
            occurrences,
            text,
            self.iter().filter(|l| l.contains(text)).count(),
            self
        );
        self
    }

    fn assert_equals(self, text: &str) -> Self {
        for line in &self {
            if line == text {
                return self;
            }
        }
        panic!("Expected response to be {:?}, got {:?}", text, self);
    }

    fn into_response_code(self) -> String {
        if let Some((_, code)) = self.last().unwrap().split_once('[') {
            if let Some((code, _)) = code.split_once(']') {
                return code.to_string();
            }
        }
        panic!("No response code found in {:?}", self.last().unwrap());
    }

    fn into_append_uid(self) -> String {
        if let Some((_, code)) = self.last().unwrap().split_once("[APPENDUID ") {
            if let Some((code, _)) = code.split_once(']') {
                if let Some((_, uid)) = code.split_once(' ') {
                    return uid.to_string();
                }
            }
        }
        panic!("No APPENDUID found in {:?}", self.last().unwrap());
    }

    fn into_copy_uid(self) -> String {
        for line in &self {
            if let Some((_, code)) = line.split_once("[COPYUID ") {
                if let Some((code, _)) = code.split_once(']') {
                    if let Some((_, uid)) = code.rsplit_once(' ') {
                        return uid.to_string();
                    }
                }
            }
        }
        panic!("No COPYUID found in {:?}", self);
    }

    fn into_highest_modseq(self) -> String {
        for line in &self {
            if let Some((_, value)) = line.split_once("HIGHESTMODSEQ ") {
                if let Some((value, _)) = value.split_once(']') {
                    return value.to_string();
                } else if let Some((value, _)) = value.split_once(')') {
                    return value.to_string();
                } else {
                    panic!("No HIGHESTMODSEQ delimiter found in {:?}", line);
                }
            }
        }
        panic!("No HIGHESTMODSEQ entries found in {:?}", self);
    }

    fn into_modseq(self) -> String {
        for line in &self {
            if let Some((_, value)) = line.split_once("MODSEQ (") {
                if let Some((value, _)) = value.split_once(')') {
                    return value.to_string();
                } else {
                    panic!("No MODSEQ delimiter found in {:?}", line);
                }
            }
        }
        panic!("No MODSEQ entries found in {:?}", self);
    }

    fn into_uid_validity(self) -> String {
        for line in &self {
            if let Some((_, value)) = line.split_once("UIDVALIDITY ") {
                if let Some((value, _)) = value.split_once(']') {
                    return value.to_string();
                } else if let Some((value, _)) = value.split_once(')') {
                    return value.to_string();
                } else {
                    panic!("No UIDVALIDITY delimiter found in {:?}", line);
                }
            }
        }
        panic!("No UIDVALIDITY entries found in {:?}", self);
    }
}

pub fn expand_uid_list(list: &str) -> AHashSet<u32> {
    let mut items = AHashSet::new();
    for uid in list.split(',') {
        if let Some((start, end)) = uid.split_once(':') {
            let start = start.parse::<u32>().unwrap();
            let end = end.parse::<u32>().unwrap();
            for uid in start..=end {
                items.insert(uid);
            }
        } else {
            items.insert(uid.parse::<u32>().unwrap());
        }
    }

    items
}

fn resources_dir() -> PathBuf {
    let mut resources = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resources.push("resources");
    resources.push("imap");
    resources
}
