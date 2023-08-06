/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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
pub mod search;
pub mod store;
pub mod thread;

use std::{path::PathBuf, sync::Arc, time::Duration};

use ::managesieve::core::ManageSieveSessionManager;
use directory::config::ConfigDirectory;
use imap::core::{ImapSessionManager, IMAP};
use imap_proto::ResponseType;
use jmap::{api::JmapSessionManager, services::IPC_CHANNEL_BUFFER, JMAP};
use smtp::core::{SmtpSessionManager, SMTP};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, watch},
};
use utils::{config::ServerProtocol, UnwrapFailure};

use crate::{
    add_test_certs,
    directory::sql::{
        add_to_group, create_test_directory, create_test_group_with_email, create_test_user,
        create_test_user_with_email,
    },
    store::TempDir,
};

const SERVER: &str = r#"
[server]
hostname = "imap.example.org"

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

#[allow(dead_code)]
struct IMAPTest {
    jmap: Arc<JMAP>,
    imap: Arc<IMAP>,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_imap_tests(delete_if_exists: bool) -> IMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("imap_tests", delete_if_exists);
    let config = utils::config::Config::parse(
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
    let imap: Arc<IMAP> = IMAP::init(&config)
        .await
        .failed("Invalid configuration file");
    let shutdown_tx = servers.spawn(|server, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Jmap => {
                server.spawn(JmapSessionManager::new(jmap.clone()), shutdown_rx)
            }
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(jmap.clone(), imap.clone()),
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(jmap.clone(), imap.clone()),
                shutdown_rx,
            ),
            ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                server.spawn(SmtpSessionManager::new(smtp.clone()), shutdown_rx)
            }
            _ => unreachable!(),
        };
    });

    // Create tables and test accounts
    create_test_directory(jmap.directory.as_ref()).await;
    create_test_user(jmap.directory.as_ref(), "admin", "secret", "Superuser").await;
    add_to_group(jmap.directory.as_ref(), "admin", "superuser").await;
    create_test_user_with_email(
        jmap.directory.as_ref(),
        "jdoe@example.com",
        "secret",
        "John Doe",
    )
    .await;
    create_test_user_with_email(
        jmap.directory.as_ref(),
        "jane.smith@example.com",
        "secret",
        "Jane Smith",
    )
    .await;
    create_test_user_with_email(
        jmap.directory.as_ref(),
        "foobar@example.com",
        "secret",
        "Bill Foobar",
    )
    .await;
    create_test_group_with_email(
        jmap.directory.as_ref(),
        "support@example.com",
        "Support Group",
    )
    .await;
    add_to_group(
        jmap.directory.as_ref(),
        "jane.smith@example.com",
        "support@example.com",
    )
    .await;

    if delete_if_exists {
        jmap.store.destroy().await;
    }

    // Assign Id 0 to admin (required for some tests)
    jmap.get_account_id("admin").await.unwrap();

    IMAPTest {
        jmap,
        imap,
        temp_dir,
        shutdown_tx,
    }
}

#[tokio::test]
pub async fn imap_tests() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Prepare settings
    let delete = true;
    let handle = init_imap_tests(delete).await;

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
    append::test(&mut imap, &mut imap_check).await;
    search::test(&mut imap, &mut imap_check).await;
    fetch::test(&mut imap, &mut imap_check).await;
    store::test(&mut imap, &mut imap_check).await;
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
                    println!("<- {:?}", line);
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
        println!("-> {}{:?}", std::str::from_utf8(self.tag).unwrap(), text);
        self.writer.write_all(self.tag).await.unwrap();
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_untagged(&mut self, text: &str) {
        println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        println!("-> {:?}", text);
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
    fn assert_count(self, text: &str, occurences: usize) -> Self;
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

    fn assert_count(self, text: &str, occurences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurences,
            "Expected {} occurrences of {:?}, found {}.",
            occurences,
            text,
            self.iter().filter(|l| l.contains(text)).count()
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

fn resources_dir() -> PathBuf {
    let mut resources = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resources.push("resources");
    resources.push("imap");
    resources
}
