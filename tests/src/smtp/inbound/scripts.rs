/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::path::PathBuf;

use crate::smtp::{
    inbound::{sign::TextConfigContext, TestMessage, TestQueueEvent},
    session::{TestSession, VerifyResponse},
    TestConfig, TestSMTP,
};
use smtp::{
    config::{
        database::ConfigDatabase, list::ConfigList, scripts::ConfigSieve, session::ConfigSession,
        ConfigContext, EnvelopeKey, IfBlock,
    },
    core::{Session, SMTP},
};
use utils::config::Config;

const CONFIG: &str = r#"
[database."sql"]
address = "sqlite://%PATH%/test.db?mode=rwc"
max-connections = 10
min-connections = 0
idle-timeout = "5m"

[list]
invalid-ehlos = ["spammer.org", "spammer.net"]

[session.data.pipe."test"]
command = [ { if = "remote-ip", eq = "10.0.0.123", then = "/bin/bash" }, 
            { else = false } ]
arguments = ["%CFG_PATH%/pipe_me.sh", "hello", "world"]
timeout = "10s"

[sieve]
from-name = "Sieve Daemon"
from-addr = "sieve@foobar.org"
return-path = ""
hostname = "mx.foobar.org"
sign = ["rsa"]
use-database = "sql"

[sieve.limits]
redirects = 3
out-messages = 5
received-headers = 50
cpu = 10000
nested-includes = 5
duplicate-expiry = "7d"

[sieve.scripts]
connect = '''
require ["variables", "reject"];

if string "${env.remote_ip}" "10.0.0.88" {
    reject "Your IP '${env.remote_ip}' is not welcomed here.";
}
'''

ehlo = '''
require ["variables", "extlists", "reject"];

if string :list "${env.helo_domain}" "list/invalid-ehlos" {
    reject "551 5.1.1 Your domain '${env.helo_domain}' has been blacklisted.";
}
'''

mail = '''
require ["variables", "vnd.stalwart.execute", "envelope", "reject"];

if envelope :localpart :is "from" "spammer" {
    reject "450 4.1.1 Invalid address";
}

execute :query "CREATE TABLE IF NOT EXISTS blocked_senders (addr TEXT PRIMARY KEY)";
execute :query "INSERT OR IGNORE INTO blocked_senders (addr) VALUES (?)" "marketing@spam-domain.com";

if execute :query "SELECT EXISTS(SELECT 1 FROM blocked_senders WHERE addr=? LIMIT 1)" ["${envelope.from}"] {
    reject "Your address has been blocked.";
}
'''

rcpt = '''
require ["variables", "vnd.stalwart.execute", "envelope", "reject"];

if envelope :domain :is "to" "foobar.org" {
    execute :query "CREATE TABLE IF NOT EXISTS greylist (addr TEXT PRIMARY KEY)";

    set "triplet" "${env.remote_ip}.${envelope.from}.${envelope.to}";

    if not execute :query "SELECT EXISTS(SELECT 1 FROM greylist WHERE addr=? LIMIT 1)" ["${triplet}"] {
        execute :query "INSERT INTO greylist (addr) VALUES (?)" ["${triplet}"];
        reject "422 4.2.2 You have been greylisted '${triplet}'.";
    }
}

'''

data = '''
require ["envelope", "reject", "variables", "replace", "mime", "foreverypart", "editheader", "extracttext", "enotify"];

if envelope :localpart :is "to" "bill" {
    reject "Bill cannot receive messages.";
    stop;
}

if envelope :localpart :is "to" "jane" {
    set "counter" "a";
    foreverypart {
        if header :mime :contenttype "content-type" "text/html" {
            extracttext :upper "text_content";
            replace "${text_content}";
        }
        set :length "part_num" "${counter}";
        addheader :last "X-Part-Number" "${part_num}";
        set "counter" "${counter}a";
    }
}

if envelope :domain :is "to" "foobar.net" {
    notify "mailto:john@example.net?cc=jane@example.org&subject=You%20have%20got%20mail";
}
'''

"#;

#[tokio::test]
async fn sieve_scripts() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    let mut pipe_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pipe_path.push("resources");
    pipe_path.push("smtp");
    pipe_path.push("pipe");

    // Prepare config
    let mut core = SMTP::test();
    let mut qr = core.init_test_queue("smtp_sieve_test");
    let mut ctx = ConfigContext::new(&[]).parse_signatures();
    let config = Config::parse(
        &CONFIG
            .replace("%PATH%", qr._temp_dir.temp_dir.as_path().to_str().unwrap())
            .replace("%CFG_PATH%", pipe_path.as_path().to_str().unwrap()),
    )
    .unwrap();
    config.parse_lists(&mut ctx).unwrap();
    config.parse_databases(&mut ctx).unwrap();
    let pipes = config.parse_pipes(&ctx, &[EnvelopeKey::RemoteIp]).unwrap();
    core.sieve = config.parse_sieve(&mut ctx).unwrap();
    let config = &mut core.session.config;
    config.connect.script = IfBlock::new(ctx.scripts.get("connect").cloned());
    config.ehlo.script = IfBlock::new(ctx.scripts.get("ehlo").cloned());
    config.mail.script = IfBlock::new(ctx.scripts.get("mail").cloned());
    config.rcpt.script = IfBlock::new(ctx.scripts.get("rcpt").cloned());
    config.data.script = IfBlock::new(ctx.scripts.get("data").cloned());
    config.rcpt.relay = IfBlock::new(true);
    config.data.pipe_commands = pipes;

    // Test connect script
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.88".parse().unwrap();
    assert!(!session.init_conn().await);
    session
        .response()
        .assert_contains("503 5.5.3 Your IP '10.0.0.88' is not welcomed here");
    session.data.remote_ip = "10.0.0.5".parse().unwrap();
    assert!(session.init_conn().await);
    session
        .response()
        .assert_contains("220 mx.example.org at your service");

    // Test EHLO script
    session
        .cmd(
            "EHLO spammer.org",
            "551 5.1.1 Your domain 'spammer.org' has been blacklisted",
        )
        .await;
    session.cmd("EHLO foobar.net", "250").await;

    // Test MAIL-FROM script
    session
        .mail_from("spammer@domain.com", "450 4.1.1 Invalid address")
        .await;
    session
        .mail_from(
            "marketing@spam-domain.com",
            "503 5.5.3 Your address has been blocked",
        )
        .await;
    session.mail_from("bill@foobar.org", "250").await;

    // Test RCPT-TO script
    session
        .rcpt_to(
            "jane@foobar.org",
            "422 4.2.2 You have been greylisted '10.0.0.5.bill@foobar.org.jane@foobar.org'.",
        )
        .await;
    session.rcpt_to("jane@foobar.org", "250").await;

    // Expect a modified message
    session.data("test:multipart", "250").await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("X-Part-Number: 5")
        .assert_contains("THIS IS A PIECE OF HTML TEXT");
    qr.assert_empty_queue();

    // Expect rejection for bill@foobar.net
    session
        .send_message(
            "test@example.net",
            &["bill@foobar.net"],
            "test:multipart",
            "503 5.5.3 Bill cannot receive messages",
        )
        .await;
    qr.assert_empty_queue();

    // Expect message delivery plus a notification
    session
        .send_message(
            "test@example.net",
            &["john@foobar.net"],
            "test:multipart",
            "250",
        )
        .await;
    let notification = qr.read_event().await.unwrap_message();
    assert_eq!(notification.return_path, "");
    assert_eq!(notification.recipients.len(), 2);
    assert_eq!(
        notification.recipients.first().unwrap().address,
        "john@example.net"
    );
    assert_eq!(
        notification.recipients.last().unwrap().address,
        "jane@example.org"
    );
    notification
        .read_lines()
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("From: \"Sieve Daemon\" <sieve@foobar.org>")
        .assert_contains("To: <john@example.net>")
        .assert_contains("Cc: <jane@example.org>")
        .assert_contains("Subject: You have got mail")
        .assert_contains("One Two Three Four");
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("One Two Three Four")
        .assert_contains("multi-part message in MIME format")
        .assert_not_contains("X-Part-Number: 5")
        .assert_not_contains("THIS IS A PIECE OF HTML TEXT");
    qr.assert_empty_queue();

    // Expect a modified message delivery plus a notification
    session
        .send_message(
            "test@example.net",
            &["jane@foobar.net"],
            "test:multipart",
            "250",
        )
        .await;

    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("From: \"Sieve Daemon\" <sieve@foobar.org>")
        .assert_contains("To: <john@example.net>")
        .assert_contains("Cc: <jane@example.org>")
        .assert_contains("Subject: You have got mail")
        .assert_contains("One Two Three Four");

    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("X-Part-Number: 5")
        .assert_contains("THIS IS A PIECE OF HTML TEXT")
        .assert_not_contains("X-My-Header: true");

    // Test pipes
    session.data.remote_ip = "10.0.0.123".parse().unwrap();
    session
        .send_message(
            "test@example.net",
            &["pipe@foobar.com"],
            "test:no_dkim",
            "250",
        )
        .await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("X-My-Header: true")
        .assert_contains("Authentication-Results");
    qr.assert_empty_queue();
}
