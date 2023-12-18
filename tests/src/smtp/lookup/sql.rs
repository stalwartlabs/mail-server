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

use std::time::Duration;

use directory::core::config::ConfigDirectory;
use smtp_proto::{AUTH_LOGIN, AUTH_PLAIN};
use store::config::ConfigStore;
use utils::config::{Config, DynValue};

use crate::{
    directory::DirectoryStore,
    smtp::{
        session::{TestSession, VerifyResponse},
        ParseTestConfig, TestConfig,
    },
    store::TempDir,
};
use smtp::{
    config::{ConfigContext, EnvelopeKey, IfBlock},
    core::{Session, SMTP},
};

const CONFIG: &str = r#"
[store."sql"]
type = "sqlite"
path = "{TMP}/smtp_sql.db"

[store."sql".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ?"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || ? || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || ? LIMIT 1"
is_ip_allowed = "SELECT addr FROM allowed_ips WHERE addr = ? LIMIT 1"

[directory."sql"]
type = "sql"
store = "sql"

[directory."sql".columns]
name = "name"
description = "description"
secret = "secret"
email = "address"
quota = "quota"
type = "type"

"#;

#[tokio::test]
async fn lookup_sql() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Parse settings
    let temp_dir = TempDir::new("smtp_lookup_tests", true);
    let config_file = CONFIG.replace("{TMP}", &temp_dir.path.to_string_lossy());
    let mut core = SMTP::test();
    let mut ctx = ConfigContext::new(&[]);
    let config = Config::new(&config_file).unwrap();
    ctx.stores = config.parse_stores().await.unwrap();
    ctx.directory = config.parse_directory(&ctx.stores, None).unwrap();

    // Obtain directory handle
    let handle = DirectoryStore {
        store: ctx.stores.lookup_stores.get("sql").unwrap().clone(),
    };

    // Create tables
    handle.create_test_directory().await;

    // Create test records
    handle
        .create_test_user_with_email("jane@foobar.org", "s3cr3tp4ss", "Jane")
        .await;
    handle
        .create_test_user_with_email("john@foobar.org", "mypassword", "John")
        .await;
    handle
        .create_test_user_with_email("bill@foobar.org", "123456", "Bill")
        .await;
    handle
        .create_test_user_with_email("mike@foobar.net", "098765", "Mike")
        .await;
    handle
        .link_test_address("jane@foobar.org", "sales@foobar.org", "list")
        .await;
    handle
        .link_test_address("john@foobar.org", "sales@foobar.org", "list")
        .await;
    handle
        .link_test_address("bill@foobar.org", "sales@foobar.org", "list")
        .await;
    handle
        .link_test_address("mike@foobar.net", "support@foobar.org", "list")
        .await;

    for query in [
        "CREATE TABLE domains (name TEXT PRIMARY KEY, description TEXT);",
        "INSERT INTO domains (name, description) VALUES ('foobar.org', 'Main domain');",
        "INSERT INTO domains (name, description) VALUES ('foobar.net', 'Secondary domain');",
        "CREATE TABLE allowed_ips (addr TEXT PRIMARY KEY);",
        "INSERT INTO allowed_ips (addr) VALUES ('10.0.0.50');",
    ] {
        handle
            .store
            .query::<usize>(query, Vec::new())
            .await
            .unwrap();
    }

    // Enable AUTH
    let config = &mut core.session.config.auth;
    config.directory = r"'sql'"
        .parse_if::<Option<DynValue<EnvelopeKey>>>(&ctx)
        .map_if_block(&ctx.directory.directories, "", "")
        .unwrap();
    config.mechanisms = IfBlock::new(AUTH_PLAIN | AUTH_LOGIN);
    config.errors_wait = IfBlock::new(Duration::from_millis(5));

    // Enable VRFY/EXPN/RCPT
    let config = &mut core.session.config.rcpt;
    config.directory = r"'sql'"
        .parse_if::<Option<DynValue<EnvelopeKey>>>(&ctx)
        .map_if_block(&ctx.directory.directories, "", "")
        .unwrap();
    config.relay = IfBlock::new(false);
    config.errors_wait = IfBlock::new(Duration::from_millis(5));

    // Enable REQUIRETLS based on SQL lookup
    core.session.config.extensions.requiretls =
        r"[{if = 'remote-ip', in-list = 'sql/is_ip_allowed', then = true},
    {else = false}]"
            .parse_if(&ctx);
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.50".parse().unwrap();
    session.eval_session_params().await;
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("REQUIRETLS");
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx1.foobar.org")
        .await
        .assert_not_contains("REQUIRETLS");

    // Test RCPT
    session.mail_from("john@example.net", "250").await;

    // External domain
    session.rcpt_to("user@otherdomain.org", "550 5.1.2").await;

    // Non-existant user
    session.rcpt_to("jack@foobar.org", "550 5.1.2").await;

    // Valid users
    session.rcpt_to("jane@foobar.org", "250").await;
    session.rcpt_to("john@foobar.org", "250").await;
    session.rcpt_to("bill@foobar.org", "250").await;

    // Test EXPN
    session
        .cmd("EXPN sales@foobar.org", "250")
        .await
        .assert_contains("jane@foobar.org")
        .assert_contains("john@foobar.org")
        .assert_contains("bill@foobar.org");
    session
        .cmd("EXPN support@foobar.org", "250")
        .await
        .assert_contains("mike@foobar.net");
    session.cmd("EXPN marketing@foobar.org", "550 5.1.2").await;

    // Test VRFY
    session
        .cmd("VRFY john", "250")
        .await
        .assert_contains("john@foobar.org");
    session
        .cmd("VRFY jane", "250")
        .await
        .assert_contains("jane@foobar.org");
    session.cmd("VRFY tim", "550 5.1.2").await;

    // Test AUTH
    session
        .cmd(
            "AUTH PLAIN AGphbmVAZm9vYmFyLm9yZwB3cm9uZ3Bhc3M=",
            "535 5.7.8",
        )
        .await;
    session
        .cmd(
            "AUTH PLAIN AGphbmVAZm9vYmFyLm9yZwBzM2NyM3RwNHNz",
            "235 2.7.0",
        )
        .await;
}
