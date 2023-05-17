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

use std::time::Duration;

use smtp_proto::{AUTH_LOGIN, AUTH_PLAIN};
use utils::config::Config;

use crate::smtp::{
    make_temp_dir,
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::{database::ConfigDatabase, ConfigContext, IfBlock},
    core::{Session, SMTP},
    lookup::SqlDatabase,
};

const CONFIG: &str = r#"
[database."sql"]
address = "sqlite://%PATH%/test.db?mode=rwc"
max-connections = 10
min-connections = 0
idle-timeout = "5m"

[database."sql".lookup]
auth = "SELECT secret FROM users WHERE email=?"
rcpt = "SELECT EXISTS(SELECT 1 FROM users WHERE email=? LIMIT 1)"
vrfy = "SELECT email FROM users WHERE email LIKE '%' || ? || '%' LIMIT 5"
expn = "SELECT member FROM mailing_lists WHERE id = ?"
domains = "SELECT EXISTS(SELECT 1 FROM domains WHERE name=? LIMIT 1)"
is_ip_allowed = "SELECT EXISTS(SELECT 1 FROM allowed_ips WHERE addr=? LIMIT 1)"

[database."sql".cache]
enable = ["rcpt", "domains"]
entries = 1000
ttl = {positive = "1d", negative = "1h"}
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
    let mut core = SMTP::test();
    let _temp_dir = make_temp_dir("sql_lookup_test", true);
    let mut ctx = ConfigContext::new(&[]);
    let config =
        Config::parse(&CONFIG.replace("%PATH%", _temp_dir.temp_dir.as_path().to_str().unwrap()))
            .unwrap();
    config.parse_databases(&mut ctx).unwrap();

    // Create test records
    if let SqlDatabase::SqlLite(db) = ctx.databases.get("sql").unwrap() {
        for query in [
            "CREATE TABLE users (email TEXT PRIMARY KEY, secret TEXT NOT NULL);",
            "CREATE TABLE mailing_lists (id TEXT NOT NULL, member TEXT NOT NULL, PRIMARY KEY (id, member));",
            "CREATE TABLE domains (name TEXT PRIMARY KEY, description TEXT);",
            "CREATE TABLE allowed_ips (addr TEXT PRIMARY KEY);",
            "INSERT INTO allowed_ips (addr) VALUES ('10.0.0.50');",
            "INSERT INTO domains (name, description) VALUES ('foobar.org', 'Main domain');",
            "INSERT INTO domains (name, description) VALUES ('foobar.net', 'Secondary domain');",
            "INSERT INTO users (email, secret) VALUES ('jane@foobar.org', 's3cr3tp4ss');",
            "INSERT INTO users (email, secret) VALUES ('john@foobar.org', 'mypassword');",
            "INSERT INTO users (email, secret) VALUES ('bill@foobar.org', '123456');",
            "INSERT INTO mailing_lists (id, member) VALUES ('sales@foobar.org', 'jane@foobar.org');",
            "INSERT INTO mailing_lists (id, member) VALUES ('sales@foobar.org', 'john@foobar.org');",
            "INSERT INTO mailing_lists (id, member) VALUES ('sales@foobar.org', 'bill@foobar.org');",
            "INSERT INTO mailing_lists (id, member) VALUES ('support@foobar.org', 'mike@foobar.net');",
        ] {
            sqlx::query(query).execute(db).await.unwrap();
        }
    } else {
        panic!("Unexpected database type");
    }

    // Enable AUTH
    let mut config = &mut core.session.config.auth;
    config.lookup = r"'db/sql/auth'"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.mechanisms = IfBlock::new(AUTH_PLAIN | AUTH_LOGIN);
    config.errors_wait = IfBlock::new(Duration::from_millis(5));

    // Enable VRFY/EXPN/RCPT
    let mut config = &mut core.session.config.rcpt;
    config.lookup_addresses = r"'db/sql/rcpt'"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.lookup_domains = r"'db/sql/domains'"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.lookup_expn = r"'db/sql/expn'"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.lookup_vrfy = r"'db/sql/vrfy'"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.relay = IfBlock::new(false);
    config.errors_wait = IfBlock::new(Duration::from_millis(5));

    // Enable REQUIRETLS based on SQL lookup
    core.session.config.extensions.requiretls =
        r"[{if = 'remote-ip', in-list = 'db/sql/is_ip_allowed', then = true},
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
