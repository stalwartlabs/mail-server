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

use std::time::{Duration, Instant};

use directory::core::config::ConfigDirectory;
use mail_auth::MX;
use smtp_proto::{AUTH_LOGIN, AUTH_PLAIN};
use store::{config::ConfigStore, Store};
use utils::{
    config::{if_block::IfBlock, Config},
    expr::Expression,
};

use crate::{
    directory::DirectoryStore,
    smtp::{
        session::{TestSession, VerifyResponse},
        ParseTestConfig, TestConfig,
    },
    store::TempDir,
};
use smtp::{
    config::{map_expr_token, session::Mechanism, ConfigContext},
    core::{eval::*, Session, SMTP},
    queue::RecipientDomain,
};

const CONFIG: &str = r#"
[storage]
lookup = "sql"

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
    /*let disable = true;
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
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
    core.shared.lookup_stores = ctx.stores.lookup_stores.clone();
    core.shared.directories = config
        .parse_directory(&ctx.stores, Store::default())
        .await
        .unwrap()
        .directories;
    core.resolvers.dns.mx_add(
        "test.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );

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

    // Test expression functions
    for (expr, expected) in [
        (
            "sql_query('sql', 'SELECT description FROM domains WHERE name = ?', 'foobar.org')",
            "Main domain",
        ),
        ("dns_query(rcpt_domain, 'mx')[0]", "mx.foobar.org"),
        (
            concat!(
                "key_get('sql', 'hello') + '-' + key_exists('sql', 'hello') + '-' + ",
                "key_set('sql', 'hello', 'world') + '-' + key_get('sql', 'hello') + ",
                "'-' + key_exists('sql', 'hello')"
            ),
            "0-0-1-world-1",
        ),
        (
            concat!(
                "counter_get('sql', 'county') + '-' + counter_incr('sql', 'county', 1) + '-' ",
                "+ counter_incr('sql', 'county', 1) + '-' + counter_get('sql', 'county')"
            ),
            "0-1-2-2",
        ),
    ] {
        let e = Expression::parse("test", expr, |name| {
            map_expr_token::<Duration>(
                name,
                &[
                    V_RECIPIENT,
                    V_RECIPIENT_DOMAIN,
                    V_SENDER,
                    V_SENDER_DOMAIN,
                    V_MX,
                    V_HELO_DOMAIN,
                    V_AUTHENTICATED_AS,
                    V_LISTENER,
                    V_REMOTE_IP,
                    V_LOCAL_IP,
                    V_PRIORITY,
                ],
            )
        })
        .unwrap();
        assert_eq!(
            core.eval_expr::<String, _>(&e, &RecipientDomain::new("test.org"), "text")
                .await
                .unwrap(),
            expected,
            "failed for '{}'",
            expr
        );
    }

    // Enable AUTH
    let config = &mut core.session.config.auth;
    config.directory = "\"'sql'\"".parse_if();
    config.mechanisms = IfBlock::new(Mechanism::from(AUTH_PLAIN | AUTH_LOGIN));
    config.errors_wait = IfBlock::new(Duration::from_millis(5));

    // Enable VRFY/EXPN/RCPT
    let config = &mut core.session.config.rcpt;
    config.directory = "\"'sql'\"".parse_if();
    config.relay = IfBlock::new(false);
    config.errors_wait = IfBlock::new(Duration::from_millis(5));

    // Enable REQUIRETLS based on SQL lookup
    core.session.config.extensions.requiretls =
        r#"[{if = "key_exists('sql/is_ip_allowed', remote_ip)", then = true},
    {else = false}]"#
            .parse_if();
    let mut session = Session::test(core);
    session.data.remote_ip_str = "10.0.0.50".parse().unwrap();
    session.eval_session_params().await;
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("REQUIRETLS");
    session.data.remote_ip_str = "10.0.0.1".to_string();
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
