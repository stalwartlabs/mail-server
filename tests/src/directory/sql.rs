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

use directory::{Directory, Principal, Type};
use mail_send::Credentials;

use crate::directory::parse_config;

#[tokio::test]
async fn sql_directory() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Obtain directory handle
    let mut config = parse_config();
    let lookups = config.lookups;
    let handle = config.directories.remove("sql").unwrap();

    // Create tables
    create_test_directory(handle.as_ref()).await;

    // Create test users
    create_test_user(handle.as_ref(), "john", "12345", "John Doe").await;
    create_test_user(handle.as_ref(), "jane", "abcde", "Jane Doe").await;
    create_test_user(
        handle.as_ref(),
        "bill",
        "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe",
        "Bill Foobar",
    )
    .await;
    set_test_quota(handle.as_ref(), "bill", 500000).await;

    // Create test groups
    create_test_group(handle.as_ref(), "sales", "Sales Team").await;
    create_test_group(handle.as_ref(), "support", "Support Team").await;

    // Link users to groups
    add_to_group(handle.as_ref(), "john", "sales").await;
    add_to_group(handle.as_ref(), "jane", "sales").await;
    add_to_group(handle.as_ref(), "jane", "support").await;

    // Add email addresses
    link_test_address(handle.as_ref(), "john", "john@example.org", "primary").await;
    link_test_address(handle.as_ref(), "jane", "jane@example.org", "primary").await;
    link_test_address(handle.as_ref(), "bill", "bill@example.org", "primary").await;

    // Add aliases and lists
    link_test_address(handle.as_ref(), "john", "john.doe@example.org", "alias").await;
    link_test_address(handle.as_ref(), "john", "jdoe@example.org", "alias").await;
    link_test_address(handle.as_ref(), "john", "info@example.org", "list").await;
    link_test_address(handle.as_ref(), "jane", "info@example.org", "list").await;
    link_test_address(handle.as_ref(), "bill", "info@example.org", "list").await;

    // Add catch-all user
    create_test_user(handle.as_ref(), "robert", "abcde", "Robert Foobar").await;
    link_test_address(handle.as_ref(), "robert", "robert@catchall.org", "primary").await;
    link_test_address(handle.as_ref(), "robert", "@catchall.org", "alias").await;

    // Text lookup
    assert!(lookups
        .get("sql/domains")
        .unwrap()
        .contains("example.org")
        .await
        .unwrap());

    // Test authentication
    assert_eq!(
        handle
            .authenticate(&Credentials::Plain {
                username: "john".to_string(),
                secret: "12345".to_string()
            })
            .await
            .unwrap()
            .unwrap(),
        Principal {
            name: "john".to_string(),
            description: "John Doe".to_string().into(),
            secrets: vec!["12345".to_string()],
            typ: Type::Individual,
            member_of: vec!["sales".to_string()],
            ..Default::default()
        }
    );
    assert_eq!(
        handle
            .authenticate(&Credentials::Plain {
                username: "bill".to_string(),
                secret: "password".to_string()
            })
            .await
            .unwrap()
            .unwrap(),
        Principal {
            name: "bill".to_string(),
            description: "Bill Foobar".to_string().into(),
            secrets: vec![
                "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe".to_string()
            ],
            typ: Type::Individual,
            quota: 500000,
            ..Default::default()
        }
    );
    assert!(handle
        .authenticate(&Credentials::Plain {
            username: "bill".to_string(),
            secret: "invalid".to_string()
        })
        .await
        .unwrap()
        .is_none());

    // Get user by name
    assert_eq!(
        handle.principal("jane").await.unwrap().unwrap(),
        Principal {
            name: "jane".to_string(),
            description: "Jane Doe".to_string().into(),
            typ: Type::Individual,
            secrets: vec!["abcde".to_string()],
            member_of: vec!["sales".to_string(), "support".to_string()],
            ..Default::default()
        }
    );

    // Get group by name
    assert_eq!(
        handle.principal("sales").await.unwrap().unwrap(),
        Principal {
            name: "sales".to_string(),
            description: "Sales Team".to_string().into(),
            typ: Type::Group,
            ..Default::default()
        }
    );

    // Emails by id
    assert_eq!(
        handle.emails_by_name("john").await.unwrap(),
        vec![
            "john@example.org".to_string(),
            "jdoe@example.org".to_string(),
            "john.doe@example.org".to_string(),
        ]
    );
    assert_eq!(
        handle.emails_by_name("bill").await.unwrap(),
        vec!["bill@example.org".to_string(),]
    );

    // Ids by email
    assert_eq!(
        handle.names_by_email("jane@example.org").await.unwrap(),
        vec!["jane".to_string()]
    );
    assert_eq!(
        handle.names_by_email("info@example.org").await.unwrap(),
        vec!["bill".to_string(), "jane".to_string(), "john".to_string()]
    );
    assert_eq!(
        handle
            .names_by_email("jane+alias@example.org")
            .await
            .unwrap(),
        vec!["jane".to_string()]
    );
    assert_eq!(
        handle
            .names_by_email("info+alias@example.org")
            .await
            .unwrap(),
        vec!["bill".to_string(), "jane".to_string(), "john".to_string()]
    );
    assert_eq!(
        handle.names_by_email("unknown@example.org").await.unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        handle
            .names_by_email("anything@catchall.org")
            .await
            .unwrap(),
        vec!["robert".to_string()]
    );

    // Domain validation
    assert!(handle.is_local_domain("example.org").await.unwrap());
    assert!(!handle.is_local_domain("other.org").await.unwrap());

    // RCPT TO
    assert!(handle.rcpt("jane@example.org").await.unwrap());
    assert!(handle.rcpt("info@example.org").await.unwrap());
    assert!(handle.rcpt("jane+alias@example.org").await.unwrap());
    assert!(handle.rcpt("info+alias@example.org").await.unwrap());
    assert!(handle.rcpt("random_user@catchall.org").await.unwrap());
    assert!(!handle.rcpt("invalid@example.org").await.unwrap());

    // VRFY
    assert_eq!(
        handle.vrfy("jane").await.unwrap(),
        vec!["jane@example.org".to_string()]
    );
    assert_eq!(
        handle.vrfy("john").await.unwrap(),
        vec!["john@example.org".to_string()]
    );
    assert_eq!(
        handle.vrfy("jane+alias@example").await.unwrap(),
        vec!["jane@example.org".to_string()]
    );
    assert_eq!(handle.vrfy("info").await.unwrap(), Vec::<String>::new());
    assert_eq!(handle.vrfy("invalid").await.unwrap(), Vec::<String>::new());

    // EXPN
    assert_eq!(
        handle.expn("info@example.org").await.unwrap(),
        vec![
            "bill@example.org".to_string(),
            "jane@example.org".to_string(),
            "john@example.org".to_string()
        ]
    );
    assert_eq!(
        handle.expn("john@example.org").await.unwrap(),
        Vec::<String>::new()
    );
}

pub async fn create_test_directory(handle: &dyn Directory) {
    // Create tables
    for query in [
        "CREATE TABLE accounts (name TEXT PRIMARY KEY, secret TEXT, description TEXT, type TEXT NOT NULL, quota INTEGER DEFAULT 0, active BOOLEAN DEFAULT 1)",
        "CREATE TABLE group_members (name TEXT NOT NULL, member_of TEXT NOT NULL, PRIMARY KEY (name, member_of))",
        "CREATE TABLE emails (name TEXT NOT NULL, address TEXT NOT NULL, type TEXT, PRIMARY KEY (name, address))",
        "INSERT INTO accounts (name, secret, type) VALUES ('admin', 'secret', 'individual')", 
    ] {
        handle.query(query, &[]).await.unwrap_or_else(|_| panic!("failed for {query}"));
    }
}

pub async fn create_test_user(handle: &dyn Directory, login: &str, secret: &str, name: &str) {
    handle
        .query(
            "INSERT OR IGNORE INTO accounts (name, secret, description, type, active) VALUES (?, ?, ?, 'individual', true)",
            &[login, secret, name],
        )
        .await
        .unwrap();
}

pub async fn create_test_user_with_email(
    handle: &dyn Directory,
    login: &str,
    secret: &str,
    name: &str,
) {
    create_test_user(handle, login, secret, name).await;
    link_test_address(handle, login, login, "primary").await;
}

pub async fn create_test_group(handle: &dyn Directory, login: &str, name: &str) {
    handle
        .query(
            "INSERT OR IGNORE INTO accounts (name, description, type, active) VALUES (?, ?, 'group', true)",
            &[login,  name],
        )
        .await
        .unwrap();
}

pub async fn create_test_group_with_email(handle: &dyn Directory, login: &str, name: &str) {
    create_test_group(handle, login, name).await;
    link_test_address(handle, login, login, "primary").await;
}

pub async fn link_test_address(handle: &dyn Directory, login: &str, address: &str, typ: &str) {
    handle
        .query(
            "INSERT OR IGNORE INTO emails (name, address, type) VALUES (?, ?, ?)",
            &[login, address, typ],
        )
        .await
        .unwrap();
}

pub async fn set_test_quota(handle: &dyn Directory, login: &str, quota: u32) {
    handle
        .query(
            &format!("UPDATE accounts SET quota = {} where name = ?", quota,),
            &[login],
        )
        .await
        .unwrap();
}

pub async fn add_to_group(handle: &dyn Directory, login: &str, group: &str) {
    handle
        .query(
            "INSERT INTO group_members (name, member_of) VALUES (?, ?)",
            &[login, group],
        )
        .await
        .unwrap();
}

pub async fn remove_from_group(handle: &dyn Directory, login: &str, group: &str) {
    handle
        .query(
            "DELETE FROM group_members WHERE name = ? AND member_of = ?",
            &[login, group],
        )
        .await
        .unwrap();
}

pub async fn remove_test_alias(handle: &dyn Directory, login: &str, alias: &str) {
    handle
        .query(
            "DELETE FROM emails WHERE name = ? AND address = ?",
            &[login, alias],
        )
        .await
        .unwrap();
}
