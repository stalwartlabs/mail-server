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

use ahash::AHashMap;
use directory::{Principal, Type};
use mail_send::Credentials;
use smtp::core::Lookup;
use store::{LookupStore, Store};

use crate::directory::parse_config;

use super::DirectoryStore;

#[tokio::test]
async fn sql_directory() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Parse config
    let mut config = parse_config().await;
    let lookups = config
        .stores
        .lookups
        .into_iter()
        .map(|(k, v)| (k, Lookup::from(v)))
        .collect::<AHashMap<_, _>>();

    // Obtain directory handle
    for directory_id in ["sqlite", "postgresql", "mysql"] {
        println!("Testing SQL directory {:?}", directory_id);
        let handle = config.directories.directories.remove(directory_id).unwrap();
        let store = DirectoryStore {
            store: config.stores.lookup_stores.remove(directory_id).unwrap(),
        };

        // Create tables
        store.create_test_directory().await;

        // Create test users
        store.create_test_user("john", "12345", "John Doe").await;
        store.create_test_user("jane", "abcde", "Jane Doe").await;
        store
            .create_test_user(
                "bill",
                "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe",
                "Bill Foobar",
            )
            .await;
        store.set_test_quota("bill", 500000).await;

        // Create test groups
        store.create_test_group("sales", "Sales Team").await;
        store.create_test_group("support", "Support Team").await;

        // Link users to groups
        store.add_to_group("john", "sales").await;
        store.add_to_group("jane", "sales").await;
        store.add_to_group("jane", "support").await;

        // Add email addresses
        store
            .link_test_address("john", "john@example.org", "primary")
            .await;
        store
            .link_test_address("jane", "jane@example.org", "primary")
            .await;
        store
            .link_test_address("bill", "bill@example.org", "primary")
            .await;

        // Add aliases and lists
        store
            .link_test_address("john", "john.doe@example.org", "alias")
            .await;
        store
            .link_test_address("john", "jdoe@example.org", "alias")
            .await;
        store
            .link_test_address("john", "info@example.org", "list")
            .await;
        store
            .link_test_address("jane", "info@example.org", "list")
            .await;
        store
            .link_test_address("bill", "info@example.org", "list")
            .await;

        // Add catch-all user
        store
            .create_test_user("robert", "abcde", "Robert Foobar")
            .await;
        store
            .link_test_address("robert", "robert@catchall.org", "primary")
            .await;
        store
            .link_test_address("robert", "@catchall.org", "alias")
            .await;

        // Text lookup
        assert!(lookups
            .get(&format!("{}/domains", directory_id))
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
}

impl DirectoryStore {
    pub async fn create_test_directory(&self) {
        // Create tables
        for table in ["accounts", "group_members", "emails"] {
            self.store
                .query::<usize>(&format!("DROP TABLE IF EXISTS {table}"), vec![])
                .await
                .unwrap();
        }
        for query in [
            concat!(
                "CREATE TABLE accounts (name TEXT PRIMARY KEY, secret TEXT, description TEXT,",
                " type TEXT NOT NULL, quota INTEGER ",
                "DEFAULT 0, active BOOLEAN DEFAULT TRUE)"
            ),
            concat!(
                "CREATE TABLE group_members (name TEXT NOT NULL, member_of ",
                "TEXT NOT NULL, PRIMARY KEY (name, member_of))"
            ),
            concat!(
                "CREATE TABLE emails (name TEXT NOT NULL, address TEXT NOT",
                " NULL, type TEXT, PRIMARY KEY (name, address))"
            ),
            "INSERT INTO accounts (name, secret, type) VALUES ('admin', 'secret', 'individual')",
        ] {
            let query = if matches!(self.store, LookupStore::Store(Store::MySQL(_))) {
                query.replace("TEXT", "VARCHAR(255)")
            } else {
                query.to_string()
            };

            self.store
                .query::<usize>(&query, vec![])
                .await
                .unwrap_or_else(|_| panic!("failed for {query}"));
        }
    }

    pub async fn create_test_user(&self, login: &str, secret: &str, name: &str) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    concat!(
                        "INSERT INTO accounts (name, secret, description, ",
                        "type, active) VALUES ($1, $2, $3, 'individual', true) ON CONFLICT (name) DO NOTHING"
                    )
                } else if matches!(self.store, LookupStore::Store(Store::MySQL(_))) {
                    concat!(
                        "INSERT IGNORE INTO accounts (name, secret, description, ",
                        "type, active) VALUES (?, ?, ?, 'individual', true)"
                    )
                } else {
                    concat!(
                        "INSERT OR IGNORE INTO accounts (name, secret, description, ",
                        "type, active) VALUES (?, ?, ?, 'individual', true)"
                    )
                },
                vec![login.into(), secret.into(), name.into()],
            )
            .await
            .unwrap();
    }

    pub async fn create_test_user_with_email(&self, login: &str, secret: &str, name: &str) {
        self.create_test_user(login, secret, name).await;
        self.link_test_address(login, login, "primary").await;
    }

    pub async fn create_test_group(&self, login: &str, name: &str) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    concat!(
                        "INSERT INTO accounts (name, description, ",
                        "type, active) VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO NOTHING"
                    )
                } else if matches!(self.store, LookupStore::Store(Store::MySQL(_))) {
                    concat!(
                        "INSERT IGNORE INTO accounts (name, description, ",
                        "type, active) VALUES (?, ?, ?, ?)"
                    )
                } else {
                    concat!(
                        "INSERT OR IGNORE INTO accounts (name, description, ",
                        "type, active) VALUES (?, ?, ?, ?)"
                    )
                },
                vec![login.into(), name.into(), "group".into(), true.into()],
            )
            .await
            .unwrap();
    }

    pub async fn create_test_group_with_email(&self, login: &str, name: &str) {
        self.create_test_group(login, name).await;
        self.link_test_address(login, login, "primary").await;
    }

    pub async fn link_test_address(&self, login: &str, address: &str, typ: &str) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    "INSERT INTO emails (name, address, type) VALUES ($1, $2, $3) ON CONFLICT (name, address) DO NOTHING"
                } else if matches!(self.store, LookupStore::Store(Store::MySQL(_))) {
                    "INSERT IGNORE INTO emails (name, address, type) VALUES (?, ?, ?)"
                } else {
                    "INSERT OR IGNORE INTO emails (name, address, type) VALUES (?, ?, ?)"
                },
                vec![login.into(), address.into(), typ.into()],
            )
            .await
            .unwrap();
    }

    pub async fn set_test_quota(&self, login: &str, quota: u32) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    "UPDATE accounts SET quota = $1 where name = $2"
                } else {
                    "UPDATE accounts SET quota = ? where name = ?"
                },
                vec![quota.into(), login.into()],
            )
            .await
            .unwrap();
    }

    pub async fn add_to_group(&self, login: &str, group: &str) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    "INSERT INTO group_members (name, member_of) VALUES ($1, $2)"
                } else {
                    "INSERT INTO group_members (name, member_of) VALUES (?, ?)"
                },
                vec![login.into(), group.into()],
            )
            .await
            .unwrap();
    }

    pub async fn remove_from_group(&self, login: &str, group: &str) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    "DELETE FROM group_members WHERE name = $1 AND member_of = $2"
                } else {
                    "DELETE FROM group_members WHERE name = ? AND member_of = ?"
                },
                vec![login.into(), group.into()],
            )
            .await
            .unwrap();
    }

    pub async fn remove_test_alias(&self, login: &str, alias: &str) {
        self.store
            .query::<usize>(
                if matches!(self.store, LookupStore::Store(Store::PostgreSQL(_))) {
                    "DELETE FROM emails WHERE name = $1 AND address = $2"
                } else {
                    "DELETE FROM emails WHERE name = ? AND address = ?"
                },
                vec![login.into(), alias.into()],
            )
            .await
            .unwrap();
    }
}
