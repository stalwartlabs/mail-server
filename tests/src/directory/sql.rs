/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{
    QueryBy, ROLE_USER, Type,
    backend::{RcptType, internal::manage::ManageDirectory},
};
use mail_send::Credentials;

#[allow(unused_imports)]
use store::{InMemoryStore, Store};

use crate::directory::{
    DirectoryTest, IntoTestPrincipal, TestPrincipal, map_account_id, map_account_ids,
};

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

    // Obtain directory handle
    for directory_id in ["sqlite", "postgresql", "mysql"] {
        // Parse config
        let mut config = DirectoryTest::new(directory_id.into()).await;

        println!("Testing SQL directory {:?}", directory_id);
        let handle = config.directories.directories.remove(directory_id).unwrap();
        let store = DirectoryStore {
            store: config.stores.stores.remove(directory_id).unwrap(),
        };
        let base_store = &store.store;
        let core = config.server;

        // Create tables
        base_store.destroy().await;
        store.create_test_directory().await;

        // Create test users
        store
            .create_test_user("admin", "very_secret", "Administrator")
            .await;
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

        // Test authentication
        assert_eq!(
            handle
                .query(
                    QueryBy::Credentials(&Credentials::Plain {
                        username: "john".into(),
                        secret: "12345".into()
                    }),
                    true
                )
                .await
                .unwrap()
                .unwrap()
                .into_test(),
            TestPrincipal {
                id: base_store.get_principal_id("john").await.unwrap().unwrap(),
                name: "john".into(),
                description: Some("John Doe".into()),
                secrets: vec!["12345".into()],
                typ: Type::Individual,
                member_of: map_account_ids(base_store, vec!["sales"])
                    .await
                    .into_iter()
                    .map(|v| v.to_string())
                    .collect(),
                emails: vec![
                    "john@example.org".into(),
                    "jdoe@example.org".into(),
                    "john.doe@example.org".into()
                ],
                roles: vec![ROLE_USER.to_string()],
                ..Default::default()
            }
        );
        assert_eq!(
            handle
                .query(
                    QueryBy::Credentials(&Credentials::Plain {
                        username: "bill".into(),
                        secret: "password".into()
                    }),
                    true
                )
                .await
                .unwrap()
                .unwrap()
                .into_test(),
            TestPrincipal {
                id: base_store.get_principal_id("bill").await.unwrap().unwrap(),
                name: "bill".into(),
                description: Some("Bill Foobar".into()),
                secrets: vec![
                    "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe".into()
                ],
                typ: Type::Individual,
                quota: 500000,
                emails: vec!["bill@example.org".into(),],
                roles: vec![ROLE_USER.to_string()],
                ..Default::default()
            }
        );
        assert_eq!(
            handle
                .query(
                    QueryBy::Credentials(&Credentials::Plain {
                        username: "admin".into(),
                        secret: "very_secret".into()
                    }),
                    true
                )
                .await
                .unwrap()
                .unwrap()
                .into_test(),
            TestPrincipal {
                id: base_store.get_principal_id("admin").await.unwrap().unwrap(),
                name: "admin".into(),
                description: Some("Administrator".into()),
                secrets: vec!["very_secret".into()],
                typ: Type::Individual,
                roles: vec![ROLE_USER.to_string()],
                ..Default::default()
            }
        );
        assert!(
            handle
                .query(
                    QueryBy::Credentials(&Credentials::Plain {
                        username: "bill".into(),
                        secret: "invalid".into()
                    }),
                    true
                )
                .await
                .unwrap()
                .is_none()
        );

        // Get user by name
        assert_eq!(
            handle
                .query(QueryBy::Name("jane"), true)
                .await
                .unwrap()
                .unwrap()
                .into_test(),
            TestPrincipal {
                id: base_store.get_principal_id("jane").await.unwrap().unwrap(),
                name: "jane".into(),
                description: Some("Jane Doe".into()),
                typ: Type::Individual,
                secrets: vec!["abcde".into()],
                member_of: map_account_ids(base_store, vec!["sales", "support"])
                    .await
                    .into_iter()
                    .map(|v| v.to_string())
                    .collect(),
                emails: vec!["jane@example.org".into(),],
                roles: vec![ROLE_USER.to_string()],
                ..Default::default()
            }
        );

        // Get group by name
        assert_eq!(
            handle
                .query(QueryBy::Name("sales"), true)
                .await
                .unwrap()
                .unwrap()
                .into_test(),
            TestPrincipal {
                id: base_store.get_principal_id("sales").await.unwrap().unwrap(),
                name: "sales".into(),
                description: Some("Sales Team".into()),
                typ: Type::Group,
                roles: vec![ROLE_USER.to_string()],
                ..Default::default()
            }
        );

        // Ids by email
        assert_eq!(
            core.email_to_id(&handle, "jane@example.org", 0)
                .await
                .unwrap(),
            Some(map_account_id(base_store, "jane").await)
        );
        assert_eq!(
            core.email_to_id(&handle, "jane+alias@example.org", 0)
                .await
                .unwrap(),
            Some(map_account_id(base_store, "jane").await)
        );
        assert_eq!(
            core.email_to_id(&handle, "unknown@example.org", 0)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            core.email_to_id(&handle, "anything@catchall.org", 0)
                .await
                .unwrap(),
            Some(map_account_id(base_store, "robert").await)
        );

        // Domain validation
        assert!(handle.is_local_domain("example.org").await.unwrap());
        assert!(!handle.is_local_domain("other.org").await.unwrap());

        // RCPT TO
        assert_eq!(
            core.rcpt(&handle, "jane@example.org", 0).await.unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            core.rcpt(&handle, "info@example.org", 0).await.unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            core.rcpt(&handle, "jane+alias@example.org", 0)
                .await
                .unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            core.rcpt(&handle, "info+alias@example.org", 0)
                .await
                .unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            core.rcpt(&handle, "random_user@catchall.org", 0)
                .await
                .unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            core.rcpt(&handle, "invalid@example.org", 0).await.unwrap(),
            RcptType::Invalid
        );

        // VRFY
        assert_eq!(
            core.vrfy(&handle, "jane", 0).await.unwrap(),
            vec!["jane@example.org".to_string()]
        );
        assert_eq!(
            core.vrfy(&handle, "john", 0).await.unwrap(),
            vec![
                "john.doe@example.org".to_string(),
                "john@example.org".to_string(),
            ]
        );
        assert_eq!(
            core.vrfy(&handle, "jane+alias@example", 0).await.unwrap(),
            vec!["jane@example.org".to_string()]
        );
        assert_eq!(
            core.vrfy(&handle, "info", 0).await.unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            core.vrfy(&handle, "invalid", 0).await.unwrap(),
            Vec::<String>::new()
        );

        // EXPN (now handled by the internal store)
        /*assert_eq!(
            core.expn(&handle, "info@example.org", 0).await.unwrap(),
            vec![
                "bill@example.org".into(),
                "jane@example.org".into(),
                "john@example.org".into()
            ]
        );
        assert_eq!(
            core.expn(&handle, "john@example.org", 0).await.unwrap(),
            Vec::<String>::new()
        );*/
    }
}

impl DirectoryStore {
    pub async fn create_test_directory(&self) {
        // Create tables
        for table in ["accounts", "group_members", "emails"] {
            self.store
                .sql_query::<usize>(&format!("DROP TABLE IF EXISTS {table}"), vec![])
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
            "INSERT INTO accounts (name, secret, type) VALUES ('admin', 'secret', 'admin')",
        ] {
            let query = if self.is_mysql() {
                query.replace("TEXT", "VARCHAR(255)")
            } else {
                query.into()
            };

            self.store
                .sql_query::<usize>(&query, vec![])
                .await
                .unwrap_or_else(|_| panic!("failed for {query}"));
        }
    }

    pub async fn create_test_user(&self, login: &str, secret: &str, name: &str) {
        let account_type = if login == "admin" {
            "admin"
        } else {
            "individual"
        };
        self.store
            .sql_query::<usize>(
                if self.is_postgresql() {
                    concat!(
                        "INSERT INTO accounts (name, secret, description, ",
                        "type, active) VALUES ($1, $2, $3, $4, true) ",
                        "ON CONFLICT (name) ",
                        "DO UPDATE SET secret = $2, description = $3, type = $4, active = true"
                    )
                } else if self.is_mysql() {
                    concat!(
                        "INSERT INTO accounts (name, secret, description, ",
                        "type, active) VALUES (?, ?, ?, ?, true) ",
                        "ON DUPLICATE KEY UPDATE ",
                        "secret = VALUES(secret), description = VALUES(description), ",
                        "type = VALUES(type), active = true"
                    )
                } else {
                    concat!(
                        "INSERT INTO accounts (name, secret, description, ",
                        "type, active) VALUES (?, ?, ?, ?, true) ",
                        "ON CONFLICT(name) DO UPDATE SET ",
                        "secret = excluded.secret, description = excluded.description, ",
                        "type = excluded.type, active = true"
                    )
                },
                vec![
                    login.into(),
                    secret.into(),
                    name.into(),
                    account_type.into(),
                ],
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
            .sql_query::<usize>(
                if self.is_postgresql() {
                    concat!(
                        "INSERT INTO accounts (name, description, ",
                        "type, active) VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO NOTHING"
                    )
                } else if self.is_mysql() {
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
            .sql_query::<usize>(
                if self.is_postgresql() {
                    "INSERT INTO emails (name, address, type) VALUES ($1, $2, $3) ON CONFLICT (name, address) DO NOTHING"
                } else if self.is_mysql() {
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
            .sql_query::<usize>(
                if self.is_postgresql() {
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
            .sql_query::<usize>(
                if self.is_postgresql() {
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
            .sql_query::<usize>(
                if self.is_postgresql() {
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
            .sql_query::<usize>(
                if self.is_postgresql() {
                    "DELETE FROM emails WHERE name = $1 AND address = $2"
                } else {
                    "DELETE FROM emails WHERE name = ? AND address = ?"
                },
                vec![login.into(), alias.into()],
            )
            .await
            .unwrap();
    }

    fn is_mysql(&self) -> bool {
        #[cfg(feature = "mysql")]
        {
            matches!(self.store, Store::MySQL(_))
        }
        #[cfg(not(feature = "mysql"))]
        {
            false
        }
    }

    fn is_postgresql(&self) -> bool {
        #[cfg(feature = "postgres")]
        {
            matches!(self.store, Store::PostgreSQL(_))
        }
        #[cfg(not(feature = "postgres"))]
        {
            false
        }
    }

    #[allow(dead_code)]
    fn is_sqlite(&self) -> bool {
        #[cfg(feature = "sqlite")]
        {
            matches!(self.store, Store::SQLite(_))
        }
        #[cfg(not(feature = "sqlite"))]
        {
            false
        }
    }
}
