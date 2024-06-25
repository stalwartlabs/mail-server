/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{backend::internal::manage::ManageDirectory, Principal, QueryBy, Type};
use mail_send::Credentials;
use store::{LookupStore, Store};

use crate::directory::{map_account_ids, DirectoryTest};

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
            store: config.stores.lookup_stores.remove(directory_id).unwrap(),
        };
        let base_store = config.stores.stores.get(directory_id).unwrap();
        let core = config.core;

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

        // Test authentication
        assert_eq!(
            handle
                .query(
                    QueryBy::Credentials(&Credentials::Plain {
                        username: "john".to_string(),
                        secret: "12345".to_string()
                    }),
                    true
                )
                .await
                .unwrap()
                .unwrap(),
            Principal {
                id: base_store.get_account_id("john").await.unwrap().unwrap(),
                name: "john".to_string(),
                description: "John Doe".to_string().into(),
                secrets: vec!["12345".to_string()],
                typ: Type::Individual,
                member_of: map_account_ids(base_store, vec!["sales"]).await,
                emails: vec![
                    "john@example.org".to_string(),
                    "jdoe@example.org".to_string(),
                    "john.doe@example.org".to_string()
                ],
                ..Default::default()
            }
        );
        assert_eq!(
            handle
                .query(
                    QueryBy::Credentials(&Credentials::Plain {
                        username: "bill".to_string(),
                        secret: "password".to_string()
                    }),
                    true
                )
                .await
                .unwrap()
                .unwrap(),
            Principal {
                id: base_store.get_account_id("bill").await.unwrap().unwrap(),
                name: "bill".to_string(),
                description: "Bill Foobar".to_string().into(),
                secrets: vec![
                    "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe".to_string()
                ],
                typ: Type::Individual,
                quota: 500000,
                emails: vec!["bill@example.org".to_string(),],
                ..Default::default()
            }
        );
        assert!(handle
            .query(
                QueryBy::Credentials(&Credentials::Plain {
                    username: "bill".to_string(),
                    secret: "invalid".to_string()
                }),
                true
            )
            .await
            .unwrap()
            .is_none());

        // Get user by name
        assert_eq!(
            handle
                .query(QueryBy::Name("jane"), true)
                .await
                .unwrap()
                .unwrap(),
            Principal {
                id: base_store.get_account_id("jane").await.unwrap().unwrap(),
                name: "jane".to_string(),
                description: "Jane Doe".to_string().into(),
                typ: Type::Individual,
                secrets: vec!["abcde".to_string()],
                member_of: map_account_ids(base_store, vec!["sales", "support"]).await,
                emails: vec!["jane@example.org".to_string(),],
                ..Default::default()
            }
        );

        // Get group by name
        assert_eq!(
            handle
                .query(QueryBy::Name("sales"), true)
                .await
                .unwrap()
                .unwrap(),
            Principal {
                id: base_store.get_account_id("sales").await.unwrap().unwrap(),
                name: "sales".to_string(),
                description: "Sales Team".to_string().into(),
                typ: Type::Group,
                ..Default::default()
            }
        );

        // Ids by email
        assert_eq!(
            core.email_to_ids(&handle, "jane@example.org")
                .await
                .unwrap(),
            map_account_ids(base_store, vec!["jane"]).await
        );
        assert_eq!(
            core.email_to_ids(&handle, "info@example.org")
                .await
                .unwrap(),
            map_account_ids(base_store, vec!["bill", "jane", "john"]).await
        );
        assert_eq!(
            core.email_to_ids(&handle, "jane+alias@example.org")
                .await
                .unwrap(),
            map_account_ids(base_store, vec!["jane"]).await
        );
        assert_eq!(
            core.email_to_ids(&handle, "info+alias@example.org")
                .await
                .unwrap(),
            map_account_ids(base_store, vec!["bill", "jane", "john"]).await
        );
        assert_eq!(
            core.email_to_ids(&handle, "unknown@example.org")
                .await
                .unwrap(),
            Vec::<u32>::new()
        );
        assert_eq!(
            core.email_to_ids(&handle, "anything@catchall.org")
                .await
                .unwrap(),
            map_account_ids(base_store, vec!["robert"]).await
        );

        // Domain validation
        assert!(handle.is_local_domain("example.org").await.unwrap());
        assert!(!handle.is_local_domain("other.org").await.unwrap());

        // RCPT TO
        assert!(core.rcpt(&handle, "jane@example.org").await.unwrap());
        assert!(core.rcpt(&handle, "info@example.org").await.unwrap());
        assert!(core.rcpt(&handle, "jane+alias@example.org").await.unwrap());
        assert!(core.rcpt(&handle, "info+alias@example.org").await.unwrap());
        assert!(core
            .rcpt(&handle, "random_user@catchall.org")
            .await
            .unwrap());
        assert!(!core.rcpt(&handle, "invalid@example.org").await.unwrap());

        // VRFY
        assert_eq!(
            core.vrfy(&handle, "jane").await.unwrap(),
            vec!["jane@example.org".to_string()]
        );
        assert_eq!(
            core.vrfy(&handle, "john").await.unwrap(),
            vec!["john@example.org".to_string()]
        );
        assert_eq!(
            core.vrfy(&handle, "jane+alias@example").await.unwrap(),
            vec!["jane@example.org".to_string()]
        );
        assert_eq!(
            core.vrfy(&handle, "info").await.unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            core.vrfy(&handle, "invalid").await.unwrap(),
            Vec::<String>::new()
        );

        // EXPN
        assert_eq!(
            core.expn(&handle, "info@example.org").await.unwrap(),
            vec![
                "bill@example.org".to_string(),
                "jane@example.org".to_string(),
                "john@example.org".to_string()
            ]
        );
        assert_eq!(
            core.expn(&handle, "john@example.org").await.unwrap(),
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
            "INSERT INTO accounts (name, secret, type) VALUES ('admin', 'secret', 'admin')",
        ] {
            let query = if self.is_mysql() {
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
        let account_type = if login == "admin" {
            "admin"
        } else {
            "individual"
        };
        self.store
            .query::<usize>(
                if self.is_postgresql() {
                    concat!(
                        "INSERT INTO accounts (name, secret, description, ",
                        "type, active) VALUES ($1, $2, $3, $4, true) ON CONFLICT (name) DO NOTHING"
                    )
                } else if self.is_mysql() {
                    concat!(
                        "INSERT IGNORE INTO accounts (name, secret, description, ",
                        "type, active) VALUES (?, ?, ?, ?, true)"
                    )
                } else {
                    concat!(
                        "INSERT OR IGNORE INTO accounts (name, secret, description, ",
                        "type, active) VALUES (?, ?, ?, ?, true)"
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
            .query::<usize>(
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
            .query::<usize>(
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
            .query::<usize>(
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
            .query::<usize>(
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
            .query::<usize>(
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
            .query::<usize>(
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
            matches!(self.store, LookupStore::Store(Store::MySQL(_)))
        }
        #[cfg(not(feature = "mysql"))]
        {
            false
        }
    }

    fn is_postgresql(&self) -> bool {
        #[cfg(feature = "postgres")]
        {
            matches!(self.store, LookupStore::Store(Store::PostgreSQL(_)))
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
            matches!(self.store, LookupStore::Store(Store::SQLite(_)))
        }
        #[cfg(not(feature = "sqlite"))]
        {
            false
        }
    }
}
