/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Debug;

use directory::{
    QueryBy, ROLE_USER, Type,
    backend::{RcptType, internal::manage::ManageDirectory},
};
use mail_send::Credentials;

use crate::directory::{
    DirectoryTest, IntoTestPrincipal, TestPrincipal, map_account_id, map_account_ids,
};

#[tokio::test]
async fn ldap_directory() {
    // Enable logging
    crate::enable_logging();

    // Obtain directory handle
    let mut config = DirectoryTest::new("sqlite".into()).await;
    let handle = config.directories.directories.remove("ldap").unwrap();
    let base_store = config.stores.stores.get("sqlite").unwrap();
    let core = config.server;

    // Test authentication
    for (auth_type, handle) in [
        ("Default", handle.clone()),
        (
            "Bind template",
            config
                .directories
                .directories
                .remove("ldap-bind-template")
                .unwrap(),
        ),
        (
            "Bind lookup",
            config
                .directories
                .directories
                .remove("ldap-bind-lookup")
                .unwrap(),
        ),
    ] {
        println!("Testing {auth_type} LDAP authentication...");
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
                .into_test()
                .into_sorted(),
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
                emails: vec!["john@example.org".into(), "john.doe@example.org".into()],
                roles: vec![ROLE_USER.to_string()],
                ..Default::default()
            }
            .into_sorted()
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
                .into_test()
                .into_sorted(),
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
            .into_sorted()
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
    }

    // Get user by name
    assert_eq!(
        handle
            .query(QueryBy::Name("jane"), true)
            .await
            .unwrap()
            .unwrap()
            .into_test()
            .into_sorted(),
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
        .into_sorted()
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
            description: Some("sales".into()),
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
        Some(map_account_id(base_store, "jane").await),
    );
    assert_eq!(
        core.email_to_id(&handle, "jane+alias@example.org", 0)
            .await
            .unwrap(),
        Some(map_account_id(base_store, "jane").await),
    );
    assert_eq!(
        core.email_to_id(&handle, "unknown@example.org", 0)
            .await
            .unwrap(),
        None,
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
    compare_sorted(
        core.vrfy(&handle, "jane", 0).await.unwrap(),
        vec!["jane@example.org".into()],
    );
    compare_sorted(
        core.vrfy(&handle, "john", 0).await.unwrap(),
        vec!["john@example.org".into(), "john.doe@example.org".into()],
    );
    compare_sorted(
        core.vrfy(&handle, "jane+alias@example", 0).await.unwrap(),
        vec!["jane@example.org".into()],
    );
    compare_sorted(
        core.vrfy(&handle, "info", 0).await.unwrap(),
        Vec::<String>::new(),
    );
    compare_sorted(
        core.vrfy(&handle, "invalid", 0).await.unwrap(),
        Vec::<String>::new(),
    );

    // EXPN
    // Now handled by the internal directory
    /*compare_sorted(
        core.expn(&handle, "info@example.org", 0).await.unwrap(),
        vec![
            "bill@example.org".into(),
            "jane@example.org".into(),
            "john@example.org".into(),
        ],
    );
    compare_sorted(
        core.expn(&handle, "john@example.org", 0).await.unwrap(),
        Vec::<String>::new(),
    );*/
}

fn compare_sorted<T: Eq + Debug>(v1: Vec<T>, v2: Vec<T>) {
    for val in v1.iter() {
        assert!(v2.contains(val), "{v1:?} != {v2:?}");
    }

    for val in v2.iter() {
        assert!(v1.contains(val), "{v1:?} != {v2:?}");
    }
}
