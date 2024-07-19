/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use directory::{
    backend::internal::{
        lookup::DirectoryStore,
        manage::{self, ManageDirectory},
        PrincipalField, PrincipalUpdate, PrincipalValue,
    },
    Principal, QueryBy, Type,
};
use jmap_proto::types::collection::Collection;
use mail_send::Credentials;
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, BitmapClass, ValueClass},
    BitmapKey, ValueKey,
};

use crate::directory::DirectoryTest;

#[tokio::test]
async fn internal_directory() {
    let config = DirectoryTest::new(None).await;

    for (store_id, store) in config.stores.stores {
        println!("Testing internal directory with store {:?}", store_id);
        store.destroy().await;

        // A principal without name should fail
        assert_eq!(
            store.create_account(Principal::default(), vec![]).await,
            Err(manage::err_missing(PrincipalField::Name))
        );

        // Basic account creation
        let john_id = store
            .create_account(
                Principal {
                    name: "john".to_string(),
                    description: Some("John Doe".to_string()),
                    secrets: vec!["secret".to_string(), "secret2".to_string()],
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

        // Two accounts with the same name should fail
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "john".to_string(),
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Err(manage::err_exists(PrincipalField::Name, "john".to_string()))
        );

        // An account using a non-existent domain should fail
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "jane".to_string(),
                        emails: vec!["jane@example.org".to_string()],
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Err(manage::not_found("example.org".to_string()))
        );

        // Create a domain name
        assert_eq!(store.create_domain("example.org").await, Ok(()));
        assert!(store.is_local_domain("example.org").await.unwrap());
        assert!(!store.is_local_domain("otherdomain.org").await.unwrap());

        // Add an email address
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john"),
                    vec![PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@example.org".to_string()),
                    )],
                )
                .await,
            Ok(())
        );
        assert!(store.rcpt("john@example.org").await.unwrap());
        assert_eq!(
            store.email_to_ids("john@example.org").await.unwrap(),
            vec![john_id]
        );

        // Using non-existent domain should fail
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john"),
                    vec![PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@otherdomain.org".to_string()),
                    )],
                )
                .await,
            Err(manage::not_found("otherdomain.org".to_string()))
        );

        // Create an account with an email address
        let jane_id = store
            .create_account(
                Principal {
                    name: "jane".to_string(),
                    description: Some("Jane Doe".to_string()),
                    secrets: vec!["my_secret".to_string(), "my_secret2".to_string()],
                    emails: vec!["jane@example.org".to_string()],
                    quota: 123,
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

        assert!(store.rcpt("jane@example.org").await.unwrap());
        assert!(!store.rcpt("jane@otherdomain.org").await.unwrap());
        assert_eq!(
            store.email_to_ids("jane@example.org").await.unwrap(),
            vec![jane_id]
        );
        assert_eq!(store.vrfy("jane").await.unwrap(), vec!["jane@example.org"]);
        assert_eq!(
            store
                .query(
                    QueryBy::Credentials(&Credentials::new(
                        "jane".to_string(),
                        "my_secret".to_string()
                    )),
                    true
                )
                .await
                .unwrap(),
            Some(Principal {
                id: jane_id,
                name: "jane".to_string(),
                description: Some("Jane Doe".to_string()),
                emails: vec!["jane@example.org".to_string()],
                secrets: vec!["my_secret".to_string(), "my_secret2".to_string()],
                quota: 123,
                ..Default::default()
            })
        );
        assert_eq!(
            store
                .query(
                    QueryBy::Credentials(&Credentials::new(
                        "jane".to_string(),
                        "wrong_password".to_string()
                    )),
                    true
                )
                .await
                .unwrap(),
            None
        );

        // Duplicate email address should fail
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "janeth".to_string(),
                        description: Some("Janeth Doe".to_string()),
                        emails: vec!["jane@example.org".to_string()],
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Err(manage::err_exists(
                PrincipalField::Emails,
                "jane@example.org".to_string()
            ))
        );

        // Create a mailing list
        let list_id = store
            .create_account(
                Principal {
                    name: "list".to_string(),
                    typ: Type::List,
                    emails: vec!["list@example.org".to_string()],
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("list"),
                    vec![PrincipalUpdate::set(
                        PrincipalField::Members,
                        PrincipalValue::StringList(vec!["john".to_string(), "jane".to_string()]),
                    ),],
                )
                .await,
            Ok(())
        );
        assert!(store.rcpt("list@example.org").await.unwrap());
        assert_eq!(
            store
                .email_to_ids("list@example.org")
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            [john_id, jane_id].into_iter().collect::<AHashSet<_>>(),
        );
        assert_eq!(
            store
                .query(QueryBy::Name("list"), true)
                .await
                .unwrap()
                .unwrap(),
            Principal {
                name: "list".to_string(),
                id: list_id,
                typ: Type::List,
                emails: vec!["list@example.org".to_string()],
                ..Default::default()
            }
        );
        assert_eq!(
            store
                .expn("list@example.org")
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            ["john@example.org", "jane@example.org"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );

        // Create groups
        store
            .create_account(
                Principal {
                    name: "sales".to_string(),
                    description: Some("Sales Team".to_string()),
                    typ: Type::Group,
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();
        store
            .create_account(
                Principal {
                    name: "support".to_string(),
                    description: Some("Support Team".to_string()),
                    typ: Type::Group,
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

        // Add John to the Sales and Support groups
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john"),
                    vec![
                        PrincipalUpdate::add_item(
                            PrincipalField::MemberOf,
                            PrincipalValue::String("sales".to_string()),
                        ),
                        PrincipalUpdate::add_item(
                            PrincipalField::MemberOf,
                            PrincipalValue::String("support".to_string()),
                        )
                    ],
                )
                .await,
            Ok(())
        );
        assert_eq!(
            store
                .map_group_ids(
                    store
                        .query(QueryBy::Name("john"), true)
                        .await
                        .unwrap()
                        .unwrap()
                )
                .await
                .unwrap()
                .into_sorted(),
            Principal {
                id: john_id,
                name: "john".to_string(),
                description: Some("John Doe".to_string()),
                secrets: vec!["secret".to_string(), "secret2".to_string()],
                emails: vec!["john@example.org".to_string()],
                member_of: vec![
                    "list".to_string(),
                    "sales".to_string(),
                    "support".to_string()
                ],
                ..Default::default()
            }
        );

        // Adding a non-existent user should fail
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john"),
                    vec![PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("accounting".to_string()),
                    )],
                )
                .await,
            Err(manage::not_found("accounting".to_string()))
        );

        // Remove a member from a group
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john"),
                    vec![PrincipalUpdate::remove_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("support".to_string()),
                    )],
                )
                .await,
            Ok(())
        );
        assert_eq!(
            store
                .map_group_ids(
                    store
                        .query(QueryBy::Name("john"), true)
                        .await
                        .unwrap()
                        .unwrap()
                )
                .await
                .unwrap()
                .into_sorted(),
            Principal {
                id: john_id,
                name: "john".to_string(),
                description: Some("John Doe".to_string()),
                secrets: vec!["secret".to_string(), "secret2".to_string()],
                emails: vec!["john@example.org".to_string()],
                member_of: vec!["list".to_string(), "sales".to_string()],
                ..Default::default()
            }
        );

        // Update multiple fields
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john"),
                    vec![
                        PrincipalUpdate::set(
                            PrincipalField::Name,
                            PrincipalValue::String("john.doe".to_string())
                        ),
                        PrincipalUpdate::set(
                            PrincipalField::Description,
                            PrincipalValue::String("Johnny Doe".to_string())
                        ),
                        PrincipalUpdate::set(
                            PrincipalField::Secrets,
                            PrincipalValue::StringList(vec!["12345".to_string()])
                        ),
                        PrincipalUpdate::set(PrincipalField::Quota, PrincipalValue::Integer(1024)),
                        PrincipalUpdate::set(
                            PrincipalField::Type,
                            PrincipalValue::String("superuser".to_string())
                        ),
                        PrincipalUpdate::remove_item(
                            PrincipalField::Emails,
                            PrincipalValue::String("john@example.org".to_string()),
                        ),
                        PrincipalUpdate::add_item(
                            PrincipalField::Emails,
                            PrincipalValue::String("john.doe@example.org".to_string()),
                        )
                    ],
                )
                .await,
            Ok(())
        );
        assert_eq!(
            store
                .map_group_ids(
                    store
                        .query(QueryBy::Name("john.doe"), true)
                        .await
                        .unwrap()
                        .unwrap()
                )
                .await
                .unwrap()
                .into_sorted(),
            Principal {
                id: john_id,
                name: "john.doe".to_string(),
                description: Some("Johnny Doe".to_string()),
                secrets: vec!["12345".to_string()],
                emails: vec!["john.doe@example.org".to_string()],
                quota: 1024,
                typ: Type::Superuser,
                member_of: vec!["list".to_string(), "sales".to_string()],
            }
        );
        assert_eq!(store.get_account_id("john").await.unwrap(), None);
        assert!(!store.rcpt("john@example.org").await.unwrap());
        assert!(store.rcpt("john.doe@example.org").await.unwrap());

        // Remove a member from a mailing list and then add it back
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("list"),
                    vec![PrincipalUpdate::remove_item(
                        PrincipalField::Members,
                        PrincipalValue::String("john.doe".to_string()),
                    )],
                )
                .await,
            Ok(())
        );
        assert_eq!(
            store.email_to_ids("list@example.org").await.unwrap(),
            vec![jane_id]
        );
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("list"),
                    vec![PrincipalUpdate::add_item(
                        PrincipalField::Members,
                        PrincipalValue::String("john.doe".to_string()),
                    )],
                )
                .await,
            Ok(())
        );
        assert_eq!(
            store
                .email_to_ids("list@example.org")
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            [john_id, jane_id].into_iter().collect::<AHashSet<_>>()
        );

        // Field validation
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john.doe"),
                    vec![PrincipalUpdate::set(
                        PrincipalField::Name,
                        PrincipalValue::String("jane".to_string())
                    ),],
                )
                .await,
            Err(manage::err_exists(PrincipalField::Name, "jane".to_string()))
        );
        assert_eq!(
            store
                .update_account(
                    QueryBy::Name("john.doe"),
                    vec![PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("jane@example.org".to_string())
                    ),],
                )
                .await,
            Err(manage::err_exists(
                PrincipalField::Emails,
                "jane@example.org".to_string()
            ))
        );

        // List accounts
        assert_eq!(
            store
                .list_accounts(None, None)
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            ["jane", "john.doe", "list", "sales", "support"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store.list_accounts("john".into(), None).await.unwrap(),
            vec!["john.doe"]
        );
        assert_eq!(
            store
                .list_accounts(None, Type::Individual.into())
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            ["jane", "john.doe"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_accounts(None, Type::Group.into())
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            ["sales", "support"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store.list_accounts(None, Type::List.into()).await.unwrap(),
            vec!["list"]
        );

        // Write records on John's and Jane's accounts
        let mut document_id = u32::MAX;
        for account_id in [john_id, jane_id] {
            document_id = store
                .write(
                    BatchBuilder::new()
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .create_document()
                        .set(ValueClass::Property(0), "hello".as_bytes())
                        .build_batch(),
                )
                .await
                .unwrap()
                .last_document_id()
                .unwrap();
            assert_eq!(
                store
                    .get_value::<String>(ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id,
                        class: ValueClass::Property(0)
                    })
                    .await
                    .unwrap(),
                Some("hello".to_string())
            );
        }

        // Delete John's account and make sure his records are gone
        store.delete_account(QueryBy::Id(john_id)).await.unwrap();
        assert_eq!(store.get_account_id("john.doe").await.unwrap(), None);
        assert_eq!(
            store.email_to_ids("john.doe@example.org").await.unwrap(),
            Vec::<u32>::new()
        );
        assert!(!store.rcpt("john.doe@example.org").await.unwrap());
        assert_eq!(
            store
                .list_accounts(None, None)
                .await
                .unwrap()
                .into_iter()
                .collect::<AHashSet<_>>(),
            ["jane", "list", "sales", "support"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .get_bitmap(BitmapKey {
                    account_id: john_id,
                    collection: Collection::Email.into(),
                    class: BitmapClass::DocumentIds,
                    document_id: 0
                })
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .get_value::<String>(ValueKey {
                    account_id: john_id,
                    collection: Collection::Email.into(),
                    document_id: 0,
                    class: ValueClass::Property(0)
                })
                .await
                .unwrap(),
            None
        );

        // Make sure Jane's records are still there
        assert_eq!(store.get_account_id("jane").await.unwrap(), Some(jane_id));
        assert_eq!(
            store.email_to_ids("jane@example.org").await.unwrap(),
            vec![jane_id]
        );
        assert!(store.rcpt("jane@example.org").await.unwrap());
        assert_eq!(
            store
                .get_bitmap(BitmapKey {
                    account_id: jane_id,
                    collection: Collection::Email.into(),
                    class: BitmapClass::DocumentIds,
                    document_id: 0
                })
                .await
                .unwrap(),
            Some(RoaringBitmap::from_sorted_iter([document_id]).unwrap())
        );
        assert_eq!(
            store
                .get_value::<String>(ValueKey {
                    account_id: jane_id,
                    collection: Collection::Email.into(),
                    document_id,
                    class: ValueClass::Property(0)
                })
                .await
                .unwrap(),
            Some("hello".to_string())
        );
    }
}
