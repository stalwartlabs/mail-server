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

use directory::{
    backend::internal::{
        lookup::DirectoryStore, manage::ManageDirectory, PrincipalField, PrincipalUpdate,
        PrincipalValue,
    },
    DirectoryError, ManagementError, Principal, QueryBy, Type,
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
            Err(DirectoryError::Management(ManagementError::MissingField(
                PrincipalField::Name
            )))
        );

        // Basic account creation
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "john".to_string(),
                        description: Some("John Doe".to_string()),
                        secrets: vec!["secret".to_string(), "secret2".to_string()],
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Ok(0)
        );

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
            Err(DirectoryError::Management(ManagementError::AlreadyExists {
                field: PrincipalField::Name,
                value: "john".to_string()
            }))
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
            Err(DirectoryError::Management(ManagementError::NotFound(
                "example.org".to_string()
            )))
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
            vec![0]
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
            Err(DirectoryError::Management(ManagementError::NotFound(
                "otherdomain.org".to_string()
            )))
        );

        // Create an account with an email address
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "jane".to_string(),
                        description: Some("Jane Doe".to_string()),
                        secrets: vec!["my_secret".to_string(), "my_secret2".to_string()],
                        emails: vec!["jane@example.org".to_string()],
                        quota: 123,
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Ok(1)
        );
        assert!(store.rcpt("jane@example.org").await.unwrap());
        assert!(!store.rcpt("jane@otherdomain.org").await.unwrap());
        assert_eq!(
            store.email_to_ids("jane@example.org").await.unwrap(),
            vec![1]
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
                id: 1,
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
            Err(DirectoryError::Management(ManagementError::AlreadyExists {
                field: PrincipalField::Emails,
                value: "jane@example.org".to_string()
            }))
        );

        // Create a mailing list
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "list".to_string(),
                        typ: Type::List,
                        emails: vec!["list@example.org".to_string()],
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Ok(2)
        );
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
            store.email_to_ids("list@example.org").await.unwrap(),
            vec![0, 1]
        );
        assert_eq!(
            store
                .query(QueryBy::Name("list"), true)
                .await
                .unwrap()
                .unwrap(),
            Principal {
                name: "list".to_string(),
                id: 2,
                typ: Type::List,
                emails: vec!["list@example.org".to_string()],
                ..Default::default()
            }
        );
        assert_eq!(
            store.expn("list@example.org").await.unwrap(),
            vec!["john@example.org", "jane@example.org"]
        );

        // Create groups
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "sales".to_string(),
                        description: Some("Sales Team".to_string()),
                        typ: Type::Group,
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Ok(3)
        );
        assert_eq!(
            store
                .create_account(
                    Principal {
                        name: "support".to_string(),
                        description: Some("Support Team".to_string()),
                        typ: Type::Group,
                        ..Default::default()
                    },
                    vec![]
                )
                .await,
            Ok(4)
        );

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
                .unwrap(),
            Principal {
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
            Err(DirectoryError::Management(ManagementError::NotFound(
                "accounting".to_string()
            )))
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
                .unwrap(),
            Principal {
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
                .unwrap(),
            Principal {
                name: "john.doe".to_string(),
                description: Some("Johnny Doe".to_string()),
                secrets: vec!["12345".to_string()],
                emails: vec!["john.doe@example.org".to_string()],
                quota: 1024,
                typ: Type::Superuser,
                member_of: vec!["list".to_string(), "sales".to_string()],
                ..Default::default()
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
            vec![1]
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
            store.email_to_ids("list@example.org").await.unwrap(),
            vec![0, 1]
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
            Err(DirectoryError::Management(ManagementError::AlreadyExists {
                field: PrincipalField::Name,
                value: "jane".to_string()
            }))
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
            Err(DirectoryError::Management(ManagementError::AlreadyExists {
                field: PrincipalField::Emails,
                value: "jane@example.org".to_string()
            }))
        );

        // List accounts
        assert_eq!(
            store.list_accounts(None, None).await.unwrap(),
            vec!["jane", "john.doe", "list", "sales", "support"]
        );
        assert_eq!(
            store.list_accounts("john".into(), None).await.unwrap(),
            vec!["john.doe"]
        );
        assert_eq!(
            store
                .list_accounts(None, Type::Individual.into())
                .await
                .unwrap(),
            vec!["jane", "john.doe"]
        );
        assert_eq!(
            store.list_accounts(None, Type::Group.into()).await.unwrap(),
            vec!["sales", "support"]
        );
        assert_eq!(
            store.list_accounts(None, Type::List.into()).await.unwrap(),
            vec!["list"]
        );

        // Write records on John's and Jane's accounts
        for account_id in [0, 1] {
            let document_id = store
                .assign_document_id(account_id, Collection::Email)
                .await
                .unwrap();
            store
                .write(
                    BatchBuilder::new()
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .create_document(document_id)
                        .set(ValueClass::Property(0), "hello".as_bytes())
                        .build_batch(),
                )
                .await
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
        store.delete_account(QueryBy::Id(0)).await.unwrap();
        assert_eq!(store.get_account_id("john.doe").await.unwrap(), None);
        assert_eq!(
            store.email_to_ids("john.doe@example.org").await.unwrap(),
            Vec::<u32>::new()
        );
        assert!(!store.rcpt("john.doe@example.org").await.unwrap());
        assert_eq!(
            store.list_accounts(None, None).await.unwrap(),
            vec!["jane", "list", "sales", "support"]
        );
        assert_eq!(
            store
                .get_bitmap(BitmapKey {
                    account_id: 0,
                    collection: Collection::Email.into(),
                    class: BitmapClass::DocumentIds,
                    block_num: 0
                })
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .get_value::<String>(ValueKey {
                    account_id: 0,
                    collection: Collection::Email.into(),
                    document_id: 0,
                    class: ValueClass::Property(0)
                })
                .await
                .unwrap(),
            None
        );

        // Make sure Jane's records are still there
        assert_eq!(store.get_account_id("jane").await.unwrap(), Some(1));
        assert_eq!(
            store.email_to_ids("jane@example.org").await.unwrap(),
            vec![1]
        );
        assert!(store.rcpt("jane@example.org").await.unwrap());
        assert_eq!(
            store
                .get_bitmap(BitmapKey {
                    account_id: 1,
                    collection: Collection::Email.into(),
                    class: BitmapClass::DocumentIds,
                    block_num: 0
                })
                .await
                .unwrap(),
            Some(RoaringBitmap::from_sorted_iter([0]).unwrap())
        );
        assert_eq!(
            store
                .get_value::<String>(ValueKey {
                    account_id: 1,
                    collection: Collection::Email.into(),
                    document_id: 0,
                    class: ValueClass::Property(0)
                })
                .await
                .unwrap(),
            Some("hello".to_string())
        );
    }
}
