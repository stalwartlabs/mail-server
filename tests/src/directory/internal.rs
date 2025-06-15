/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use directory::{
    Permission, QueryBy, Type,
    backend::{
        RcptType,
        internal::{
            PrincipalField, PrincipalSet, PrincipalUpdate, PrincipalValue,
            lookup::DirectoryStore,
            manage::{self, ChangedPrincipals, ManageDirectory, UpdatePrincipal},
        },
    },
};
use jmap_proto::types::collection::Collection;
use mail_send::Credentials;
use store::{
    BitmapKey, Store, ValueKey,
    roaring::RoaringBitmap,
    write::{BatchBuilder, BitmapClass, ValueClass},
};

use crate::directory::{DirectoryTest, IntoTestPrincipal, TestPrincipal};

#[tokio::test]
async fn internal_directory() {
    let config = DirectoryTest::new(None).await;

    for (store_id, store) in config.stores.stores {
        println!("Testing internal directory with store {:?}", store_id);
        store.destroy().await;

        // A principal without name should fail
        assert_eq!(
            store
                .create_principal(PrincipalSet::default(), None, None)
                .await,
            Err(manage::err_missing(PrincipalField::Name))
        );

        // Basic account creation
        let john_id = store
            .create_principal(
                TestPrincipal {
                    name: "john".into(),
                    description: Some("John Doe".into()),
                    secrets: vec!["secret".into(), "secret2".into()],
                    ..Default::default()
                }
                .into(),
                None,
                None,
            )
            .await
            .unwrap()
            .id;

        // Two accounts with the same name should fail
        assert_eq!(
            store
                .create_principal(
                    TestPrincipal {
                        name: "john".into(),
                        ..Default::default()
                    }
                    .into(),
                    None,
                    None
                )
                .await,
            Err(manage::err_exists(PrincipalField::Name, "john"))
        );

        // An account using a non-existent domain should fail
        assert_eq!(
            store
                .create_principal(
                    TestPrincipal {
                        name: "jane".into(),
                        emails: vec!["jane@example.org".into()],
                        ..Default::default()
                    }
                    .into(),
                    None,
                    None
                )
                .await,
            Err(manage::not_found("example.org"))
        );

        // Create a domain name
        store
            .create_principal(
                TestPrincipal {
                    name: "example.org".into(),
                    typ: Type::Domain,
                    ..Default::default()
                }
                .into(),
                None,
                None,
            )
            .await
            .unwrap();
        assert!(store.is_local_domain("example.org").await.unwrap());
        assert!(!store.is_local_domain("otherdomain.org").await.unwrap());

        // Add an email address
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@example.org".into()),
                    )
                ]))
                .await
                .is_ok()
        );
        assert_eq!(
            store.rcpt("john@example.org").await.unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            store.email_to_id("john@example.org").await.unwrap(),
            Some(john_id)
        );

        // Using non-existent domain should fail
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@otherdomain.org".into()),
                    )
                ]))
                .await,
            Err(manage::not_found("otherdomain.org"))
        );

        // Create an account with an email address
        let jane_id = store
            .create_principal(
                TestPrincipal {
                    name: "jane".into(),
                    description: Some("Jane Doe".into()),
                    secrets: vec!["my_secret".into(), "my_secret2".into()],
                    emails: vec!["jane@example.org".into()],
                    quota: 123,
                    ..Default::default()
                }
                .into(),
                None,
                None,
            )
            .await
            .unwrap()
            .id;

        assert_eq!(
            store.rcpt("jane@example.org").await.unwrap(),
            RcptType::Mailbox
        );
        assert_eq!(
            store.rcpt("jane@otherdomain.org").await.unwrap(),
            RcptType::Invalid
        );
        assert_eq!(
            store.email_to_id("jane@example.org").await.unwrap(),
            Some(jane_id)
        );
        assert_eq!(store.vrfy("jane").await.unwrap(), vec!["jane@example.org"]);
        assert_eq!(
            store
                .query(
                    QueryBy::Credentials(&Credentials::new("jane".into(), "my_secret".into())),
                    true
                )
                .await
                .unwrap()
                .map(|p| p.into_test()),
            Some(TestPrincipal {
                id: jane_id,
                name: "jane".into(),
                description: Some("Jane Doe".into()),
                emails: vec!["jane@example.org".into()],
                secrets: vec!["my_secret".into(), "my_secret2".into()],
                quota: 123,
                ..Default::default()
            })
        );
        assert_eq!(
            store
                .query(
                    QueryBy::Credentials(&Credentials::new("jane".into(), "wrong_password".into())),
                    true
                )
                .await
                .unwrap(),
            None
        );

        // Duplicate email address should fail
        assert_eq!(
            store
                .create_principal(
                    TestPrincipal {
                        name: "janeth".into(),
                        description: Some("Janeth Doe".into()),
                        emails: vec!["jane@example.org".into()],
                        ..Default::default()
                    }
                    .into(),
                    None,
                    None
                )
                .await,
            Err(manage::err_exists(
                PrincipalField::Emails,
                "jane@example.org"
            ))
        );

        // Create a mailing list
        let list_id = store
            .create_principal(
                TestPrincipal {
                    name: "list".into(),
                    typ: Type::List,
                    emails: vec!["list@example.org".into()],
                    ..Default::default()
                }
                .into(),
                None,
                None,
            )
            .await
            .unwrap()
            .id;
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                    PrincipalUpdate::set(
                        PrincipalField::Members,
                        PrincipalValue::StringList(vec!["john".into(), "jane".into()]),
                    ),
                    PrincipalUpdate::set(
                        PrincipalField::ExternalMembers,
                        PrincipalValue::StringList(vec![
                            "mike@other.org".into(),
                            "lucy@foobar.net".into()
                        ]),
                    )
                ]))
                .await
                .is_ok()
        );

        assert_list_members(
            &store,
            "list@example.org",
            [
                "john@example.org",
                "mike@other.org",
                "lucy@foobar.net",
                "jane@example.org",
            ],
        )
        .await;

        assert_eq!(
            store
                .query(QueryBy::Name("list"), true)
                .await
                .unwrap()
                .unwrap()
                .into_test(),
            TestPrincipal {
                name: "list".into(),
                id: list_id,
                typ: Type::List,
                emails: vec!["list@example.org".into()],
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
            [
                "john@example.org",
                "mike@other.org",
                "lucy@foobar.net",
                "jane@example.org"
            ]
            .into_iter()
            .map(|s| s.into())
            .collect::<AHashSet<_>>()
        );

        // Create groups
        store
            .create_principal(
                TestPrincipal {
                    name: "sales".into(),
                    description: Some("Sales Team".into()),
                    typ: Type::Group,
                    ..Default::default()
                }
                .into(),
                None,
                None,
            )
            .await
            .unwrap();
        store
            .create_principal(
                TestPrincipal {
                    name: "support".into(),
                    description: Some("Support Team".into()),
                    typ: Type::Group,
                    ..Default::default()
                }
                .into(),
                None,
                None,
            )
            .await
            .unwrap();

        // Add John to the Sales and Support groups
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("sales".into()),
                    ),
                    PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("support".into()),
                    )
                ]))
                .await
                .is_ok()
        );
        let principal = store
            .query(QueryBy::Name("john"), true)
            .await
            .unwrap()
            .unwrap();
        let principal = store.map_principal(principal, &[]).await.unwrap();
        assert_eq!(
            principal.into_test().into_sorted(),
            TestPrincipal {
                id: john_id,
                name: "john".into(),
                description: Some("John Doe".into()),
                secrets: vec!["secret".into(), "secret2".into()],
                emails: vec!["john@example.org".into()],
                member_of: vec!["sales".into(), "support".into()],
                lists: vec!["list".into()],
                ..Default::default()
            }
        );

        // Adding a non-existent user should fail
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("accounting".into()),
                    )
                ]))
                .await,
            Err(manage::not_found("accounting"))
        );

        // Remove a member from a group
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::remove_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("support".into()),
                    )
                ]))
                .await
                .is_ok()
        );
        let principal = store
            .query(QueryBy::Name("john"), true)
            .await
            .unwrap()
            .unwrap();
        let principal = store.map_principal(principal, &[]).await.unwrap();
        assert_eq!(
            principal.into_test().into_sorted(),
            TestPrincipal {
                id: john_id,
                name: "john".into(),
                description: Some("John Doe".into()),
                secrets: vec!["secret".into(), "secret2".into()],
                emails: vec!["john@example.org".into()],
                member_of: vec!["sales".into()],
                lists: vec!["list".into()],
                ..Default::default()
            }
        );

        // Update multiple fields
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::set(
                        PrincipalField::Name,
                        PrincipalValue::String("john.doe".into())
                    ),
                    PrincipalUpdate::set(
                        PrincipalField::Description,
                        PrincipalValue::String("Johnny Doe".into())
                    ),
                    PrincipalUpdate::set(
                        PrincipalField::Secrets,
                        PrincipalValue::StringList(vec!["12345".into()])
                    ),
                    PrincipalUpdate::set(PrincipalField::Quota, PrincipalValue::Integer(1024)),
                    PrincipalUpdate::remove_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@example.org".into()),
                    ),
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john.doe@example.org".into()),
                    )
                ]))
                .await
                .is_ok()
        );

        let principal = store
            .query(QueryBy::Name("john.doe"), true)
            .await
            .unwrap()
            .unwrap();
        let principal = store.map_principal(principal, &[]).await.unwrap();
        assert_eq!(
            principal.into_test().into_sorted(),
            TestPrincipal {
                id: john_id,
                name: "john.doe".into(),
                description: Some("Johnny Doe".into()),
                secrets: vec!["12345".into()],
                emails: vec!["john.doe@example.org".into()],
                quota: 1024,
                typ: Type::Individual,
                member_of: vec!["sales".into()],
                lists: vec!["list".into()],
                ..Default::default()
            }
        );
        assert_eq!(store.get_principal_id("john").await.unwrap(), None);
        assert_eq!(
            store.rcpt("john@example.org").await.unwrap(),
            RcptType::Invalid
        );
        assert_eq!(
            store.rcpt("john.doe@example.org").await.unwrap(),
            RcptType::Mailbox
        );

        // Remove a member from a mailing list and then add it back
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                    PrincipalUpdate::remove_item(
                        PrincipalField::Members,
                        PrincipalValue::String("john.doe".into()),
                    )
                ]))
                .await
                .is_ok()
        );
        assert_list_members(
            &store,
            "list@example.org",
            ["jane@example.org", "mike@other.org", "lucy@foobar.net"],
        )
        .await;
        assert!(
            store
                .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Members,
                        PrincipalValue::String("john.doe".into()),
                    )
                ]))
                .await
                .is_ok()
        );
        assert_list_members(
            &store,
            "list@example.org",
            [
                "john.doe@example.org",
                "jane@example.org",
                "mike@other.org",
                "lucy@foobar.net",
            ],
        )
        .await;

        // Field validation
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john.doe").with_updates(vec![
                    PrincipalUpdate::set(
                        PrincipalField::Name,
                        PrincipalValue::String("jane".into())
                    ),
                ]))
                .await,
            Err(manage::err_exists(PrincipalField::Name, "jane"))
        );
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john.doe").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("jane@example.org".into())
                    ),
                ]))
                .await,
            Err(manage::err_exists(
                PrincipalField::Emails,
                "jane@example.org"
            ))
        );

        // List accounts
        assert_eq!(
            store
                .list_principals(
                    None,
                    None,
                    &[Type::Individual, Type::Group, Type::List],
                    true,
                    0,
                    0
                )
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<AHashSet<_>>(),
            ["jane", "john.doe", "list", "sales", "support"]
                .into_iter()
                .map(|s| s.into())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_principals("john".into(), None, &[], true, 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<Vec<_>>(),
            vec!["john.doe"]
        );
        assert_eq!(
            store
                .list_principals(None, None, &[Type::Individual], true, 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<AHashSet<_>>(),
            ["jane", "john.doe"]
                .into_iter()
                .map(|s| s.into())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_principals(None, None, &[Type::Group], true, 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<AHashSet<_>>(),
            ["sales", "support"]
                .into_iter()
                .map(|s| s.into())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_principals(None, None, &[Type::List], true, 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<Vec<_>>(),
            vec!["list"]
        );
        assert_eq!(
            store
                .list_principals("example.org".into(), None, &[], true, 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<Vec<_>>(),
            vec!["example.org", "jane", "john.doe", "list"]
        );
        assert_eq!(
            store
                .list_principals("johnny doe".into(), None, &[], true, 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<Vec<_>>(),
            vec!["john.doe"]
        );

        // Write records on John's and Jane's accounts
        let mut document_id = u32::MAX;
        for account_id in [john_id, jane_id] {
            document_id = store
                .assign_document_ids(u32::MAX, Collection::Principal, 1)
                .await
                .unwrap();
            store
                .write(
                    BatchBuilder::new()
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .create_document(document_id)
                        .set(ValueClass::Property(0), "hello".as_bytes())
                        .build_all(),
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
                Some("hello".into())
            );
        }

        // Delete John's account and make sure his records are gone
        store.delete_principal(QueryBy::Id(john_id)).await.unwrap();
        assert_eq!(store.get_principal_id("john.doe").await.unwrap(), None);
        assert_eq!(
            store.email_to_id("john.doe@example.org").await.unwrap(),
            None
        );
        assert_eq!(
            store.rcpt("john.doe@example.org").await.unwrap(),
            RcptType::Invalid
        );
        assert_eq!(
            store
                .list_principals(
                    None,
                    None,
                    &[Type::Individual, Type::Group, Type::List],
                    true,
                    0,
                    0
                )
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name)
                .collect::<AHashSet<_>>(),
            ["jane", "list", "sales", "support"]
                .into_iter()
                .map(|s| s.into())
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
        assert_eq!(store.get_principal_id("jane").await.unwrap(), Some(jane_id));
        assert_eq!(
            store.email_to_id("jane@example.org").await.unwrap(),
            Some(jane_id)
        );
        assert_eq!(
            store.rcpt("jane@example.org").await.unwrap(),
            RcptType::Mailbox
        );
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
            Some("hello".into())
        );
    }
}

#[allow(async_fn_in_trait)]
pub trait TestInternalDirectory {
    async fn create_test_user(&self, login: &str, secret: &str, name: &str, emails: &[&str])
    -> u32;
    async fn create_test_group(&self, login: &str, name: &str, emails: &[&str]) -> u32;
    async fn create_test_list(&self, login: &str, name: &str, emails: &[&str]) -> u32;
    async fn set_test_quota(&self, login: &str, quota: u32);
    async fn add_permissions(&self, login: &str, permissions: impl IntoIterator<Item = Permission>);
    async fn add_to_group(&self, login: &str, group: &str) -> ChangedPrincipals;
    async fn remove_from_group(&self, login: &str, group: &str) -> ChangedPrincipals;
    async fn remove_test_alias(&self, login: &str, alias: &str);
    async fn create_test_domains(&self, domains: &[&str]);
}

impl TestInternalDirectory for Store {
    async fn create_test_user(
        &self,
        login: &str,
        secret: &str,
        name: &str,
        emails: &[&str],
    ) -> u32 {
        let role = if login == "admin" { "admin" } else { "user" };
        self.create_test_domains(emails).await;
        if let Some(principal) = self.query(QueryBy::Name(login), false).await.unwrap() {
            self.update_principal(UpdatePrincipal::by_id(principal.id()).with_updates(vec![
                PrincipalUpdate::set(
                    PrincipalField::Secrets,
                    PrincipalValue::StringList(vec![secret.into()]),
                ),
                PrincipalUpdate::set(
                    PrincipalField::Description,
                    PrincipalValue::String(name.into()),
                ),
                PrincipalUpdate::set(
                    PrincipalField::Emails,
                    PrincipalValue::StringList(emails.iter().map(|s| (*s).into()).collect()),
                ),
                PrincipalUpdate::add_item(
                    PrincipalField::Roles,
                    PrincipalValue::String(role.into()),
                ),
            ]))
            .await
            .unwrap();
            principal.id()
        } else {
            self.create_principal(
                PrincipalSet::new(0, Type::Individual)
                    .with_field(PrincipalField::Name, login)
                    .with_field(PrincipalField::Description, name)
                    .with_field(
                        PrincipalField::Secrets,
                        PrincipalValue::StringList(vec![secret.into()]),
                    )
                    .with_field(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(emails.iter().map(|s| (*s).into()).collect()),
                    )
                    .with_field(
                        PrincipalField::Roles,
                        PrincipalValue::StringList(vec![role.into()]),
                    ),
                None,
                None,
            )
            .await
            .unwrap()
            .id
        }
    }

    async fn create_test_group(&self, login: &str, name: &str, emails: &[&str]) -> u32 {
        self.create_test_domains(emails).await;
        if let Some(principal) = self.query(QueryBy::Name(login), false).await.unwrap() {
            principal.id()
        } else {
            self.create_principal(
                PrincipalSet::new(0, Type::Group)
                    .with_field(PrincipalField::Name, login)
                    .with_field(PrincipalField::Description, name)
                    .with_field(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(emails.iter().map(|s| (*s).into()).collect()),
                    )
                    .with_field(
                        PrincipalField::Roles,
                        PrincipalValue::StringList(vec!["user".into()]),
                    ),
                None,
                None,
            )
            .await
            .unwrap()
            .id
        }
    }

    async fn create_test_list(&self, login: &str, name: &str, members: &[&str]) -> u32 {
        if let Some(principal) = self.query(QueryBy::Name(login), false).await.unwrap() {
            principal.id()
        } else {
            self.create_test_domains(&[login]).await;
            self.create_principal(
                PrincipalSet::new(0, Type::List)
                    .with_field(PrincipalField::Name, login)
                    .with_field(PrincipalField::Description, name)
                    .with_field(
                        PrincipalField::Members,
                        PrincipalValue::StringList(members.iter().map(|s| (*s).into()).collect()),
                    )
                    .with_field(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(vec![login.into()]),
                    ),
                None,
                None,
            )
            .await
            .unwrap()
            .id
        }
    }

    async fn set_test_quota(&self, login: &str, quota: u32) {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::set(PrincipalField::Quota, PrincipalValue::Integer(quota as u64)),
        ]))
        .await
        .unwrap();
    }

    async fn add_permissions(
        &self,
        login: &str,
        permissions: impl IntoIterator<Item = Permission>,
    ) {
        self.update_principal(
            UpdatePrincipal::by_name(login).with_updates(
                permissions
                    .into_iter()
                    .map(|p| {
                        PrincipalUpdate::add_item(
                            PrincipalField::EnabledPermissions,
                            PrincipalValue::String(p.name().to_string()),
                        )
                    })
                    .collect(),
            ),
        )
        .await
        .unwrap();
    }

    async fn add_to_group(&self, login: &str, group: &str) -> ChangedPrincipals {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::add_item(
                PrincipalField::MemberOf,
                PrincipalValue::String(group.into()),
            ),
        ]))
        .await
        .unwrap()
    }

    async fn remove_from_group(&self, login: &str, group: &str) -> ChangedPrincipals {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::remove_item(
                PrincipalField::MemberOf,
                PrincipalValue::String(group.into()),
            ),
        ]))
        .await
        .unwrap()
    }

    async fn remove_test_alias(&self, login: &str, alias: &str) {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::remove_item(
                PrincipalField::Emails,
                PrincipalValue::String(alias.into()),
            ),
        ]))
        .await
        .unwrap();
    }

    async fn create_test_domains(&self, domains: &[&str]) {
        for domain in domains {
            let domain = domain.rsplit_once('@').map_or(*domain, |(_, d)| d);
            if self
                .query(QueryBy::Name(domain), false)
                .await
                .unwrap()
                .is_none()
            {
                self.create_principal(
                    PrincipalSet::new(0, Type::Domain).with_field(PrincipalField::Name, domain),
                    None,
                    None,
                )
                .await
                .unwrap();
            }
        }
    }
}

async fn assert_list_members(
    store: &Store,
    list_addr: &str,
    members: impl IntoIterator<Item = &str>,
) {
    match store.rcpt(list_addr).await.unwrap() {
        RcptType::List(items) => {
            assert_eq!(
                items.into_iter().collect::<AHashSet<_>>(),
                members
                    .into_iter()
                    .map(|s| s.into())
                    .collect::<AHashSet<_>>()
            );
        }
        other => panic!("invalid {other:?}"),
    }
}
