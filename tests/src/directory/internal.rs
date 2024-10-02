/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use directory::{
    backend::internal::{
        lookup::DirectoryStore,
        manage::{self, ManageDirectory, UpdatePrincipal},
        PrincipalField, PrincipalUpdate, PrincipalValue,
    },
    Principal, QueryBy, Type,
};
use jmap_proto::types::collection::Collection;
use mail_send::Credentials;
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, BitmapClass, ValueClass},
    BitmapKey, Store, ValueKey,
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
            store.create_principal(Principal::default(), None).await,
            Err(manage::err_missing(PrincipalField::Name))
        );

        // Basic account creation
        let john_id = store
            .create_principal(
                TestPrincipal {
                    name: "john".to_string(),
                    description: Some("John Doe".to_string()),
                    secrets: vec!["secret".to_string(), "secret2".to_string()],
                    ..Default::default()
                }
                .into(),
                None,
            )
            .await
            .unwrap();

        // Two accounts with the same name should fail
        assert_eq!(
            store
                .create_principal(
                    TestPrincipal {
                        name: "john".to_string(),
                        ..Default::default()
                    }
                    .into(),
                    None
                )
                .await,
            Err(manage::err_exists(PrincipalField::Name, "john".to_string()))
        );

        // An account using a non-existent domain should fail
        assert_eq!(
            store
                .create_principal(
                    TestPrincipal {
                        name: "jane".to_string(),
                        emails: vec!["jane@example.org".to_string()],
                        ..Default::default()
                    }
                    .into(),
                    None
                )
                .await,
            Err(manage::not_found("example.org".to_string()))
        );

        // Create a domain name
        store
            .create_principal(
                TestPrincipal {
                    name: "example.org".to_string(),
                    typ: Type::Domain,
                    ..Default::default()
                }
                .into(),
                None,
            )
            .await
            .unwrap();
        assert!(store.is_local_domain("example.org").await.unwrap());
        assert!(!store.is_local_domain("otherdomain.org").await.unwrap());

        // Add an email address
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@example.org".to_string()),
                    )
                ]))
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
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@otherdomain.org".to_string()),
                    )
                ]))
                .await,
            Err(manage::not_found("otherdomain.org".to_string()))
        );

        // Create an account with an email address
        let jane_id = store
            .create_principal(
                TestPrincipal {
                    name: "jane".to_string(),
                    description: Some("Jane Doe".to_string()),
                    secrets: vec!["my_secret".to_string(), "my_secret2".to_string()],
                    emails: vec!["jane@example.org".to_string()],
                    quota: 123,
                    ..Default::default()
                }
                .into(),
                None,
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
                .unwrap()
                .map(|p| p.into_test()),
            Some(TestPrincipal {
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
                .create_principal(
                    TestPrincipal {
                        name: "janeth".to_string(),
                        description: Some("Janeth Doe".to_string()),
                        emails: vec!["jane@example.org".to_string()],
                        ..Default::default()
                    }
                    .into(),
                    None
                )
                .await,
            Err(manage::err_exists(
                PrincipalField::Emails,
                "jane@example.org".to_string()
            ))
        );

        // Create a mailing list
        let list_id = store
            .create_principal(
                TestPrincipal {
                    name: "list".to_string(),
                    typ: Type::List,
                    emails: vec!["list@example.org".to_string()],
                    ..Default::default()
                }
                .into(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                    PrincipalUpdate::set(
                        PrincipalField::Members,
                        PrincipalValue::StringList(vec!["john".to_string(), "jane".to_string()]),
                    )
                ]))
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
                .unwrap()
                .into_test(),
            TestPrincipal {
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
            .create_principal(
                TestPrincipal {
                    name: "sales".to_string(),
                    description: Some("Sales Team".to_string()),
                    typ: Type::Group,
                    ..Default::default()
                }
                .into(),
                None,
            )
            .await
            .unwrap();
        store
            .create_principal(
                TestPrincipal {
                    name: "support".to_string(),
                    description: Some("Support Team".to_string()),
                    typ: Type::Group,
                    ..Default::default()
                }
                .into(),
                None,
            )
            .await
            .unwrap();

        // Add John to the Sales and Support groups
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("sales".to_string()),
                    ),
                    PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("support".to_string()),
                    )
                ]))
                .await,
            Ok(())
        );
        let mut principal = store
            .query(QueryBy::Name("john"), true)
            .await
            .unwrap()
            .unwrap();
        store.map_field_ids(&mut principal, &[]).await.unwrap();
        assert_eq!(
            principal.into_test().into_sorted(),
            TestPrincipal {
                id: john_id,
                name: "john".to_string(),
                description: Some("John Doe".to_string()),
                secrets: vec!["secret".to_string(), "secret2".to_string()],
                emails: vec!["john@example.org".to_string()],
                member_of: vec!["sales".to_string(), "support".to_string()],
                lists: vec!["list".to_string()],
                ..Default::default()
            }
        );

        // Adding a non-existent user should fail
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("accounting".to_string()),
                    )
                ]))
                .await,
            Err(manage::not_found("accounting".to_string()))
        );

        // Remove a member from a group
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                    PrincipalUpdate::remove_item(
                        PrincipalField::MemberOf,
                        PrincipalValue::String("support".to_string()),
                    )
                ]))
                .await,
            Ok(())
        );
        let mut principal = store
            .query(QueryBy::Name("john"), true)
            .await
            .unwrap()
            .unwrap();
        store.map_field_ids(&mut principal, &[]).await.unwrap();
        assert_eq!(
            principal.into_test().into_sorted(),
            TestPrincipal {
                id: john_id,
                name: "john".to_string(),
                description: Some("John Doe".to_string()),
                secrets: vec!["secret".to_string(), "secret2".to_string()],
                emails: vec!["john@example.org".to_string()],
                member_of: vec!["sales".to_string()],
                lists: vec!["list".to_string()],
                ..Default::default()
            }
        );

        // Update multiple fields
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
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
                    PrincipalUpdate::remove_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john@example.org".to_string()),
                    ),
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("john.doe@example.org".to_string()),
                    )
                ]))
                .await,
            Ok(())
        );

        let mut principal = store
            .query(QueryBy::Name("john.doe"), true)
            .await
            .unwrap()
            .unwrap();
        store.map_field_ids(&mut principal, &[]).await.unwrap();
        assert_eq!(
            principal.into_test().into_sorted(),
            TestPrincipal {
                id: john_id,
                name: "john.doe".to_string(),
                description: Some("Johnny Doe".to_string()),
                secrets: vec!["12345".to_string()],
                emails: vec!["john.doe@example.org".to_string()],
                quota: 1024,
                typ: Type::Individual,
                member_of: vec!["sales".to_string()],
                lists: vec!["list".to_string()],
                ..Default::default()
            }
        );
        assert_eq!(store.get_principal_id("john").await.unwrap(), None);
        assert!(!store.rcpt("john@example.org").await.unwrap());
        assert!(store.rcpt("john.doe@example.org").await.unwrap());

        // Remove a member from a mailing list and then add it back
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                    PrincipalUpdate::remove_item(
                        PrincipalField::Members,
                        PrincipalValue::String("john.doe".to_string()),
                    )
                ]))
                .await,
            Ok(())
        );
        assert_eq!(
            store.email_to_ids("list@example.org").await.unwrap(),
            vec![jane_id]
        );
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Members,
                        PrincipalValue::String("john.doe".to_string()),
                    )
                ]))
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
                .update_principal(UpdatePrincipal::by_name("john.doe").with_updates(vec![
                    PrincipalUpdate::set(
                        PrincipalField::Name,
                        PrincipalValue::String("jane".to_string())
                    ),
                ]))
                .await,
            Err(manage::err_exists(PrincipalField::Name, "jane".to_string()))
        );
        assert_eq!(
            store
                .update_principal(UpdatePrincipal::by_name("john.doe").with_updates(vec![
                    PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String("jane@example.org".to_string())
                    ),
                ]))
                .await,
            Err(manage::err_exists(
                PrincipalField::Emails,
                "jane@example.org".to_string()
            ))
        );

        // List accounts
        assert_eq!(
            store
                .list_principals(
                    None,
                    None,
                    &[Type::Individual, Type::Group, Type::List],
                    &[],
                    0,
                    0
                )
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name().to_string())
                .collect::<AHashSet<_>>(),
            ["jane", "john.doe", "list", "sales", "support"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_principals("john".into(), None, &[], &[], 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name().to_string())
                .collect::<Vec<_>>(),
            vec!["john.doe"]
        );
        assert_eq!(
            store
                .list_principals(None, None, &[Type::Individual], &[], 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name().to_string())
                .collect::<AHashSet<_>>(),
            ["jane", "john.doe"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_principals(None, None, &[Type::Group], &[], 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name().to_string())
                .collect::<AHashSet<_>>(),
            ["sales", "support"]
                .into_iter()
                .map(|s| s.to_string())
                .collect::<AHashSet<_>>()
        );
        assert_eq!(
            store
                .list_principals(None, None, &[Type::List], &[], 0, 0)
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name().to_string())
                .collect::<Vec<_>>(),
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
        store.delete_principal(QueryBy::Id(john_id)).await.unwrap();
        assert_eq!(store.get_principal_id("john.doe").await.unwrap(), None);
        assert_eq!(
            store.email_to_ids("john.doe@example.org").await.unwrap(),
            Vec::<u32>::new()
        );
        assert!(!store.rcpt("john.doe@example.org").await.unwrap());
        assert_eq!(
            store
                .list_principals(
                    None,
                    None,
                    &[Type::Individual, Type::Group, Type::List],
                    &[],
                    0,
                    0
                )
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|p| p.name().to_string())
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
        assert_eq!(store.get_principal_id("jane").await.unwrap(), Some(jane_id));
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

#[allow(async_fn_in_trait)]
pub trait TestInternalDirectory {
    async fn create_test_user(&self, login: &str, secret: &str, name: &str, emails: &[&str])
        -> u32;
    async fn create_test_group(&self, login: &str, name: &str, emails: &[&str]) -> u32;
    async fn create_test_list(&self, login: &str, name: &str, emails: &[&str]) -> u32;
    async fn set_test_quota(&self, login: &str, quota: u32);
    async fn add_to_group(&self, login: &str, group: &str);
    async fn remove_from_group(&self, login: &str, group: &str);
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
                    PrincipalValue::StringList(vec![secret.to_string()]),
                ),
                PrincipalUpdate::set(
                    PrincipalField::Description,
                    PrincipalValue::String(name.to_string()),
                ),
                PrincipalUpdate::set(
                    PrincipalField::Emails,
                    PrincipalValue::StringList(emails.iter().map(|s| s.to_string()).collect()),
                ),
                PrincipalUpdate::add_item(
                    PrincipalField::Roles,
                    PrincipalValue::String(role.to_string()),
                ),
            ]))
            .await
            .unwrap();
            principal.id()
        } else {
            self.create_principal(
                Principal::new(0, Type::Individual)
                    .with_field(PrincipalField::Name, login.to_string())
                    .with_field(PrincipalField::Description, name.to_string())
                    .with_field(
                        PrincipalField::Secrets,
                        PrincipalValue::StringList(vec![secret.to_string()]),
                    )
                    .with_field(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(emails.iter().map(|s| s.to_string()).collect()),
                    )
                    .with_field(
                        PrincipalField::Roles,
                        PrincipalValue::StringList(vec![role.to_string()]),
                    ),
                None,
            )
            .await
            .unwrap()
        }
    }

    async fn create_test_group(&self, login: &str, name: &str, emails: &[&str]) -> u32 {
        self.create_test_domains(emails).await;
        if let Some(principal) = self.query(QueryBy::Name(login), false).await.unwrap() {
            principal.id()
        } else {
            self.create_principal(
                Principal::new(0, Type::Group)
                    .with_field(PrincipalField::Name, login.to_string())
                    .with_field(PrincipalField::Description, name.to_string())
                    .with_field(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(emails.iter().map(|s| s.to_string()).collect()),
                    )
                    .with_field(
                        PrincipalField::Roles,
                        PrincipalValue::StringList(vec!["user".to_string()]),
                    ),
                None,
            )
            .await
            .unwrap()
        }
    }

    async fn create_test_list(&self, login: &str, name: &str, members: &[&str]) -> u32 {
        if let Some(principal) = self.query(QueryBy::Name(login), false).await.unwrap() {
            principal.id()
        } else {
            self.create_test_domains(&[login]).await;
            self.create_principal(
                Principal::new(0, Type::List)
                    .with_field(PrincipalField::Name, login.to_string())
                    .with_field(PrincipalField::Description, name.to_string())
                    .with_field(
                        PrincipalField::Members,
                        PrincipalValue::StringList(members.iter().map(|s| s.to_string()).collect()),
                    )
                    .with_field(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(vec![login.to_string()]),
                    ),
                None,
            )
            .await
            .unwrap()
        }
    }

    async fn set_test_quota(&self, login: &str, quota: u32) {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::set(PrincipalField::Quota, PrincipalValue::Integer(quota as u64)),
        ]))
        .await
        .unwrap();
    }

    async fn add_to_group(&self, login: &str, group: &str) {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::add_item(
                PrincipalField::MemberOf,
                PrincipalValue::String(group.to_string()),
            ),
        ]))
        .await
        .unwrap();
    }

    async fn remove_from_group(&self, login: &str, group: &str) {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::remove_item(
                PrincipalField::MemberOf,
                PrincipalValue::String(group.to_string()),
            ),
        ]))
        .await
        .unwrap();
    }

    async fn remove_test_alias(&self, login: &str, alias: &str) {
        self.update_principal(UpdatePrincipal::by_name(login).with_updates(vec![
            PrincipalUpdate::remove_item(
                PrincipalField::Emails,
                PrincipalValue::String(alias.to_string()),
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
                    Principal::new(0, Type::Domain)
                        .with_field(PrincipalField::Name, domain.to_string()),
                    None,
                )
                .await
                .unwrap();
            }
        }
    }
}
