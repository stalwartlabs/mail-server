use std::fmt::Debug;

use directory::{Principal, Type};
use mail_send::Credentials;

use crate::directory::parse_config;

#[tokio::test]
async fn ldap_directory() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Obtain directory handle
    let handle = parse_config().directories.remove("ldap").unwrap();

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
            id: 2,
            name: "john".to_string(),
            description: "John Doe".to_string().into(),
            secrets: vec!["12345".to_string()],
            typ: Type::Individual,
            member_of: vec!["ou=sales,ou=groups,dc=example,dc=org".to_string()],
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
            id: 4,
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

    // Get by id
    assert_eq!(
        handle.principal_by_id(2).await.unwrap().unwrap(),
        Principal {
            id: 2,
            name: "john".to_string(),
            description: "John Doe".to_string().into(),
            typ: Type::Individual,
            secrets: vec!["12345".to_string()],
            member_of: vec!["ou=sales,ou=groups,dc=example,dc=org".to_string()],
            ..Default::default()
        }
    );

    // Get user by name
    let mut principal = handle.principal_by_name("jane").await.unwrap().unwrap();
    principal.member_of.sort_unstable();
    assert_eq!(
        principal,
        Principal {
            id: 3,
            name: "jane".to_string(),
            description: "Jane Doe".to_string().into(),
            typ: Type::Individual,
            secrets: vec!["abcde".to_string()],
            member_of: vec![
                "ou=sales,ou=groups,dc=example,dc=org".to_string(),
                "support".to_string()
            ],
            ..Default::default()
        }
    );

    // Get group by name
    assert_eq!(
        handle.principal_by_name("sales").await.unwrap().unwrap(),
        Principal {
            id: 5,
            name: "sales".to_string(),
            description: "sales".to_string().into(),
            typ: Type::Group,
            ..Default::default()
        }
    );

    // Member of
    compare_sorted(
        handle
            .member_of(&handle.principal_by_name("john").await.unwrap().unwrap())
            .await
            .unwrap(),
        vec![5],
    );
    compare_sorted(
        handle
            .member_of(&handle.principal_by_name("jane").await.unwrap().unwrap())
            .await
            .unwrap(),
        vec![5, 6],
    );

    // Emails by id
    compare_sorted(
        handle.emails_by_id(2).await.unwrap(),
        vec![
            "john@example.org".to_string(),
            "john.doe@example.org".to_string(),
        ],
    );
    compare_sorted(
        handle.emails_by_id(4).await.unwrap(),
        vec!["bill@example.org".to_string()],
    );

    // Ids by email
    compare_sorted(
        handle.ids_by_email("jane@example.org").await.unwrap(),
        vec![3],
    );
    compare_sorted(
        handle.ids_by_email("jane+alias@example.org").await.unwrap(),
        vec![3],
    );
    compare_sorted(
        handle.ids_by_email("info@example.org").await.unwrap(),
        vec![2, 3, 4],
    );
    compare_sorted(
        handle.ids_by_email("info+alias@example.org").await.unwrap(),
        vec![2, 3, 4],
    );
    compare_sorted(
        handle.ids_by_email("unknown@example.org").await.unwrap(),
        Vec::<u32>::new(),
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
    compare_sorted(
        handle.vrfy("jane").await.unwrap(),
        vec!["jane@example.org".to_string()],
    );
    compare_sorted(
        handle.vrfy("john").await.unwrap(),
        vec!["john@example.org".to_string()],
    );
    compare_sorted(
        handle.vrfy("jane+alias@example").await.unwrap(),
        vec!["jane@example.org".to_string()],
    );
    compare_sorted(handle.vrfy("info").await.unwrap(), Vec::<String>::new());
    compare_sorted(handle.vrfy("invalid").await.unwrap(), Vec::<String>::new());

    // EXPN
    compare_sorted(
        handle.expn("info@example.org").await.unwrap(),
        vec![
            "bill@example.org".to_string(),
            "jane@example.org".to_string(),
            "john@example.org".to_string(),
        ],
    );
    compare_sorted(
        handle.expn("john@example.org").await.unwrap(),
        Vec::<String>::new(),
    );
}

fn compare_sorted<T: Eq + Debug>(v1: Vec<T>, v2: Vec<T>) {
    for val in v1.iter() {
        assert!(v2.contains(val), "{v1:?} != {v2:?}");
    }

    for val in v2.iter() {
        assert!(v1.contains(val), "{v1:?} != {v2:?}");
    }
}
