use directory::{Directory, Principal, Type};
use jmap_proto::types::id::Id;
use mail_send::Credentials;

use crate::directory::parse_config;

#[tokio::test]
async fn sql_directory() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Obtain directory handle
    let handle = parse_config().directories.remove("sql").unwrap();

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
            ..Default::default()
        }
    );

    // Get user by name
    assert_eq!(
        handle.principal_by_name("jane").await.unwrap().unwrap(),
        Principal {
            id: 3,
            name: "jane".to_string(),
            description: "Jane Doe".to_string().into(),
            typ: Type::Individual,
            ..Default::default()
        }
    );

    // Get group by name
    assert_eq!(
        handle.principal_by_name("sales").await.unwrap().unwrap(),
        Principal {
            id: 5,
            name: "sales".to_string(),
            description: "Sales Team".to_string().into(),
            typ: Type::Group,
            ..Default::default()
        }
    );

    // Member of
    assert_eq!(
        handle
            .member_of(&handle.principal_by_name("john").await.unwrap().unwrap())
            .await
            .unwrap(),
        vec![5]
    );
    assert_eq!(
        handle
            .member_of(&handle.principal_by_name("jane").await.unwrap().unwrap())
            .await
            .unwrap(),
        vec![5, 6]
    );

    // Emails by id
    assert_eq!(
        handle.emails_by_id(2).await.unwrap(),
        vec![
            "john@example.org".to_string(),
            "jdoe@example.org".to_string(),
            "john.doe@example.org".to_string(),
        ]
    );
    assert_eq!(
        handle.emails_by_id(4).await.unwrap(),
        vec!["bill@example.org".to_string(),]
    );

    // Ids by email
    assert_eq!(
        handle.ids_by_email("jane@example.org").await.unwrap(),
        vec![3]
    );
    assert_eq!(
        handle.ids_by_email("info@example.org").await.unwrap(),
        vec![2, 3, 4]
    );

    // Domain validation
    assert!(handle.is_local_domain("example.org").await.unwrap());
    assert!(!handle.is_local_domain("other.org").await.unwrap());

    // RCPT TO
    assert!(handle.rcpt("jane@example.org").await.unwrap());
    assert!(handle.rcpt("info@example.org").await.unwrap());
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
        "CREATE TABLE accounts (name TEXT, id INTEGER PRIMARY KEY, secret TEXT, description TEXT, type TEXT NOT NULL, quota INTEGER DEFAULT 0, active BOOLEAN DEFAULT 1)",
        "CREATE TABLE group_members (uid INTEGER, gid INTEGER, PRIMARY KEY (uid, gid))",
        "CREATE TABLE emails (id INTEGER NOT NULL, address TEXT NOT NULL, type TEXT, PRIMARY KEY (id, address))",
        "INSERT INTO accounts (name, secret, type) VALUES ('admin', 'secret', 'individual')", 
    ] {
        handle.query(query, &[]).await.unwrap_or_else(|_| panic!("failed for {query}"));
    }
}

pub async fn create_test_user(handle: &dyn Directory, login: &str, secret: &str, name: &str) -> Id {
    handle
        .query(
            "INSERT OR IGNORE INTO accounts (name, secret, description, type, active) VALUES (?, ?, ?, 'individual', true)",
            &[login, secret, name],
        )
        .await
        .unwrap();

    Id::from(get_principal_id(handle, login).await)
}

pub async fn create_test_user_with_email(
    handle: &dyn Directory,
    login: &str,
    secret: &str,
    name: &str,
) -> Id {
    let id = create_test_user(handle, login, secret, name).await;
    link_test_address(handle, login, login, "primary").await;
    id
}

pub async fn create_test_group(handle: &dyn Directory, login: &str, name: &str) -> Id {
    handle
        .query(
            "INSERT OR IGNORE INTO accounts (name, description, type, active) VALUES (?, ?, 'group', true)",
            &[login,  name],
        )
        .await
        .unwrap();

    Id::from(get_principal_id(handle, login).await)
}

pub async fn create_test_group_with_email(handle: &dyn Directory, login: &str, name: &str) -> Id {
    let id = create_test_group(handle, login, name).await;
    link_test_address(handle, login, login, "primary").await;
    id
}

pub async fn link_test_address(handle: &dyn Directory, login: &str, address: &str, typ: &str) {
    let id = get_principal_id(handle, login).await;
    handle
        .query(
            &format!(
                "INSERT OR IGNORE INTO emails (id, address, type) VALUES ({}, ?, ?)",
                id,
            ),
            &[address, typ],
        )
        .await
        .unwrap();
}

pub async fn set_test_quota(handle: &dyn Directory, login: &str, quota: u32) {
    let id = get_principal_id(handle, login).await;
    handle
        .query(
            &format!("UPDATE accounts SET quota = {} where id = {}", quota, id,),
            &[],
        )
        .await
        .unwrap();
}

pub async fn add_to_group(handle: &dyn Directory, login: &str, group: &str) {
    let group = handle.principal_by_name(group).await.unwrap().unwrap();
    let gid = group.id;
    assert_ne!(gid, u32::MAX, "{group:?}");

    add_to_group_id(handle, login, gid).await;
}

pub async fn add_to_group_id(handle: &dyn Directory, login: &str, gid: u32) {
    let user = handle.principal_by_name(login).await.unwrap().unwrap();
    let uid = user.id;
    assert_ne!(uid, u32::MAX, "{user:?}");
    assert_ne!(uid, gid, "{user:?}");
    add_user_id_to_group_id(handle, uid, gid).await;
}

pub async fn add_user_id_to_group_id(handle: &dyn Directory, uid: u32, gid: u32) {
    handle
        .query(
            &format!(
                "INSERT INTO group_members (uid, gid) VALUES ({}, {})",
                uid, gid
            ),
            &[],
        )
        .await
        .unwrap();
}

pub async fn remove_from_group(handle: &dyn Directory, uid: u32, gid: u32) {
    handle
        .query(
            &format!(
                "DELETE FROM group_members WHERE uid = {} AND gid = {}",
                uid, gid
            ),
            &[],
        )
        .await
        .unwrap();
}

pub async fn remove_test_alias(handle: &dyn Directory, login: &str, alias: &str) {
    let id = get_principal_id(handle, login).await;
    handle
        .query(
            &format!("DELETE FROM emails WHERE id = {} AND address = ?", id),
            &[alias],
        )
        .await
        .unwrap();
}

async fn get_principal_id(handle: &dyn Directory, name: &str) -> u32 {
    let p = handle.principal_by_name(name).await.unwrap().unwrap();
    assert_ne!(p.id, u32::MAX, "{name} {p:#?}");
    p.id
}
