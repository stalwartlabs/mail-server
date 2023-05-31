use directory::Directory;
use jmap_proto::types::id::Id;

pub async fn create_test_directory(handle: &dyn Directory) {
    // Create tables
    for query in [
        "CREATE TABLE accounts (name TEXT, id INTEGER PRIMARY KEY, secret TEXT, description TEXT, type TEXT NOT NULL, quota INTEGER, active BOOLEAN DEFAULT 1)",
        "CREATE TABLE group_members (uid INTEGER, gid INTEGER, PRIMARY KEY (uid, gid))",
        "CREATE TABLE emails (id INTEGER NOT NULL, email TEXT NOT NULL, type TEXT, PRIMARY KEY (id, email))",
        "INSERT INTO accounts (name, secret, type) VALUES ('admin', 'secret', 'individual')", 
    ] {
        handle.query(query, &[]).await.unwrap_or_else(|_| panic!("failed for {query}"));
    }
}

pub async fn create_test_user(handle: &dyn Directory, login: &str, secret: &str, name: &str) -> Id {
    handle
        .query(
            "INSERT OR IGNORE INTO users (name, secret, description, type, is_active) VALUES (?, ?, ?, 'individual', true)",
            &[login, secret, name],
        )
        .await
        .unwrap();

    Id::from(handle.principal_by_name(login).await.unwrap().unwrap().id)
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
            "INSERT OR IGNORE INTO users (name, description, type, is_active) VALUES (?, ?, 'group', true)",
            &[login,  name],
        )
        .await
        .unwrap();

    let id = handle.principal_by_name(login).await.unwrap().unwrap().id;

    handle
        .query(
            &format!(
                "INSERT OR IGNORE INTO emails (id, email, type) VALUES ({}, ?, 'primary')",
                id
            ),
            &[login],
        )
        .await
        .unwrap();

    Id::from(id)
}

pub async fn link_test_address(handle: &dyn Directory, login: &str, address: &str, typ: &str) {
    let id = handle.principal_by_name(login).await.unwrap().unwrap().id;
    handle
        .query(
            &format!(
                "INSERT OR IGNORE INTO emails (id, email, type) VALUES ({}, ?, ?)",
                id,
            ),
            &[address, typ],
        )
        .await
        .unwrap();
}

pub async fn add_to_group(handle: &dyn Directory, uid: u32, gid: u32) {
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
            &format!("DELETE FROM groups WHERE uid = {} AND gid = {}", uid, gid),
            &[],
        )
        .await
        .unwrap();
}

pub async fn remove_test_alias(handle: &dyn Directory, login: &str, alias: &str) {
    let id = handle.principal_by_name(login).await.unwrap().unwrap().id;
    handle
        .query(
            &format!("DELETE FROM emails WHERE id = {} AND email = ?", id),
            &[alias],
        )
        .await
        .unwrap();
}
