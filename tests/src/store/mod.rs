/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod assign_id;
pub mod blob;
pub mod import_export;
pub mod lookup;
pub mod ops;
pub mod query;

use std::io::Read;

use store::{FtsStore, Stores};
use utils::config::Config;

use crate::AssertConfig;

pub struct TempDir {
    pub path: std::path::PathBuf,
}

const CONFIG: &str = r#"
[store."s3"]
type = "s3"
access-key = "minioadmin"
secret-key = "minioadmin"
region = "eu-central-1"
endpoint = "http://localhost:9000"
bucket = "tmp"

[store."fs"]
type = "fs"
path = "{TMP}"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/rocksdb"

[store."foundationdb"]
type = "foundationdb"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/sqlite.db"

[store."postgresql"]
type = "postgresql"
host = "localhost"
port = 5432
database = "stalwart"
user = "postgres"
password = "mysecretpassword"

[store."mysql"]
type = "mysql"
host = "localhost"
port = 3307
database = "stalwart"
user = "root"
password = "password"

[store."redis"]
type = "redis"
urls = "redis://127.0.0.1"
redis-type = "single"

"#;

#[tokio::test(flavor = "multi_thread")]
pub async fn store_tests() {
    let insert = true;
    let temp_dir = TempDir::new("store_tests", insert);
    let mut config = Config::new(CONFIG.replace("{TMP}", &temp_dir.path.to_string_lossy()))
        .unwrap()
        .assert_no_errors();
    let stores = Stores::parse_all(&mut config).await;

    let store_id = std::env::var("STORE")
        .expect("Missing store type. Try running `STORE=<store_type> cargo test`");
    let store = stores
        .stores
        .get(&store_id)
        .expect("Store not found")
        .clone();

    println!("Testing store {}...", store_id);
    if insert {
        store.destroy().await;
    }

    import_export::test(store.clone()).await;
    assign_id::test(store.clone()).await;
    ops::test(store.clone()).await;
    query::test(store.clone(), FtsStore::Store(store.clone()), insert).await;

    if insert {
        temp_dir.delete();
    }
}

pub fn deflate_test_resource(name: &str) -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    csv_path.push("resources");
    csv_path.push(name);

    let mut decoder = flate2::bufread::GzDecoder::new(std::io::BufReader::new(
        std::fs::File::open(csv_path).unwrap(),
    ));
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).unwrap();
    result
}

impl TempDir {
    pub fn new(name: &str, delete_if_exists: bool) -> Self {
        let mut path = std::env::temp_dir();
        path.push(name);
        if delete_if_exists && path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn delete(&self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
