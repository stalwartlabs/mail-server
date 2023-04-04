pub mod assign_id;
pub mod blobs;
pub mod query;

use std::{io::Read, sync::Arc};

use ::store::Store;
use utils::config::Config;

struct TempDir {
    path: std::path::PathBuf,
}

#[tokio::test]
pub async fn store_test() {
    let temp_dir = TempDir::new("store_tests", true);
    let config_file = format!(
        concat!("[blob.store]\n", "path = \"{}\"\n", "hash = 1\n"),
        temp_dir.path.display()
    );
    let db = Arc::new(
        Store::open(&Config::parse(&config_file).unwrap())
            .await
            .unwrap(),
    );
    let insert = true;
    if insert {
        db.destroy().await;
    }
    //assign_id::test(db).await;
    blobs::test(db).await;
    //query::test(db, insert).await;
    temp_dir.delete();
}

pub fn deflate_artwork_data() -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    csv_path.push("src");
    csv_path.push("tests");
    csv_path.push("resources");
    csv_path.push("artwork_data.csv.gz");

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
