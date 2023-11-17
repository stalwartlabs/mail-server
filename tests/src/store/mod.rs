/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

pub mod assign_id;
pub mod blob;
pub mod query;

use std::io::Read;

use ::store::Store;

use store::backend::sqlite::SqliteStore;
use utils::config::Config;

pub struct TempDir {
    pub path: std::path::PathBuf,
}

#[tokio::test]
pub async fn store_tests() {
    let insert = true;
    let temp_dir = TempDir::new("store_tests", insert);
    let config_file = format!(
        concat!(
            "store.blob.type = \"local\"\n",
            "store.blob.local.path = \"{}\"\n",
            "store.db.path = \"{}/sqlite.db\"\n"
        ),
        temp_dir.path.display(),
        temp_dir.path.display()
    );
    let db: Store = SqliteStore::open(&Config::new(&config_file).unwrap())
        .await
        .unwrap()
        .into();
    if insert {
        db.destroy().await;
    }
    query::test(db.clone(), insert).await;
    assign_id::test(db).await;
    temp_dir.delete();
}

pub fn deflate_artwork_data() -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
