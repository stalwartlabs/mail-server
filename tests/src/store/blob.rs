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

use store::{
    backend::{fs::FsStore, s3::S3Store, sqlite::SqliteStore},
    write::{blob::BlobQuota, now, BatchBuilder, BlobOp, F_CLEAR},
    BlobClass, BlobHash, BlobStore, Store,
};
use utils::config::Config;

use crate::store::TempDir;

const CONFIG_S3: &str = r#"
[store.blob.s3]
access-key = "minioadmin"
secret-key = "minioadmin"
region = "eu-central-1"
endpoint = "http://localhost:9000"
bucket = "tmp"
"#;

const CONFIG_LOCAL: &str = r#"
[store.blob.local]
path = "{TMP}"
"#;

const CONFIG_DB: &str = r#"
[store.db]
path = "{TMP}/db.db?mode=rwc"
"#;

#[tokio::test]
pub async fn blob_tests() {
    let temp_dir = TempDir::new("blob_tests", true);
    let mut blob_store = None;

    for (store_id, store_cfg) in [("s3", CONFIG_S3), ("fs", CONFIG_LOCAL)] {
        let config =
            Config::new(&store_cfg.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap()))
                .unwrap();

        let blob_store_: BlobStore = match store_id {
            "fs" => FsStore::open(&config).await.unwrap().into(),
            "s3" => S3Store::open(&config).await.unwrap().into(),
            _ => unreachable!(),
        };

        println!("Testing store {}...", store_id);
        test_store(blob_store_.clone()).await;
        blob_store = Some(blob_store_);
    }
    let blob_store = blob_store.unwrap();

    // Start SQLite store
    let store: Store = SqliteStore::open(
        &Config::new(&CONFIG_DB.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap()))
            .unwrap(),
    )
    .await
    .unwrap()
    .into();

    // Blob hash exists
    let hash = BlobHash::from(b"abc".as_slice());
    assert!(!store.blob_hash_exists(&hash).await.unwrap());

    // Reserve blob but mark it as expired
    store
        .write(
            BatchBuilder::new()
                .with_account_id(0)
                .blob(
                    hash.clone(),
                    BlobOp::Reserve {
                        until: now() - 10,
                        size: 1024,
                    },
                    0,
                )
                .build_batch(),
        )
        .await
        .unwrap();

    // Uncommitted blob, should not exist
    assert!(!store.blob_hash_exists(&hash).await.unwrap());

    // Write blob to store
    blob_store.put_blob(hash.as_ref(), b"abc").await.unwrap();

    // Commit blob
    store
        .write(
            BatchBuilder::new()
                .blob(hash.clone(), BlobOp::Commit, 0)
                .build_batch(),
        )
        .await
        .unwrap();

    // Blob hash should now exist
    assert!(store.blob_hash_exists(&hash).await.unwrap());

    // AccountId 0 should be able to read blob
    assert!(store
        .blob_hash_can_read(&hash, BlobClass::Reserved { account_id: 0 })
        .await
        .unwrap());

    // AccountId 1 should not be able to read blob
    assert!(!store
        .blob_hash_can_read(&hash, BlobClass::Reserved { account_id: 1 })
        .await
        .unwrap());

    // Blob already expired, quota should be 0
    assert_eq!(
        store.blob_hash_quota(0).await.unwrap(),
        BlobQuota { bytes: 0, count: 0 }
    );

    // Purge expired blobs
    store.blob_hash_purge(blob_store.clone()).await.unwrap();

    // Blob hash should no longer exist
    assert!(!store.blob_hash_exists(&hash).await.unwrap());

    // AccountId 0 should not be able to read blob
    assert!(!store
        .blob_hash_can_read(&hash, BlobClass::Reserved { account_id: 0 })
        .await
        .unwrap());

    // Blob should no longer be in store
    assert!(blob_store
        .get_blob(hash.as_ref(), 0..u32::MAX)
        .await
        .unwrap()
        .is_none());

    // Upload one linked blob to accountId 1, two linked blobs to accountId 0, and three unlinked (reserved) blobs to accountId 2
    for (document_id, (blob, blob_op)) in [
        (b"123", BlobOp::Link),
        (b"456", BlobOp::Link),
        (b"789", BlobOp::Link),
        (
            b"abc",
            BlobOp::Reserve {
                until: now() - 10,
                size: 5000,
            },
        ),
        (
            b"efg",
            BlobOp::Reserve {
                until: now() + 10,
                size: 1000,
            },
        ),
        (
            b"hij",
            BlobOp::Reserve {
                until: now() + 10,
                size: 2000,
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let hash = BlobHash::from(blob.as_slice());
        store
            .write(
                BatchBuilder::new()
                    .with_account_id(if document_id > 0 { 0 } else { 1 })
                    .with_collection(0)
                    .update_document(document_id as u32)
                    .blob(hash.clone(), blob_op, 0)
                    .blob(hash.clone(), BlobOp::Commit, 0)
                    .build_batch(),
            )
            .await
            .unwrap();
        blob_store
            .put_blob(hash.as_ref(), blob.as_slice())
            .await
            .unwrap();
    }

    // One of the reserved blobs expired and should not count towards quota
    assert_eq!(
        store.blob_hash_quota(0).await.unwrap(),
        BlobQuota {
            bytes: 3000,
            count: 2
        }
    );
    assert_eq!(
        store.blob_hash_quota(1).await.unwrap(),
        BlobQuota { bytes: 0, count: 0 }
    );

    // Purge expired blobs and make sure nothing else is deleted
    store.blob_hash_purge(blob_store.clone()).await.unwrap();
    for (pos, (blob, blob_class)) in [
        (b"abc", BlobClass::Reserved { account_id: 0 }),
        (
            b"123",
            BlobClass::Linked {
                account_id: 1,
                collection: 0,
                document_id: 0,
            },
        ),
        (
            b"456",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 1,
            },
        ),
        (
            b"789",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 2,
            },
        ),
        (b"efg", BlobClass::Reserved { account_id: 0 }),
        (b"hij", BlobClass::Reserved { account_id: 0 }),
    ]
    .into_iter()
    .enumerate()
    {
        let ct = pos == 0;
        let hash = BlobHash::from(blob.as_slice());
        assert!(store.blob_hash_can_read(&hash, blob_class).await.unwrap() ^ ct);
        assert!(store.blob_hash_exists(&hash).await.unwrap() ^ ct);
        assert!(
            blob_store
                .get_blob(hash.as_ref(), 0..u32::MAX)
                .await
                .unwrap()
                .is_some()
                ^ ct
        );
    }

    // AccountId 0 should not have access to accountId 1's blobs
    assert!(!store
        .blob_hash_can_read(
            BlobHash::from(b"123".as_slice()),
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 0,
            }
        )
        .await
        .unwrap());

    // Unlink blob
    store
        .write(
            BatchBuilder::new()
                .with_account_id(0)
                .with_collection(0)
                .update_document(2)
                .blob(BlobHash::from(b"789".as_slice()), BlobOp::Link, F_CLEAR)
                .build_batch(),
        )
        .await
        .unwrap();

    // Purge and make sure blob is deleted
    store.blob_hash_purge(blob_store.clone()).await.unwrap();
    for (pos, (blob, blob_class)) in [
        (
            b"789",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 2,
            },
        ),
        (
            b"123",
            BlobClass::Linked {
                account_id: 1,
                collection: 0,
                document_id: 0,
            },
        ),
        (
            b"456",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 1,
            },
        ),
        (b"efg", BlobClass::Reserved { account_id: 0 }),
        (b"hij", BlobClass::Reserved { account_id: 0 }),
    ]
    .into_iter()
    .enumerate()
    {
        let ct = pos == 0;
        let hash = BlobHash::from(blob.as_slice());
        assert!(store.blob_hash_can_read(&hash, blob_class).await.unwrap() ^ ct);
        assert!(store.blob_hash_exists(&hash).await.unwrap() ^ ct);
        assert!(
            blob_store
                .get_blob(hash.as_ref(), 0..u32::MAX)
                .await
                .unwrap()
                .is_some()
                ^ ct
        );
    }

    // Unlink all blobs from accountId 1 and purge
    store.blob_hash_unlink_account(1).await.unwrap();
    store.blob_hash_purge(blob_store.clone()).await.unwrap();

    // Make sure only accountId 0's blobs are left
    for (pos, (blob, blob_class)) in [
        (
            b"123",
            BlobClass::Linked {
                account_id: 1,
                collection: 0,
                document_id: 0,
            },
        ),
        (
            b"456",
            BlobClass::Linked {
                account_id: 0,
                collection: 0,
                document_id: 1,
            },
        ),
        (b"efg", BlobClass::Reserved { account_id: 0 }),
        (b"hij", BlobClass::Reserved { account_id: 0 }),
    ]
    .into_iter()
    .enumerate()
    {
        let ct = pos == 0;
        let hash = BlobHash::from(blob.as_slice());
        assert!(store.blob_hash_can_read(&hash, blob_class).await.unwrap() ^ ct);
        assert!(store.blob_hash_exists(&hash).await.unwrap() ^ ct);
        assert!(
            blob_store
                .get_blob(hash.as_ref(), 0..u32::MAX)
                .await
                .unwrap()
                .is_some()
                ^ ct
        );
    }

    temp_dir.delete();
}

async fn test_store(store: BlobStore) {
    const DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce erat nisl, dignissim a porttitor id, varius nec arcu. Sed mauris.";

    store.put_blob(b"abc", DATA).await.unwrap();
    assert_eq!(
        String::from_utf8(store.get_blob(b"abc", 0..u32::MAX).await.unwrap().unwrap()).unwrap(),
        std::str::from_utf8(DATA).unwrap()
    );
    assert_eq!(
        String::from_utf8(store.get_blob(b"abc", 11..57).await.unwrap().unwrap()).unwrap(),
        std::str::from_utf8(&DATA[11..57]).unwrap()
    );
    assert!(store.delete_blob(b"abc").await.unwrap());
    assert!(store.get_blob(b"abc", 0..u32::MAX).await.unwrap().is_none());
}
