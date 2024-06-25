/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use store::{
    write::{blob::BlobQuota, now, BatchBuilder, BlobOp},
    BlobClass, BlobStore, Serialize, Stores,
};
use utils::{config::Config, BlobHash};

use crate::store::{TempDir, CONFIG};

#[tokio::test]
pub async fn blob_tests() {
    let temp_dir = TempDir::new("blob_tests", true);
    let mut config =
        Config::new(CONFIG.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap())).unwrap();
    let stores = Stores::parse_all(&mut config).await;

    for (store_id, blob_store) in &stores.blob_stores {
        println!("Testing blob store {}...", store_id);
        test_store(blob_store.clone()).await;
    }

    for (store_id, store) in stores.stores {
        println!("Testing blob management on store {}...", store_id);

        // Init store
        store.destroy().await;

        // Test internal blob store
        let blob_store: BlobStore = store.clone().into();

        // Blob hash exists
        let hash = BlobHash::from(b"abc".as_slice());
        assert!(!store.blob_exists(&hash).await.unwrap());

        // Reserve blob
        let until = now() + 1;
        store
            .write(
                BatchBuilder::new()
                    .with_account_id(0)
                    .set(
                        BlobOp::Reserve {
                            until,
                            hash: hash.clone(),
                        },
                        1024u32.serialize(),
                    )
                    .build_batch(),
            )
            .await
            .unwrap();

        // Uncommitted blob, should not exist
        assert!(!store.blob_exists(&hash).await.unwrap());

        // Write blob to store
        blob_store.put_blob(hash.as_ref(), b"abc").await.unwrap();

        // Commit blob
        store
            .write(
                BatchBuilder::new()
                    .set(BlobOp::Commit { hash: hash.clone() }, Vec::new())
                    .build_batch(),
            )
            .await
            .unwrap();

        // Blob hash should now exist
        assert!(store.blob_exists(&hash).await.unwrap());
        assert!(blob_store
            .get_blob(hash.as_ref(), 0..usize::MAX)
            .await
            .unwrap()
            .is_some());

        // AccountId 0 should be able to read blob
        assert!(store
            .blob_has_access(
                &hash,
                BlobClass::Reserved {
                    account_id: 0,
                    expires: until
                }
            )
            .await
            .unwrap());

        // AccountId 1 should not be able to read blob
        assert!(!store
            .blob_has_access(
                &hash,
                BlobClass::Reserved {
                    account_id: 1,
                    expires: until
                }
            )
            .await
            .unwrap());

        // Blob already expired, quota should be 0
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            store.blob_quota(0).await.unwrap(),
            BlobQuota { bytes: 0, count: 0 }
        );

        // Purge expired blobs
        store.purge_blobs(blob_store.clone()).await.unwrap();

        // Blob hash should no longer exist
        assert!(!store.blob_exists(&hash).await.unwrap());

        // AccountId 0 should not be able to read blob
        assert!(!store
            .blob_has_access(
                &hash,
                BlobClass::Reserved {
                    account_id: 0,
                    expires: until
                }
            )
            .await
            .unwrap());

        // Blob should no longer be in store
        assert!(blob_store
            .get_blob(hash.as_ref(), 0..usize::MAX)
            .await
            .unwrap()
            .is_none());

        // Upload one linked blob to accountId 1, two linked blobs to accountId 0, and three unlinked (reserved) blobs to accountId 2
        let expiry_times = AHashMap::from_iter([
            (b"abc", now() - 10),
            (b"efg", now() + 10),
            (b"hij", now() + 10),
        ]);
        for (document_id, (blob, blob_value)) in [
            (b"123", vec![]),
            (b"456", vec![]),
            (b"789", vec![]),
            (b"abc", 5000u32.serialize()),
            (b"efg", 1000u32.serialize()),
            (b"hij", 2000u32.serialize()),
        ]
        .into_iter()
        .enumerate()
        {
            let hash = BlobHash::from(blob.as_slice());
            let blob_op = if let Some(until) = expiry_times.get(blob) {
                BlobOp::Reserve {
                    until: *until,
                    hash: hash.clone(),
                }
            } else {
                BlobOp::Link { hash: hash.clone() }
            };
            store
                .write(
                    BatchBuilder::new()
                        .with_account_id(if document_id > 0 { 0 } else { 1 })
                        .with_collection(0)
                        .update_document(document_id as u32)
                        .set(blob_op, blob_value)
                        .set(BlobOp::Commit { hash: hash.clone() }, vec![])
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
            store.blob_quota(0).await.unwrap(),
            BlobQuota {
                bytes: 3000,
                count: 2
            }
        );
        assert_eq!(
            store.blob_quota(1).await.unwrap(),
            BlobQuota { bytes: 0, count: 0 }
        );

        // Purge expired blobs and make sure nothing else is deleted
        store.purge_blobs(blob_store.clone()).await.unwrap();
        for (pos, (blob, blob_class)) in [
            (
                b"abc",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"abc"],
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
            (
                b"789",
                BlobClass::Linked {
                    account_id: 0,
                    collection: 0,
                    document_id: 2,
                },
            ),
            (
                b"efg",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"efg"],
                },
            ),
            (
                b"hij",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"hij"],
                },
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let ct = pos == 0;
            let hash = BlobHash::from(blob.as_slice());
            assert!(store.blob_has_access(&hash, blob_class).await.unwrap() ^ ct);
            assert!(store.blob_exists(&hash).await.unwrap() ^ ct);
            assert!(
                blob_store
                    .get_blob(hash.as_ref(), 0..usize::MAX)
                    .await
                    .unwrap()
                    .is_some()
                    ^ ct
            );
        }

        // AccountId 0 should not have access to accountId 1's blobs
        assert!(!store
            .blob_has_access(
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
                    .clear(BlobOp::Link {
                        hash: BlobHash::from(b"789".as_slice()),
                    })
                    .build_batch(),
            )
            .await
            .unwrap();

        // Purge and make sure blob is deleted
        store.purge_blobs(blob_store.clone()).await.unwrap();
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
            (
                b"efg",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"efg"],
                },
            ),
            (
                b"hij",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"hij"],
                },
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let ct = pos == 0;
            let hash = BlobHash::from(blob.as_slice());
            assert!(store.blob_has_access(&hash, blob_class).await.unwrap() ^ ct);
            assert!(store.blob_exists(&hash).await.unwrap() ^ ct);
            assert!(
                blob_store
                    .get_blob(hash.as_ref(), 0..usize::MAX)
                    .await
                    .unwrap()
                    .is_some()
                    ^ ct
            );
        }

        // Unlink all blobs from accountId 1 and purge
        store.blob_hash_unlink_account(1).await.unwrap();
        store.purge_blobs(blob_store.clone()).await.unwrap();

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
            (
                b"efg",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"efg"],
                },
            ),
            (
                b"hij",
                BlobClass::Reserved {
                    account_id: 0,
                    expires: expiry_times[&b"hij"],
                },
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let ct = pos == 0;
            let hash = BlobHash::from(blob.as_slice());
            assert!(store.blob_has_access(&hash, blob_class).await.unwrap() ^ ct);
            assert!(store.blob_exists(&hash).await.unwrap() ^ ct);
            assert!(
                blob_store
                    .get_blob(hash.as_ref(), 0..usize::MAX)
                    .await
                    .unwrap()
                    .is_some()
                    ^ ct
            );
        }
    }
    temp_dir.delete();
}

async fn test_store(store: BlobStore) {
    // Test small blob
    const DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce erat nisl, dignissim a porttitor id, varius nec arcu. Sed mauris.";
    let hash = BlobHash::from(DATA);

    store.put_blob(hash.as_slice(), DATA).await.unwrap();
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(DATA).unwrap()
    );
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 11..57)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&DATA[11..57]).unwrap()
    );
    assert!(store.delete_blob(hash.as_slice()).await.unwrap());
    assert!(store
        .get_blob(hash.as_slice(), 0..usize::MAX)
        .await
        .unwrap()
        .is_none());

    // Test large blob
    let mut data = Vec::with_capacity(50 * 1024 * 1024);
    while data.len() < 50 * 1024 * 1024 {
        data.extend_from_slice(DATA);
        let marker = format!(" [{}] ", data.len());
        data.extend_from_slice(marker.as_bytes());
    }
    let hash = BlobHash::from(&data);
    store.put_blob(hash.as_slice(), &data).await.unwrap();
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&data).unwrap()
    );

    assert_eq!(
        String::from_utf8(
            store
                .get_blob(hash.as_slice(), 3000111..4000999)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&data[3000111..4000999]).unwrap()
    );
    assert!(store.delete_blob(hash.as_slice()).await.unwrap());
    assert!(store
        .get_blob(hash.as_slice(), 0..usize::MAX)
        .await
        .unwrap()
        .is_none());
}
