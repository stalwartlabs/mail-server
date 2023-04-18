use std::sync::Arc;

use store::Store;

pub async fn test(db: Arc<Store>) {
    unimplemented!()
}
/*
    let ttl = 1_u64;

    let blob_1 = vec![b'a'; 1024];
    let blob_2 = vec![b'b'; 1024];

    let blob_id_1 = BlobKind::from(&blob_1[..]);
    let blob_id_2 = BlobKind::from(&blob_2[..]);

    // Insert the same blobs concurrently
    let handles = (1..=100)
        .map(|_| {
            let db = db.clone();
            let blob_1 = blob_1.clone();
            let blob_2 = blob_2.clone();
            tokio::spawn(async move {
                db.write_blob(u32::MAX, &blob_1).await.unwrap();
                db.write_blob(u32::MAX, &blob_2).await.unwrap();
                db.write(
                    BatchBuilder::new()
                        .with_account_id(0)
                        .with_collection(u8::MAX)
                        .update_document(u32::MAX)
                        .blob(&blob_id_2, 0)
                        .build_batch(),
                )
                .await
                .unwrap();
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.await.unwrap();
    }

    // Count number of blobs
    let mut expected_count = AHashMap::from_iter([(blob_id_1, (0, 1)), (blob_id_2, (0, 2))]);
    assert_eq!(expected_count, get_all_blobs(&db).await);

    // Purgimg should not delete any blobs at this point
    db.purge_blobs(ttl).await.unwrap();
    assert_eq!(expected_count, get_all_blobs(&db).await);

    // Link blob to an account
    db.write(
        BatchBuilder::new()
            .with_account_id(2)
            .with_collection(u8::MAX)
            .update_document(2)
            .blob(&blob_id_1, 0)
            .build_batch(),
    )
    .await
    .unwrap();

    // Check expected count
    expected_count.insert(blob_id_1, (1, 1));
    assert_eq!(expected_count, get_all_blobs(&db).await);

    // Wait 1 second until the blob reaches its TTL
    tokio::time::sleep(Duration::from_millis(1100)).await;
    db.purge_blobs(ttl).await.unwrap();
    expected_count.insert(blob_id_1, (1, 0));
    expected_count.remove(&blob_id_2);
    assert_eq!(expected_count, get_all_blobs(&db).await);

    // Unlink blob, purge and make sure it is removed.
    db.write(
        BatchBuilder::new()
            .with_account_id(2)
            .with_collection(u8::MAX)
            .update_document(2)
            .blob(&blob_id_1, F_CLEAR)
            .build_batch(),
    )
    .await
    .unwrap();
    db.purge_blobs(ttl).await.unwrap();
    expected_count.remove(&blob_id_1);
    assert_eq!(expected_count, get_all_blobs(&db).await);
}

struct BlobPurge {
    result: AHashMap<BlobKind, (u32, u32)>,
    link_count: u32,
    ephemeral_count: u32,
    id: [u8; BLOB_HASH_LEN],
}

async fn get_all_blobs(store: &Store) -> AHashMap<BlobKind, (u32, u32)> {
    let results = BlobPurge {
        result: AHashMap::new(),
        id: [0u8; BLOB_HASH_LEN],
        link_count: u32::MAX,
        ephemeral_count: u32::MAX,
    };

    let from_key = BlobKey {
        account_id: 0,
        collection: 0,
        document_id: 0,
        hash: [0; BLOB_HASH_LEN],
    };
    let to_key = BlobKey {
        account_id: u32::MAX,
        collection: u8::MAX,
        document_id: u32::MAX,
        hash: [u8::MAX; BLOB_HASH_LEN],
    };

    let mut b = store
        .iterate(results, from_key, to_key, false, true, move |b, k, v| {
            if !k.starts_with(&b.id) {
                if b.link_count != u32::MAX {
                    let id = BlobKind { hash: b.id };
                    b.result.insert(id, (b.link_count, b.ephemeral_count));
                }
                b.link_count = 0;
                b.ephemeral_count = 0;
                b.id.copy_from_slice(&k[..BLOB_HASH_LEN]);
            }

            if v.is_empty() {
                b.link_count += 1;
            } else {
                b.ephemeral_count += 1;
            }

            Ok(true)
        })
        .await
        .unwrap();

    if b.link_count != u32::MAX {
        let id = BlobKind { hash: b.id };
        b.result.insert(id, (b.link_count, b.ephemeral_count));
    }

    b.result
}
*/
