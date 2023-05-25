use std::{collections::HashSet, sync::Arc, time::Duration};

use store::ahash::AHashSet;

use store::{write::BatchBuilder, Store};

pub async fn test(db: Arc<Store>) {
    println!("Running Store ID assignment tests...");

    test_1(db.clone()).await;
    test_2(db.clone()).await;
    test_3(db.clone()).await;
    test_4(db).await;
}

async fn test_1(db: Arc<Store>) {
    // Test change id assignment
    let mut handles = Vec::new();
    let mut expected_ids = HashSet::new();

    // Create 100 change ids concurrently
    for id in 0..100 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move { db.assign_change_id(0).await })
        });
        expected_ids.insert(id);
    }

    for handle in handles {
        let assigned_id = handle.await.unwrap().unwrap();
        assert!(
            expected_ids.remove(&assigned_id),
            "already assigned or invalid: {assigned_id} "
        );
    }
    db.destroy().await;
}

async fn test_2(db: Arc<Store>) {
    // Test document id assignment
    for wait_for_expiry in [true, false] {
        let mut handles = Vec::new();
        let mut expected_ids = HashSet::new();

        // Create 100 ids concurrently
        for id in 0..100 {
            handles.push({
                let db = db.clone();
                tokio::spawn(async move { db.assign_document_id(0, 0).await })
            });
            expected_ids.insert(id);
        }

        for handle in handles {
            let assigned_id = handle.await.unwrap().unwrap();
            //println!("assigned id: {assigned_id} ({wait_for_expiry})");
            assert!(
                expected_ids.remove(&assigned_id),
                "already assigned or invalid: {assigned_id} ({wait_for_expiry})"
            );
        }
        assert_eq!(
            expected_ids.len(),
            0,
            "{expected_ids:?} ({wait_for_expiry})"
        );

        if wait_for_expiry {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
    db.destroy().await;
}

async fn test_3(db: Arc<Store>) {
    // Create document ids and try reassigning
    let mut expected_ids = AHashSet::new();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(0).with_collection(0);
    for pos in 0..100 {
        let id = db.assign_document_id(0, 0).await.unwrap();
        if pos % 2 == 0 {
            batch.create_document(id);
        } else {
            expected_ids.insert(id);
        }
    }
    db.write(batch.build()).await.unwrap();

    // Wait for ids to expire
    tokio::time::sleep(Duration::from_secs(3)).await;

    for _ in 0..expected_ids.len() {
        let id = db.assign_document_id(0, 0).await.unwrap();
        assert!(
            expected_ids.remove(&id),
            "already assigned or invalid: {id}"
        );
    }
    assert_eq!(db.assign_document_id(0, 0).await.unwrap(), 100);
    assert_eq!(db.assign_document_id(0, 0).await.unwrap(), 101);

    db.destroy().await;
}

async fn test_4(db: Arc<Store>) {
    // Try reassigning deleted ids
    let mut expected_ids = AHashSet::new();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(0).with_collection(0);
    for id in 0..100 {
        if id % 2 == 0 {
            batch.create_document(id);
        } else {
            expected_ids.insert(id);
        }
    }
    db.write(batch.build()).await.unwrap();
    for _ in 0..expected_ids.len() {
        let id = db.assign_document_id(0, 0).await.unwrap();
        assert!(
            expected_ids.remove(&id),
            "already assigned or invalid: {id}"
        );
    }
    assert_eq!(db.assign_document_id(0, 0).await.unwrap(), 100);
    assert_eq!(db.assign_document_id(0, 0).await.unwrap(), 101);

    db.destroy().await;
}
