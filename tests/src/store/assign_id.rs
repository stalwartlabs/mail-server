/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashSet;

use store::{write::BatchBuilder, Store};

pub async fn test(db: Store) {
    println!("Running Store ID assignment tests...");

    test_0(db).await;
}

async fn test_0(db: Store) {
    // Test document id assignment
    println!("Creating 1000 documentIds concurrently...");
    let mut handles = Vec::new();
    let mut assigned_ids = HashSet::new();

    // Create 1000 ids concurrently
    for _ in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move {
                db.write(
                    BatchBuilder::new()
                        .with_account_id(0)
                        .with_collection(u8::MAX)
                        .create_document()
                        .build_batch(),
                )
                .await
                .unwrap()
                .last_document_id()
                .unwrap()
            })
        });
    }

    for handle in handles {
        let assigned_id = handle.await.unwrap();
        assert!(
            assigned_ids.insert(assigned_id),
            "already assigned or invalid: {assigned_id}"
        );
    }
    assert_eq!(assigned_ids.len(), 1000);

    // Create 1000 ids concurrently
    println!("Deleting 1000 documentIds concurrently...");
    let mut handles = Vec::new();
    for document_id in assigned_ids {
        let db = db.clone();
        handles.push({
            tokio::spawn(async move {
                db.write(
                    BatchBuilder::new()
                        .with_account_id(0)
                        .with_collection(u8::MAX)
                        .delete_document(document_id)
                        .build_batch(),
                )
                .await
                .unwrap();
            })
        });
    }
    for handle in handles {
        handle.await.unwrap();
    }

    // Reuse 1000 ids concurrently
    println!("Reusing 1000 freed documentIds concurrently...");
    let mut handles = Vec::new();
    let mut assigned_ids = HashSet::new();
    for _ in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move {
                db.write(
                    BatchBuilder::new()
                        .with_account_id(0)
                        .with_collection(u8::MAX)
                        .create_document()
                        .build_batch(),
                )
                .await
                .unwrap()
                .last_document_id()
                .unwrap()
            })
        });
    }

    for handle in handles {
        let assigned_id = handle.await.unwrap();
        assert!(
            assigned_ids.insert(assigned_id),
            "freed id already assigned or invalid: {assigned_id}"
        );
    }
    assert_eq!(assigned_ids.len(), 1000);

    db.destroy().await;
}
