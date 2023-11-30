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

use std::{collections::HashSet, time::Duration};

use store::ahash::AHashSet;

use store::backend::ID_ASSIGNMENT_EXPIRY;
use store::{write::BatchBuilder, Store};

pub async fn test(db: Store) {
    println!("Running Store ID assignment tests...");

    test_0(db.clone()).await;
    test_1(db.clone()).await;
    test_2(db.clone()).await;
    test_3(db.clone()).await;
    test_4(db).await;

    ID_ASSIGNMENT_EXPIRY.store(60 * 60, std::sync::atomic::Ordering::Relaxed);
}

async fn test_0(db: Store) {
    // Test document id assignment
    println!("Assigning 1000 ids concurrently...");
    ID_ASSIGNMENT_EXPIRY.store(10 * 60 * 60, std::sync::atomic::Ordering::Relaxed);
    let mut handles = Vec::new();
    let mut assigned_ids = HashSet::new();

    // Create 1000 ids concurrently
    for _ in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move { db.assign_document_id(0, u8::MAX).await.unwrap() })
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

    db.destroy().await;
}

async fn test_1(db: Store) {
    // Test document id assignment
    ID_ASSIGNMENT_EXPIRY.store(2, std::sync::atomic::Ordering::Relaxed);
    println!("Assigning 100 ids concurrently and reassign after expiration...");
    for wait_for_expiry in [true, false] {
        let mut handles = Vec::new();
        let mut assigned_ids = HashSet::new();

        // Create 100 ids concurrently
        for _ in 0..100 {
            handles.push({
                let db = db.clone();
                tokio::spawn(async move { db.assign_document_id(0, u8::MAX).await.unwrap() })
            });
        }

        for handle in handles {
            let assigned_id = handle.await.unwrap();
            //println!("assigned id: {assigned_id} ({wait_for_expiry})");
            assert!(
                assigned_ids.insert(assigned_id),
                "already assigned or invalid: {assigned_id} ({wait_for_expiry})"
            );
        }
        assert_eq!(
            assigned_ids.len(),
            100,
            "{assigned_ids:?} ({wait_for_expiry})"
        );

        if wait_for_expiry {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    db.destroy().await;
}

async fn test_2(db: Store) {
    // Test document id assignment
    let mut handles = Vec::new();
    let mut assigned_ids = HashSet::new();

    // Create 1000 ids concurrently
    println!("Create 1000 documentIds concurrently...");
    ID_ASSIGNMENT_EXPIRY.store(10 * 60 * 60, std::sync::atomic::Ordering::Relaxed);
    for _ in 0..1000 {
        handles.push({
            let db = db.clone();
            tokio::spawn(async move {
                {
                    let id = db.assign_document_id(0, u8::MAX).await.unwrap();
                    db.write(
                        BatchBuilder::new()
                            .with_account_id(0)
                            .with_collection(u8::MAX)
                            .create_document(id)
                            .build_batch(),
                    )
                    .await
                    .unwrap();
                    id
                }
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
    assert_eq!(assigned_ids.len(), 1000, "{assigned_ids:?} ");

    db.destroy().await;
}

async fn test_3(db: Store) {
    // Create document ids and try reassigning
    println!("Assigning 100 ids concurrently and try reassigning...");

    ID_ASSIGNMENT_EXPIRY.store(2, std::sync::atomic::Ordering::Relaxed);
    let mut expected_ids = AHashSet::new();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(0).with_collection(u8::MAX);
    for pos in 0..100 {
        let id = db.assign_document_id(0, u8::MAX).await.unwrap();
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
        let id = db.assign_document_id(0, u8::MAX).await.unwrap();
        assert!(
            expected_ids.remove(&id),
            "already assigned or invalid: {id}"
        );
    }
    assert_eq!(db.assign_document_id(0, u8::MAX).await.unwrap(), 100);
    assert_eq!(db.assign_document_id(0, u8::MAX).await.unwrap(), 101);

    db.destroy().await;
}

async fn test_4(db: Store) {
    // Try reassigning deleted ids
    println!("Create and delete 100 documentIds then try reassigning ids...");
    ID_ASSIGNMENT_EXPIRY.store(60 * 60, std::sync::atomic::Ordering::Relaxed);
    let mut expected_ids = AHashSet::new();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(0).with_collection(u8::MAX);
    for id in 0..100 {
        if id % 2 == 0 {
            batch.create_document(id);
        } else {
            expected_ids.insert(id);
        }
    }
    db.write(batch.build()).await.unwrap();
    for _ in 0..expected_ids.len() {
        let id = db.assign_document_id(0, u8::MAX).await.unwrap();
        assert!(
            expected_ids.remove(&id),
            "already assigned or invalid: {id}"
        );
    }
    assert_eq!(db.assign_document_id(0, u8::MAX).await.unwrap(), 100);
    assert_eq!(db.assign_document_id(0, u8::MAX).await.unwrap(), 101);

    db.destroy().await;
}
