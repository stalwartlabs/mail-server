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
