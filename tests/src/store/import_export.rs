/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use common::Core;
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    rand,
    write::{
        AnyKey, BatchBuilder, BitmapClass, BitmapHash, BlobOp, DirectoryClass, LookupClass,
        MaybeDynamicId, MaybeDynamicValue, Operation, QueueClass, QueueEvent, TagValue, ValueClass,
    },
    *,
};
use utils::BlobHash;

use crate::store::TempDir;

pub async fn test(db: Store) {
    let mut core = Core::default();
    core.storage.data = db.clone();
    core.storage.blob = db.clone().into();
    core.storage.fts = db.clone().into();
    core.storage.lookup = db.clone().into();

    // Make sure the store is empty
    db.assert_is_empty(db.clone().into()).await;

    // Create blobs
    println!("Creating blobs...");
    let mut batch = BatchBuilder::new();
    let mut blob_hashes = Vec::new();
    for blob_size in [16, 128, 1024, 2056, 102400] {
        let data = random_bytes(blob_size);
        let hash = BlobHash::from(data.as_slice());
        blob_hashes.push(hash.clone());
        core.storage
            .blob
            .put_blob(hash.as_ref(), &data)
            .await
            .unwrap();
        batch.set(ValueClass::Blob(BlobOp::Commit { hash }), vec![]);
    }
    db.write(batch.build()).await.unwrap();

    // Create account data
    println!("Creating account data...");
    for account_id in 0u32..10u32 {
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        // Create properties of different sizes
        for collection in [0, 1, 2, 3] {
            batch.with_collection(collection);

            for document_id in [0, 10, 20, 30, 40] {
                batch.create_document_with_id(document_id);

                if collection == u8::from(Collection::Mailbox) {
                    batch
                        .set(
                            ValueClass::Property(Property::Value.into()),
                            random_bytes(10),
                        )
                        .add(
                            ValueClass::Property(Property::EmailIds.into()),
                            rand::random(),
                        );
                }

                for (idx, value_size) in [16, 128, 1024, 2056, 102400].into_iter().enumerate() {
                    batch.set(ValueClass::Property(idx as u8), random_bytes(value_size));
                }

                for value_size in [1, 4, 7, 8, 9, 16] {
                    batch.set(
                        ValueClass::FtsIndex(BitmapHash::new(random_bytes(value_size))),
                        random_bytes(value_size * 2),
                    );
                }

                for grant_account_id in 0u32..10u32 {
                    if account_id != grant_account_id {
                        batch.set(
                            ValueClass::Acl(grant_account_id),
                            vec![account_id as u8, grant_account_id as u8, document_id as u8],
                        );
                    }
                }

                for hash in &blob_hashes {
                    batch.set(
                        ValueClass::Blob(BlobOp::Link { hash: hash.clone() }),
                        vec![],
                    );
                }

                batch.ops.push(Operation::ChangeId {
                    change_id: document_id as u64 + account_id as u64 + collection as u64,
                });

                batch.ops.push(Operation::Log {
                    set: MaybeDynamicValue::Static(vec![
                        account_id as u8,
                        collection,
                        document_id as u8,
                    ]),
                });

                for field in 0..5 {
                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Tag {
                            field,
                            value: TagValue::Id(MaybeDynamicId::Static(rand::random())),
                        },
                        set: true,
                    });

                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Tag {
                            field,
                            value: TagValue::Text(random_bytes(field as usize + 2)),
                        },
                        set: true,
                    });

                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Text {
                            field,
                            token: BitmapHash::new(&random_bytes(field as usize + 2)),
                        },
                        set: true,
                    });

                    batch.ops.push(Operation::Index {
                        field,
                        key: random_bytes(field as usize + 2),
                        set: true,
                    });
                }
            }
        }

        db.write(batch.build()).await.unwrap();
    }

    // Create queue, config and lookup data
    println!("Creating queue, config and lookup data...");
    let mut batch = BatchBuilder::new();
    for idx in [1, 2, 3, 4, 5] {
        batch.set(
            ValueClass::Queue(QueueClass::Message(rand::random())),
            random_bytes(idx),
        );
        batch.set(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: rand::random(),
                queue_id: rand::random(),
            })),
            random_bytes(idx),
        );
        batch.set(
            ValueClass::Lookup(LookupClass::Key(random_bytes(idx))),
            random_bytes(idx),
        );
        batch.add(
            ValueClass::Lookup(LookupClass::Counter(random_bytes(idx))),
            rand::random(),
        );
        batch.set(
            ValueClass::Config(random_bytes(idx + 10)),
            random_bytes(idx + 10),
        );
    }
    db.write(batch.build()).await.unwrap();

    // Create directory data
    println!("Creating directory data...");
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(u32::MAX)
        .with_collection(Collection::Principal);

    for account_id in [1, 2, 3, 4, 5] {
        batch
            .create_document_with_id(account_id)
            .add(
                ValueClass::Directory(DirectoryClass::UsedQuota(account_id)),
                rand::random(),
            )
            .set(
                ValueClass::Directory(DirectoryClass::NameToId(random_bytes(
                    2 + account_id as usize,
                ))),
                random_bytes(4),
            )
            .set(
                ValueClass::Directory(DirectoryClass::EmailToId(random_bytes(
                    4 + account_id as usize,
                ))),
                random_bytes(4),
            )
            .set(
                ValueClass::Directory(DirectoryClass::Domain(random_bytes(
                    4 + account_id as usize,
                ))),
                random_bytes(4),
            )
            .set(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Static(
                    account_id,
                ))),
                random_bytes(30),
            )
            .set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: MaybeDynamicId::Static(account_id),
                    member_of: MaybeDynamicId::Static(rand::random()),
                }),
                random_bytes(15),
            )
            .set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: MaybeDynamicId::Static(account_id),
                    has_member: MaybeDynamicId::Static(rand::random()),
                }),
                random_bytes(15),
            );
    }
    db.write(batch.build()).await.unwrap();

    // Obtain store hash
    println!("Calculating store hash...");
    let snapshot = Snapshot::new(&db).await;
    assert!(!snapshot.keys.is_empty(), "Store hash counts are empty",);

    // Export store
    println!("Exporting store...");
    let temp_dir = TempDir::new("art_vandelay_tests", true);
    core.backup(temp_dir.path.clone()).await;

    // Destroy store
    println!("Destroying store...");
    db.destroy().await;
    db.assert_is_empty(db.clone().into()).await;

    // Import store
    println!("Importing store...");
    core.restore(temp_dir.path.clone()).await;

    // Verify hash
    print!("Verifying store hash...");
    snapshot.assert_is_eq(&Snapshot::new(&db).await);
    println!(" GREAT SUCCESS!");

    // Destroy store
    db.destroy().await;
    temp_dir.delete();
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    keys: AHashSet<KeyValue>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct KeyValue {
    subspace: u8,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Snapshot {
    async fn new(db: &Store) -> Self {
        let is_sql = matches!(
            db,
            Store::SQLite(_) | Store::PostgreSQL(_) | Store::MySQL(_)
        );

        let mut keys = AHashSet::new();

        for (subspace, with_values) in [
            (SUBSPACE_ACL, true),
            (SUBSPACE_BITMAP_ID, false),
            (SUBSPACE_BITMAP_TAG, false),
            (SUBSPACE_BITMAP_TEXT, false),
            (SUBSPACE_DIRECTORY, true),
            (SUBSPACE_FTS_QUEUE, true),
            (SUBSPACE_INDEXES, false),
            (SUBSPACE_BLOB_RESERVE, true),
            (SUBSPACE_BLOB_LINK, true),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_LOGS, true),
            (SUBSPACE_COUNTER, !is_sql),
            (SUBSPACE_LOOKUP_VALUE, true),
            (SUBSPACE_PROPERTY, true),
            (SUBSPACE_SETTINGS, true),
            (SUBSPACE_QUEUE_MESSAGE, true),
            (SUBSPACE_QUEUE_EVENT, true),
            (SUBSPACE_QUOTA, !is_sql),
            (SUBSPACE_REPORT_OUT, true),
            (SUBSPACE_REPORT_IN, true),
            (SUBSPACE_FTS_INDEX, true),
        ] {
            let from_key = AnyKey {
                subspace,
                key: vec![0u8],
            };
            let to_key = AnyKey {
                subspace,
                key: vec![u8::MAX; 10],
            };

            db.iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    keys.insert(KeyValue {
                        subspace,
                        key: key.to_vec(),
                        value: value.to_vec(),
                    });

                    Ok(true)
                },
            )
            .await
            .unwrap();
        }

        Snapshot { keys }
    }

    fn assert_is_eq(&self, other: &Self) {
        let mut is_err = false;
        for key in &self.keys {
            if !other.keys.contains(key) {
                println!(
                    "Subspace {}, Key {:?} not found in restored snapshot",
                    char::from(key.subspace),
                    key.key,
                );
                is_err = true;
            }
        }
        for key in &other.keys {
            if !self.keys.contains(key) {
                println!(
                    "Subspace {}, Key {:?} not found in original snapshot",
                    char::from(key.subspace),
                    key.key,
                );
                is_err = true;
            }
        }

        if is_err {
            panic!("Snapshot mismatch");
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}
