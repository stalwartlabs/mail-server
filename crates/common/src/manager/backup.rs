/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::BTreeSet,
    io::{BufWriter, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::mpsc::{self, SyncSender},
};

use ahash::{AHashMap, AHashSet};
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    write::{
        key::DeserializeBigEndian, AnyKey, BitmapClass, BitmapHash, BlobOp, DirectoryClass,
        LookupClass, QueueClass, QueueEvent, TagValue, ValueClass,
    },
    BitmapKey, Deserialize, IndexKey, IterateParams, LogKey, Serialize, ValueKey,
    SUBSPACE_BITMAP_ID, SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT, U32_LEN, U64_LEN,
};

use utils::{
    codec::leb128::{Leb128Reader, Leb128_},
    failed, BlobHash, UnwrapFailure, BLOB_HASH_LEN,
};

use crate::Core;

pub(super) const MAGIC_MARKER: u8 = 123;
pub(super) const FILE_VERSION: u8 = 2;

#[derive(Debug)]
pub(super) enum Op {
    Family(Family),
    AccountId(u32),
    Collection(u8),
    DocumentId(u32),
    KeyValue((Vec<u8>, Vec<u8>)),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Family {
    Property = 0,
    FtsIndex = 1,
    Acl = 2,
    Blob = 3,
    Config = 4,
    LookupValue = 5,
    LookupCounter = 6,
    Directory = 7,
    Queue = 8,
    Index = 9,
    Bitmap = 10,
    Log = 11,
    None = 255,
}

type TaskHandle = (tokio::task::JoinHandle<()>, std::thread::JoinHandle<()>);

impl Core {
    pub async fn backup(&self, dest: PathBuf) {
        if !dest.exists() {
            std::fs::create_dir_all(&dest).failed("Failed to create backup directory");
        } else if !dest.is_dir() {
            eprintln!("Backup destination {dest:?} is not a directory.");
            std::process::exit(1);
        }

        let mut sync_handles = Vec::new();

        for (async_handle, sync_handle) in [
            self.backup_properties(&dest),
            self.backup_fts_index(&dest),
            self.backup_acl(&dest),
            self.backup_blob(&dest),
            self.backup_config(&dest),
            self.backup_lookup(&dest),
            self.backup_directory(&dest),
            self.backup_queue(&dest),
            self.backup_index(&dest),
            self.backup_bitmaps(&dest),
            self.backup_logs(&dest),
        ] {
            async_handle.await.failed("Task failed");
            sync_handles.push(sync_handle);
        }

        for handle in sync_handles {
            handle.join().expect("Failed to join thread");
        }
    }

    fn backup_properties(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("property"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Property))
                    .failed("Failed to send family");

                let mut keys = BTreeSet::new();

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Property(0),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Property(u8::MAX),
                            },
                        )
                        .no_values(),
                        |key, _| {
                            let account_id = key.deserialize_be_u32(0)?;
                            let collection = key.deserialize_u8(U32_LEN)?;
                            let field = key.deserialize_u8(U32_LEN + 1)?;
                            let document_id = key.deserialize_be_u32(U32_LEN + 2)?;

                            keys.insert((account_id, collection, document_id, field));

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                let mut last_account_id = u32::MAX;
                let mut last_collection = u8::MAX;
                let mut last_document_id = u32::MAX;

                for (account_id, collection, document_id, field) in keys {
                    if account_id != last_account_id {
                        writer
                            .send(Op::AccountId(account_id))
                            .failed("Failed to send account id");
                        last_account_id = account_id;
                    }

                    if collection != last_collection {
                        writer
                            .send(Op::Collection(collection))
                            .failed("Failed to send collection");
                        last_collection = collection;
                    }

                    if document_id != last_document_id {
                        writer
                            .send(Op::DocumentId(document_id))
                            .failed("Failed to send document id");
                        last_document_id = document_id;
                    }

                    // Obtain UID counter
                    if collection == u8::from(Collection::Mailbox)
                        && u8::from(Property::Value) == field
                    {
                        let value = store
                            .get_counter(ValueKey {
                                account_id,
                                collection,
                                document_id,
                                class: ValueClass::Property(Property::EmailIds.into()),
                            })
                            .await
                            .failed("Failed to get counter");
                        if value != 0 {
                            writer
                                .send(Op::KeyValue((
                                    vec![u8::from(Property::EmailIds)],
                                    value.serialize(),
                                )))
                                .failed("Failed to send key value");
                        }
                    }

                    // Write value
                    let value = store
                        .get_value::<RawBytes>(ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class: ValueClass::Property(field),
                        })
                        .await
                        .failed("Failed to get value")
                        .failed("Expected value")
                        .0;
                    writer
                        .send(Op::KeyValue((vec![field], value)))
                        .failed("Failed to send key value");
                }
            }),
            handle,
        )
    }

    fn backup_fts_index(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("fts_index"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::FtsIndex))
                    .failed("Failed to send family");

                let mut last_account_id = u32::MAX;
                let mut last_collection = u8::MAX;

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::FtsIndex(BitmapHash {
                                    hash: [0; 8],
                                    len: 1,
                                }),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::FtsIndex(BitmapHash {
                                    hash: [u8::MAX; 8],
                                    len: u8::MAX,
                                }),
                            },
                        ),
                        |key, value| {
                            let account_id = key.deserialize_be_u32(0)?;
                            let collection = key.deserialize_u8(key.len() - U32_LEN - 1)?;
                            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;

                            if account_id != last_account_id {
                                writer
                                    .send(Op::AccountId(account_id))
                                    .failed("Failed to send account id");
                                last_account_id = account_id;
                            }

                            if collection != last_collection {
                                writer
                                    .send(Op::Collection(collection))
                                    .failed("Failed to send collection");
                                last_collection = collection;
                            }

                            writer
                                .send(Op::DocumentId(document_id))
                                .failed("Failed to send document id");

                            writer
                                .send(Op::KeyValue((
                                    key.range(U32_LEN..key.len() - U32_LEN - 1)?.to_vec(),
                                    value.to_vec(),
                                )))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");
            }),
            handle,
        )
    }

    fn backup_acl(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("acl"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Acl))
                    .failed("Failed to send family");

                let mut last_account_id = u32::MAX;
                let mut last_collection = u8::MAX;
                let mut last_document_id = u32::MAX;

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Acl(0),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Acl(u32::MAX),
                            },
                        ),
                        |key, value| {
                            let grant_account_id = key.deserialize_be_u32(0)?;
                            let account_id = key.deserialize_be_u32(U32_LEN)?;
                            let collection = key.deserialize_u8(U32_LEN * 2)?;
                            let document_id = key.deserialize_be_u32((U32_LEN * 2) + 1)?;

                            if account_id != last_account_id {
                                writer
                                    .send(Op::AccountId(account_id))
                                    .failed("Failed to send account id");
                                last_account_id = account_id;
                            }

                            if collection != last_collection {
                                writer
                                    .send(Op::Collection(collection))
                                    .failed("Failed to send collection");
                                last_collection = collection;
                            }

                            if document_id != last_document_id {
                                writer
                                    .send(Op::DocumentId(document_id))
                                    .failed("Failed to send document id");
                                last_document_id = document_id;
                            }

                            writer
                                .send(Op::KeyValue((
                                    grant_account_id.to_be_bytes().to_vec(),
                                    value.to_vec(),
                                )))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");
            }),
            handle,
        )
    }

    fn backup_blob(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let blob_store = self.storage.blob.clone();
        let (handle, writer) = spawn_writer(dest.join("blob"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Blob))
                    .failed("Failed to send family");

                let mut hashes = Vec::new();

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Blob(BlobOp::Link {
                                    hash: Default::default(),
                                }),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Blob(BlobOp::Link {
                                    hash: BlobHash::new_max(),
                                }),
                            },
                        ),
                        |key, _| {
                            let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                            let collection = key.deserialize_u8(BLOB_HASH_LEN + U32_LEN)?;
                            let document_id =
                                key.deserialize_be_u32(BLOB_HASH_LEN + U32_LEN + 1)?;

                            let hash = key.range(0..BLOB_HASH_LEN)?.to_vec();

                            if account_id != u32::MAX && document_id != u32::MAX {
                                writer
                                    .send(Op::AccountId(account_id))
                                    .failed("Failed to send account id");
                                writer
                                    .send(Op::Collection(collection))
                                    .failed("Failed to send collection");
                                writer
                                    .send(Op::DocumentId(document_id))
                                    .failed("Failed to send document id");
                                writer
                                    .send(Op::KeyValue((hash, vec![])))
                                    .failed("Failed to send key value");
                            } else {
                                hashes.push(hash);
                            }

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                if !hashes.is_empty() {
                    writer
                        .send(Op::AccountId(u32::MAX))
                        .failed("Failed to send account id");
                    writer
                        .send(Op::DocumentId(u32::MAX))
                        .failed("Failed to send document id");
                    for hash in hashes {
                        if let Some(value) = blob_store
                            .get_blob(&hash, 0..usize::MAX)
                            .await
                            .failed("Failed to get blob")
                        {
                            writer
                                .send(Op::KeyValue((hash, value)))
                                .failed("Failed to send key value");
                        } else {
                            eprintln!(
                            "Warning: blob hash {hash:?} does not exist in blob store. Skipping."
                        );
                        }
                    }
                }
            }),
            handle,
        )
    }

    fn backup_config(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("config"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Config))
                    .failed("Failed to send family");

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Config(vec![0]),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Config(vec![
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                ]),
                            },
                        ),
                        |key, value| {
                            writer
                                .send(Op::KeyValue((key.to_vec(), value.to_vec())))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");
            }),
            handle,
        )
    }

    fn backup_lookup(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("lookup"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::LookupValue))
                    .failed("Failed to send family");

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Lookup(LookupClass::Key(vec![0])),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Lookup(LookupClass::Key(vec![
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                ])),
                            },
                        ),
                        |key, value| {
                            writer
                                .send(Op::KeyValue((key.to_vec(), value.to_vec())))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                writer
                    .send(Op::Family(Family::LookupCounter))
                    .failed("Failed to send family");

                let mut counters = Vec::new();

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Lookup(LookupClass::Counter(vec![0])),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Lookup(LookupClass::Counter(vec![
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                    u8::MAX,
                                ])),
                            },
                        )
                        .no_values(),
                        |key, _| {
                            if (key.len() != (U32_LEN * 2) + 2)
                                || key[U32_LEN + 1] != 84
                                || key[U32_LEN] != 1
                            {
                                counters.push(key.to_vec());
                            }

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                for key in counters {
                    let value = store
                        .get_counter(ValueKey::from(ValueClass::Lookup(LookupClass::Counter(
                            key.clone(),
                        ))))
                        .await
                        .failed("Failed to get counter");

                    if value != 0 {
                        writer
                            .send(Op::KeyValue((key, value.serialize())))
                            .failed("Failed to send key value");
                    }
                }
            }),
            handle,
        )
    }

    fn backup_directory(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("directory"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Directory))
                    .failed("Failed to send family");

                let mut principal_ids = Vec::new();

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Directory(DirectoryClass::NameToId(vec![0])),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: u32::MAX,
                                    has_member: u32::MAX,
                                }),
                            },
                        ),
                        |key, value| {
                            if key[0] == 2 {
                                principal_ids.push(key.range(1..usize::MAX)?.to_vec());
                            }

                            writer
                                .send(Op::KeyValue((key.to_vec(), value.to_vec())))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                for principal_bytes in principal_ids {
                    let value = store
                        .get_counter(ValueKey::from(ValueClass::Directory(
                            DirectoryClass::UsedQuota(
                                principal_bytes
                                    .as_slice()
                                    .deserialize_leb128()
                                    .failed("Failed to deserialize principal id"),
                            ),
                        )))
                        .await
                        .failed("Failed to get counter");
                    if value != 0 {
                        let mut key = Vec::with_capacity(U32_LEN + 1);
                        key.push(4u8);
                        key.extend_from_slice(&principal_bytes);

                        writer
                            .send(Op::KeyValue((key, value.serialize())))
                            .failed("Failed to send key value");
                    }
                }
            }),
            handle,
        )
    }

    fn backup_queue(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("queue"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Queue))
                    .failed("Failed to send family");

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Queue(QueueClass::Message(0)),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Queue(QueueClass::Message(u64::MAX)),
                            },
                        ),
                        |key_, value| {
                            let mut key = Vec::with_capacity(U64_LEN + 1);
                            key.push(0);
                            key.extend_from_slice(key_);

                            writer
                                .send(Op::KeyValue((key, value.to_vec())))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                store
                    .iterate(
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                                    due: 0,
                                    queue_id: 0,
                                })),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                                    due: u64::MAX,
                                    queue_id: u64::MAX,
                                })),
                            },
                        ),
                        |key_, value| {
                            let mut key = Vec::with_capacity(U64_LEN + 1);
                            key.push(1);
                            key.extend_from_slice(key_);

                            writer
                                .send(Op::KeyValue((key, value.to_vec())))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");
            }),
            handle,
        )
    }

    fn backup_index(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("index"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Index))
                    .failed("Failed to send family");

                let mut last_account_id = u32::MAX;
                let mut last_collection = u8::MAX;

                store
                    .iterate(
                        IterateParams::new(
                            IndexKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                field: 0,
                                key: vec![0],
                            },
                            IndexKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                field: u8::MAX,
                                key: vec![u8::MAX, u8::MAX, u8::MAX],
                            },
                        )
                        .no_values(),
                        |key, _| {
                            let account_id = key.deserialize_be_u32(0)?;
                            let collection = key.deserialize_u8(U32_LEN)?;
                            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;

                            let key = key.range(U32_LEN + 1..key.len() - U32_LEN)?.to_vec();

                            if account_id != last_account_id {
                                writer
                                    .send(Op::AccountId(account_id))
                                    .failed("Failed to send account id");
                                last_account_id = account_id;
                            }

                            if collection != last_collection {
                                writer
                                    .send(Op::Collection(collection))
                                    .failed("Failed to send collection");
                                last_collection = collection;
                            }

                            writer
                                .send(Op::DocumentId(document_id))
                                .failed("Failed to send document id");

                            writer
                                .send(Op::KeyValue((key, vec![])))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");
            }),
            handle,
        )
    }

    fn backup_bitmaps(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();

        let (handle, writer) = spawn_writer(dest.join("bitmap"));
        (
            tokio::spawn(async move {
                const BM_MARKER: u8 = 1 << 7;

                writer
                    .send(Op::Family(Family::Bitmap))
                    .failed("Failed to send family");

                let mut bitmaps: AHashMap<(u32, u8), AHashSet<BitmapClass<u32>>> = AHashMap::new();

                for subspace in [
                    SUBSPACE_BITMAP_ID,
                    SUBSPACE_BITMAP_TAG,
                    SUBSPACE_BITMAP_TEXT,
                ] {
                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace,
                                    key: vec![0u8],
                                },
                                AnyKey {
                                    subspace,
                                    key: vec![u8::MAX; 10],
                                },
                            )
                            .no_values(),
                            |key, _| {
                                let account_id = key.deserialize_be_u32(0)?;

                                let key = key.range(0..key.len() - U32_LEN)?;

                                match subspace {
                                    SUBSPACE_BITMAP_ID => {
                                        let collection = key.deserialize_u8(U32_LEN)?;
                                        bitmaps
                                            .entry((account_id, collection))
                                            .or_default()
                                            .insert(BitmapClass::DocumentIds);
                                    }
                                    SUBSPACE_BITMAP_TAG => {
                                        let collection = key.deserialize_u8(U32_LEN)?;
                                        let value = key.range(U32_LEN + 2..usize::MAX)?;
                                        let (field, value) = match key
                                            .deserialize_u8(U32_LEN + 1)?
                                        {
                                            field if field & BM_MARKER == 0 => {
                                                (field, TagValue::Id(value.deserialize_leb128()?))
                                            }
                                            field => {
                                                (field & !BM_MARKER, TagValue::Text(value.to_vec()))
                                            }
                                        };

                                        bitmaps
                                            .entry((account_id, collection))
                                            .or_default()
                                            .insert(BitmapClass::Tag { field, value });
                                    }
                                    SUBSPACE_BITMAP_TEXT => {
                                        let collection = key.deserialize_u8(key.len() - 2)?;
                                        let mut hash = [0u8; 8];
                                        let (hash, len) = match key.len() - U32_LEN - 2 {
                                            9 => {
                                                hash[..8].copy_from_slice(
                                                    key.range(U32_LEN..key.len() - 3)?,
                                                );
                                                (hash, key.deserialize_u8(key.len() - 3)?)
                                            }
                                            len @ (1..=7) => {
                                                hash[..len].copy_from_slice(
                                                    key.range(U32_LEN..key.len() - 2)?,
                                                );
                                                (hash, len as u8)
                                            }
                                            _ => {
                                                return Err(trc::Error::corrupted_key(
                                                    key,
                                                    None,
                                                    trc::location!(),
                                                ));
                                            }
                                        };

                                        bitmaps
                                            .entry((account_id, collection))
                                            .or_default()
                                            .insert(BitmapClass::Text {
                                                field: key.deserialize_u8(key.len() - 1)?,
                                                token: BitmapHash { hash, len },
                                            });
                                    }
                                    _ => unreachable!(),
                                }

                                Ok(true)
                            },
                        )
                        .await
                        .failed("Failed to iterate over data store");
                }

                for ((account_id, collection), classes) in bitmaps {
                    writer
                        .send(Op::AccountId(account_id))
                        .failed("Failed to send account id");
                    writer
                        .send(Op::Collection(collection))
                        .failed("Failed to send collection");

                    for class in classes {
                        if let Some(bitmap) = store
                            .get_bitmap(BitmapKey {
                                account_id,
                                collection,
                                class: class.clone(),
                                document_id: 0,
                            })
                            .await
                            .failed("Failed to get bitmap")
                        {
                            let key = match class {
                                BitmapClass::DocumentIds => {
                                    vec![0u8]
                                }
                                BitmapClass::Tag { field, value } => {
                                    let mut key = Vec::with_capacity(3);

                                    match value {
                                        TagValue::Id(id) => {
                                            key.push(1u8);
                                            key.push(field);
                                            key.extend_from_slice(&id.serialize());
                                        }
                                        TagValue::Text(text) => {
                                            key.push(2u8);
                                            key.push(field);
                                            key.extend_from_slice(&text);
                                        }
                                    }

                                    key
                                }
                                BitmapClass::Text { field, token } => {
                                    let mut key = vec![4u8, field];
                                    key.push(token.len);
                                    key.extend_from_slice(&token.hash);
                                    key
                                }
                            };

                            let mut bytes = Vec::with_capacity(bitmap.serialized_size());
                            bitmap
                                .serialize_into(&mut bytes)
                                .failed("Failed to serialize bitmap");

                            writer
                                .send(Op::KeyValue((key, bytes)))
                                .failed("Failed to send key value");
                        }
                    }
                }
            }),
            handle,
        )
    }

    fn backup_logs(&self, dest: &Path) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(dest.join("log"));
        (
            tokio::spawn(async move {
                writer
                    .send(Op::Family(Family::Log))
                    .failed("Failed to send family");

                let mut last_account_id = u32::MAX;
                let mut last_collection = u8::MAX;

                store
                    .iterate(
                        IterateParams::new(
                            LogKey {
                                account_id: 0,
                                collection: 0,
                                change_id: 0,
                            },
                            LogKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                change_id: u64::MAX,
                            },
                        ),
                        |key, value| {
                            let account_id = key.deserialize_be_u32(0)?;
                            let collection = key.deserialize_u8(U32_LEN)?;
                            let key = key.range(U32_LEN + 1..usize::MAX)?.to_vec();

                            if key.len() != U64_LEN {
                                failed(&format!("Found invalid log entry {key:?} {value:?}"));
                            }

                            if account_id != last_account_id {
                                writer
                                    .send(Op::AccountId(account_id))
                                    .failed("Failed to send account id");
                                last_account_id = account_id;
                            }

                            if collection != last_collection {
                                writer
                                    .send(Op::Collection(collection))
                                    .failed("Failed to send collection");
                                last_collection = collection;
                            }

                            writer
                                .send(Op::KeyValue((key, value.to_vec())))
                                .failed("Failed to send key value");

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");
            }),
            handle,
        )
    }
}

fn spawn_writer(path: PathBuf) -> (std::thread::JoinHandle<()>, SyncSender<Op>) {
    let (tx, rx) = mpsc::sync_channel(10);

    let handle = std::thread::spawn(move || {
        println!("Exporting database to {}.", path.to_str().unwrap());

        let mut file =
            BufWriter::new(std::fs::File::create(path).failed("Failed to create backup file"));
        file.write_all(&[MAGIC_MARKER, FILE_VERSION])
            .failed("Failed to write version");

        while let Ok(op) = rx.recv() {
            match op {
                Op::Family(f) => {
                    file.write_all(&[0u8, f as u8])
                        .failed("Failed to write family");
                }
                Op::KeyValue((k, v)) => {
                    file.write_all(&[if !v.is_empty() { 1u8 } else { 2u8 }])
                        .failed("Failed to write key");
                    file.write_all(&(k.len() as u32).serialize())
                        .failed("Failed to write key value");
                    file.write_all(&k).failed("Failed to write key");
                    if !v.is_empty() {
                        file.write_all(&(v.len() as u32).serialize())
                            .failed("Failed to write key value");
                        file.write_all(&v).failed("Failed to write key value");
                    }
                }
                Op::AccountId(v) => {
                    file.write_all(&[3u8]).failed("Failed to write account id");
                    file.write_all(&v.serialize())
                        .failed("Failed to write account id");
                }
                Op::Collection(v) => {
                    file.write_all(&[4u8, v])
                        .failed("Failed to write collection");
                }
                Op::DocumentId(v) => {
                    file.write_all(&[5u8]).failed("Failed to write document id");
                    file.write_all(&v.serialize())
                        .failed("Failed to write document id");
                }
            }
        }

        file.flush().failed("Failed to flush backup file");
    });

    (handle, tx)
}

pub(super) trait DeserializeBytes {
    fn range(&self, range: Range<usize>) -> trc::Result<&[u8]>;
    fn deserialize_u8(&self, offset: usize) -> trc::Result<u8>;
    fn deserialize_leb128<U: Leb128_>(&self) -> trc::Result<U>;
}

impl DeserializeBytes for &[u8] {
    fn range(&self, range: Range<usize>) -> trc::Result<&[u8]> {
        self.get(range.start..std::cmp::min(range.end, self.len()))
            .ok_or_else(|| trc::StoreCause::DataCorruption.caused_by(trc::location!()))
    }

    fn deserialize_u8(&self, offset: usize) -> trc::Result<u8> {
        self.get(offset)
            .copied()
            .ok_or_else(|| trc::StoreCause::DataCorruption.caused_by(trc::location!()))
    }

    fn deserialize_leb128<U: Leb128_>(&self) -> trc::Result<U> {
        self.read_leb128::<U>()
            .map(|(v, _)| v)
            .ok_or_else(|| trc::StoreCause::DataCorruption.caused_by(trc::location!()))
    }
}

struct RawBytes(Vec<u8>);

impl Deserialize for RawBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}
