/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use crate::Core;
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    roaring::RoaringBitmap,
    write::{
        key::DeserializeBigEndian, BatchBuilder, BitmapClass, BitmapHash, BlobOp, DirectoryClass,
        FtsQueueClass, LookupClass, MaybeDynamicId, MaybeDynamicValue, Operation, TagValue,
        ValueClass,
    },
    BlobStore, Serialize, Store, U32_LEN,
};
use store::{
    write::{QueueClass, QueueEvent},
    Deserialize, U64_LEN,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, BufReader},
};
use utils::{failed, BlobHash, UnwrapFailure};

use super::backup::{DeserializeBytes, Family, Op, FILE_VERSION, MAGIC_MARKER};

impl Core {
    pub async fn restore(&self, src: PathBuf) {
        // Backup the core
        if src.is_dir() {
            // Iterate directory and spawn a task for each file
            let mut tasks = Vec::new();
            for entry in std::fs::read_dir(&src).failed("Failed to read directory") {
                let entry = entry.failed("Failed to read entry");
                let path = entry.path();
                if path.is_file() {
                    let storage = self.storage.clone();
                    let blob_store = self.storage.blob.clone();
                    tasks.push(tokio::spawn(async move {
                        restore_file(storage.data, blob_store, &path).await;
                    }));
                }
            }

            for task in tasks {
                task.await.failed("Failed to wait for task");
            }
        } else {
            restore_file(self.storage.data.clone(), self.storage.blob.clone(), &src).await;
        }
    }
}

async fn restore_file(store: Store, blob_store: BlobStore, path: &Path) {
    println!("Importing database dump from {}.", path.to_str().unwrap());

    let mut reader = OpReader::new(path).await;
    let mut account_id = u32::MAX;
    let mut document_id = u32::MAX;
    let mut collection = u8::MAX;
    let mut family = Family::None;
    let email_collection = u8::from(Collection::Email);
    let mut seq = 0;

    let mut batch_size = 0;
    let mut batch = BatchBuilder::new();

    while let Some(op) = reader.next().await {
        match op {
            Op::Family(f) => family = f,
            Op::AccountId(a) => {
                account_id = a;
                batch.with_account_id(account_id);
            }
            Op::Collection(c) => {
                collection = c;
                batch.with_collection(collection);
            }
            Op::DocumentId(d) => {
                document_id = d;
                batch.update_document(document_id);
            }
            Op::KeyValue((key, value)) => {
                batch_size += key.len() + value.len() + U32_LEN * 2;

                match family {
                    Family::Property => {
                        let field = key
                            .as_slice()
                            .deserialize_u8(0)
                            .expect("Failed to deserialize field");
                        if collection == u8::from(Collection::Mailbox)
                            && u8::from(Property::EmailIds) == field
                        {
                            batch.add(
                                ValueClass::Property(field),
                                i64::deserialize(&value)
                                    .expect("Failed to deserialize mailbox uidnext"),
                            );
                        } else {
                            batch.set(ValueClass::Property(field), value);
                        }
                    }
                    Family::FtsIndex => {
                        if reader.version > 1 {
                            let mut hash = [0u8; 8];
                            let (hash, len) = match key.len() {
                                9 => {
                                    hash[..8].copy_from_slice(&key[..8]);
                                    (hash, key[key.len() - 1])
                                }
                                len @ (1..=7) => {
                                    hash[..len].copy_from_slice(&key[..len]);
                                    (hash, len as u8)
                                }
                                invalid => {
                                    panic!("Invalid text bitmap key length {invalid}");
                                }
                            };

                            batch.set(ValueClass::FtsIndex(BitmapHash { hash, len }), value);
                        }
                    }
                    Family::Acl => {
                        batch.set(
                            ValueClass::Acl(
                                key.as_slice()
                                    .deserialize_be_u32(0)
                                    .expect("Failed to deserialize acl"),
                            ),
                            value,
                        );
                    }
                    Family::Blob => {
                        let hash = BlobHash::try_from_hash_slice(&key).expect("Invalid blob hash");

                        if account_id != u32::MAX && document_id != u32::MAX {
                            if reader.version == 1 && collection == email_collection {
                                batch.set(
                                    ValueClass::FtsQueue(FtsQueueClass {
                                        seq,
                                        hash: hash.clone(),
                                    }),
                                    0u64.serialize(),
                                );
                                seq += 1;
                            }
                            batch.set(ValueClass::Blob(BlobOp::Link { hash }), vec![]);
                        } else {
                            batch_size -= value.len();
                            blob_store
                                .put_blob(&key, &value)
                                .await
                                .expect("Failed to write blob");
                            batch.set(ValueClass::Blob(BlobOp::Commit { hash }), vec![]);
                        }
                    }
                    Family::Config => {
                        batch.set(ValueClass::Config(key), value);
                    }
                    Family::LookupValue => {
                        batch.set(ValueClass::Lookup(LookupClass::Key(key)), value);
                    }
                    Family::LookupCounter => {
                        batch.add(
                            ValueClass::Lookup(LookupClass::Counter(key)),
                            i64::deserialize(&value).expect("Failed to deserialize counter"),
                        );
                    }
                    Family::Directory => {
                        let key = key.as_slice();
                        let class: DirectoryClass<MaybeDynamicId> =
                            match key.first().expect("Failed to read directory key type") {
                                0 => DirectoryClass::NameToId(
                                    key.get(1..)
                                        .expect("Failed to read directory string")
                                        .to_vec(),
                                ),
                                1 => DirectoryClass::EmailToId(
                                    key.get(1..)
                                        .expect("Failed to read directory string")
                                        .to_vec(),
                                ),
                                2 => DirectoryClass::Principal(MaybeDynamicId::Static(
                                    key.get(1..)
                                        .expect("Failed to read range for principal id")
                                        .deserialize_leb128::<u32>()
                                        .expect("Failed to deserialize principal id"),
                                )),
                                3 => DirectoryClass::Domain(
                                    key.get(1..)
                                        .expect("Failed to read directory string")
                                        .to_vec(),
                                ),
                                4 => {
                                    batch.add(
                                        ValueClass::Directory(DirectoryClass::UsedQuota(
                                            key.get(1..)
                                                .expect("Failed to read principal id")
                                                .deserialize_leb128()
                                                .expect("Failed to read principal id"),
                                        )),
                                        i64::deserialize(&value)
                                            .expect("Failed to deserialize quota"),
                                    );

                                    continue;
                                }
                                5 => DirectoryClass::MemberOf {
                                    principal_id: MaybeDynamicId::Static(
                                        key.deserialize_be_u32(1)
                                            .expect("Failed to read principal id"),
                                    ),
                                    member_of: MaybeDynamicId::Static(
                                        key.deserialize_be_u32(1 + U32_LEN)
                                            .expect("Failed to read principal id"),
                                    ),
                                },
                                6 => DirectoryClass::Members {
                                    principal_id: MaybeDynamicId::Static(
                                        key.deserialize_be_u32(1)
                                            .expect("Failed to read principal id"),
                                    ),
                                    has_member: MaybeDynamicId::Static(
                                        key.deserialize_be_u32(1 + U32_LEN)
                                            .expect("Failed to read principal id"),
                                    ),
                                },

                                _ => failed("Invalid directory key"),
                            };
                        batch.set(ValueClass::Directory(class), value);
                    }
                    Family::Queue => {
                        let key = key.as_slice();

                        match key.first().expect("Failed to read queue key type") {
                            0 => {
                                batch.set(
                                    ValueClass::Queue(QueueClass::Message(
                                        key.deserialize_be_u64(1)
                                            .expect("Failed to deserialize queue message id"),
                                    )),
                                    value,
                                );
                            }
                            1 => {
                                batch.set(
                                    ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                                        due: key
                                            .deserialize_be_u64(1)
                                            .expect("Failed to deserialize queue message id"),
                                        queue_id: key
                                            .deserialize_be_u64(1 + U64_LEN)
                                            .expect("Failed to deserialize queue message id"),
                                    })),
                                    value,
                                );
                            }
                            _ => failed("Invalid queue key"),
                        }
                    }
                    Family::Index => batch.ops.push(Operation::Index {
                        field: key.first().copied().expect("Failed to read index field"),
                        key: key.get(1..).expect("Failed to read index key").to_vec(),
                        set: true,
                    }),
                    Family::Bitmap => {
                        let key = key.as_slice();
                        let class: BitmapClass<MaybeDynamicId> =
                            match key.first().expect("Failed to read bitmap class") {
                                0 => BitmapClass::DocumentIds,
                                1 => BitmapClass::Tag {
                                    field: key.get(1).copied().expect("Failed to read field"),
                                    value: TagValue::Id(MaybeDynamicId::Static(
                                        key.deserialize_be_u32(2).expect("Failed to read tag id"),
                                    )),
                                },
                                2 => BitmapClass::Tag {
                                    field: key.get(1).copied().expect("Failed to read field"),
                                    value: TagValue::Text(
                                        key.get(2..).expect("Failed to read tag text").to_vec(),
                                    ),
                                },
                                3 => BitmapClass::Tag {
                                    field: key.get(1).copied().expect("Failed to read field"),
                                    value: TagValue::Id(MaybeDynamicId::Static(
                                        key.get(2)
                                            .copied()
                                            .expect("Failed to read tag static id")
                                            .into(),
                                    )),
                                },
                                4 => {
                                    if reader.version == 1 && collection == email_collection {
                                        continue;
                                    }

                                    BitmapClass::Text {
                                        field: key.get(1).copied().expect("Failed to read field"),
                                        token: BitmapHash {
                                            len: key
                                                .get(2)
                                                .copied()
                                                .expect("Failed to read tag static id"),
                                            hash: key
                                                .get(3..11)
                                                .expect("Failed to read tag static id")
                                                .try_into()
                                                .unwrap(),
                                        },
                                    }
                                }
                                _ => failed("Invalid bitmap class"),
                            };
                        let document_ids = RoaringBitmap::deserialize_from(&value[..])
                            .expect("Failed to deserialize bitmap");

                        for document_id in document_ids {
                            batch.ops.push(Operation::DocumentId { document_id });
                            batch.ops.push(Operation::Bitmap {
                                class: class.clone(),
                                set: true,
                            });

                            if batch.ops.len() >= 1000 {
                                store
                                    .write(batch.build())
                                    .await
                                    .failed("Failed to write batch");
                                batch = BatchBuilder::new();
                                batch
                                    .with_account_id(account_id)
                                    .with_collection(collection);
                            }
                        }
                    }
                    Family::Log => {
                        batch.ops.push(Operation::ChangeId {
                            change_id: key
                                .as_slice()
                                .deserialize_be_u64(0)
                                .expect("Failed to deserialize change id"),
                        });
                        batch.ops.push(Operation::Log {
                            set: MaybeDynamicValue::Static(value),
                        });
                    }
                    Family::None => failed("No family specified in file"),
                }
            }
        }

        if batch.ops.len() >= 1000 || batch_size >= 5_000_000 {
            store
                .write(batch.build())
                .await
                .failed("Failed to write batch");
            batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(collection)
                .update_document(document_id);
            batch_size = 0;
        }
    }

    if !batch.is_empty() {
        store
            .write(batch.build())
            .await
            .failed("Failed to write batch");
    }
}

struct OpReader {
    version: u8,
    file: BufReader<File>,
}

impl OpReader {
    async fn new(path: &Path) -> Self {
        let mut file = BufReader::new(File::open(&path).await.failed("Failed to open file"));

        if file
            .read_u8()
            .await
            .failed(&format!("Failed to read magic marker from {path:?}"))
            != MAGIC_MARKER
        {
            failed(&format!("Invalid magic marker in {path:?}"));
        }

        let version = file
            .read_u8()
            .await
            .failed(&format!("Failed to read version from {path:?}"));

        if version > FILE_VERSION {
            failed(&format!("Invalid file version in {path:?}"));
        }

        Self { file, version }
    }

    async fn next(&mut self) -> Option<Op> {
        match self.file.read_u8().await {
            Ok(byte) => match byte {
                0 => Op::Family(
                    Family::try_from(self.expect_u8().await).failed("Failed to read family"),
                ),
                1 => Op::KeyValue((
                    self.expect_sized_bytes().await,
                    self.expect_sized_bytes().await,
                )),
                2 => Op::KeyValue((self.expect_sized_bytes().await, vec![])),
                3 => Op::AccountId(self.expect_u32_be().await),
                4 => Op::Collection(self.expect_u8().await),
                5 => Op::DocumentId(self.expect_u32_be().await),
                unknown => {
                    failed(&format!("Unknown op type {unknown}"));
                }
            }
            .into(),
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => None,
            Err(err) => failed(&format!("Failed to read file: {err:?}")),
        }
    }

    async fn expect_u8(&mut self) -> u8 {
        self.file.read_u8().await.failed("Failed to read u8")
    }

    async fn expect_u32_be(&mut self) -> u32 {
        self.file.read_u32().await.failed("Failed to read u32")
    }

    async fn expect_sized_bytes(&mut self) -> Vec<u8> {
        let len = self.expect_u32_be().await as usize;
        let mut bytes = vec![0; len];
        self.file
            .read_exact(&mut bytes)
            .await
            .failed("Failed to read bytes");
        bytes
    }
}

impl TryFrom<u8> for Family {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Property),
            1 => Ok(Self::FtsIndex),
            2 => Ok(Self::Acl),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Config),
            5 => Ok(Self::LookupValue),
            6 => Ok(Self::LookupCounter),
            7 => Ok(Self::Directory),
            8 => Ok(Self::Queue),
            9 => Ok(Self::Index),
            10 => Ok(Self::Bitmap),
            11 => Ok(Self::Log),
            other => Err(format!("Unknown family type {other}")),
        }
    }
}
