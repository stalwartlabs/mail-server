use std::time::{Duration, Instant, SystemTime};

use ahash::AHashSet;
use foundationdb::{
    options::{MutationType, StreamingMode},
    FdbError, KeySelector, RangeOption,
};
use futures::StreamExt;
use rand::Rng;

use crate::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        Batch, Operation,
    },
    AclKey, BitmapKey, BlobKey, Deserialize, IndexKey, LogKey, Serialize, Store, ValueKey,
    BM_DOCUMENT_IDS,
};

use super::{
    bitmap::{next_available_index, DenseBitmap, BITS_PER_BLOCK},
    SUBSPACE_VALUES,
};

#[cfg(test)]
const ID_ASSIGNMENT_EXPIRY: u64 = 2; // seconds
#[cfg(not(test))]
pub const ID_ASSIGNMENT_EXPIRY: u64 = 60 * 60; // seconds

const MAX_COMMIT_ATTEMPTS: u8 = 10;
const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

impl Store {
    pub async fn write(&self, batch: Batch) -> crate::Result<()> {
        let start = Instant::now();
        let mut or_bitmap = DenseBitmap::empty();
        let mut and_bitmap = DenseBitmap::full();
        let mut block_num = u32::MAX;
        let mut retry_count = 0;

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let trx = self.db.create_trx()?;

            for op in &batch.ops {
                match op {
                    Operation::AccountId {
                        account_id: account_id_,
                    } => {
                        account_id = *account_id_;
                    }
                    Operation::Collection {
                        collection: collection_,
                    } => {
                        collection = *collection_;
                    }
                    Operation::DocumentId {
                        document_id: document_id_,
                    } => {
                        if block_num != u32::MAX {
                            or_bitmap.reset();
                            and_bitmap.reset();
                        }
                        document_id = *document_id_;
                        or_bitmap.set(document_id);
                        and_bitmap.clear(document_id);
                        block_num = or_bitmap.block_num;
                    }
                    Operation::Value { family, field, set } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            family: *family,
                            field: *field,
                        }
                        .serialize();
                        if let Some(value) = set {
                            trx.set(&key, value);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Index { field, key, set } => {
                        let key = IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key,
                        }
                        .serialize();
                        if *set {
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Bitmap {
                        family,
                        field,
                        key,
                        set,
                    } => {
                        let key = BitmapKey {
                            account_id,
                            collection,
                            family: *family,
                            field: *field,
                            block_num,
                            key,
                        }
                        .serialize();
                        if *set {
                            trx.atomic_op(&key, &or_bitmap.bitmap, MutationType::BitOr);
                        } else {
                            trx.atomic_op(&key, &and_bitmap.bitmap, MutationType::BitAnd);
                        };
                    }
                    Operation::Blob { key, set } => {
                        let key = BlobKey {
                            account_id,
                            collection,
                            document_id,
                            hash: key,
                        }
                        .serialize();
                        if *set {
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Acl {
                        grant_account_id,
                        set,
                    } => {
                        let key = AclKey {
                            grant_account_id: *grant_account_id,
                            to_account_id: account_id,
                            to_collection: collection,
                            to_document_id: document_id,
                        }
                        .serialize();
                        if let Some(value) = set {
                            trx.set(&key, value);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Log {
                        collection,
                        change_id,
                        set,
                    } => {
                        let key = LogKey {
                            account_id,
                            collection: *collection,
                            change_id: *change_id,
                        }
                        .serialize();
                        trx.set(&key, set);
                    }
                }
            }

            match trx.commit().await {
                Ok(_) => {
                    return Ok(());
                }
                Err(err) => {
                    if retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME {
                        err.on_error().await?;
                        retry_count += 1;
                    } else {
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }

    pub async fn assign_document_id(&self, account_id: u32, collection: u8) -> crate::Result<u32> {
        let start = Instant::now();

        loop {
            //let mut assign_source = 0;
            // First try to reuse an expired assigned id
            let begin = IndexKey {
                account_id,
                collection,
                document_id: 0,
                field: u8::MAX,
                key: &[],
            }
            .serialize();
            let end = IndexKey {
                account_id,
                collection,
                document_id: u32::MAX,
                field: u8::MAX,
                key: &[],
            }
            .serialize();
            let trx = self.db.create_trx()?;

            let mut values = trx.get_ranges(
                RangeOption {
                    begin: KeySelector::first_greater_or_equal(begin),
                    end: KeySelector::first_greater_or_equal(end),
                    mode: StreamingMode::Iterator,
                    reverse: false,
                    ..RangeOption::default()
                },
                true,
            );

            let expired_timestamp = now() - ID_ASSIGNMENT_EXPIRY;
            let mut reserved_ids = AHashSet::new();
            let mut expired_ids = Vec::new();
            while let Some(values) = values.next().await {
                for value in values? {
                    let key = value.key();
                    let document_id =
                        key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?;
                    if u64::deserialize(value.value())? <= expired_timestamp {
                        // Found an expired id, reuse it
                        expired_ids.push(document_id);
                    } else {
                        // Keep track of all reserved ids
                        reserved_ids.insert(document_id);
                    }
                }
            }
            drop(values);

            let mut document_id = u32::MAX;

            if !expired_ids.is_empty() {
                // Obtain a random id from the expired ids
                if expired_ids.len() > 1 {
                    document_id = expired_ids[rand::thread_rng().gen_range(0..expired_ids.len())];
                    //assign_source = 1;
                } else {
                    document_id = expired_ids[0];
                    //assign_source = 2;
                }
            } else {
                // Find the next available id
                let mut key = BitmapKey {
                    account_id,
                    collection,
                    family: BM_DOCUMENT_IDS,
                    field: u8::MAX,
                    key: b"",
                    block_num: 0,
                };
                let begin = key.serialize();
                key.block_num = u32::MAX;
                let end = key.serialize();
                let mut values = trx.get_ranges(
                    RangeOption {
                        begin: KeySelector::first_greater_or_equal(begin),
                        end: KeySelector::first_greater_or_equal(end),
                        mode: StreamingMode::Iterator,
                        reverse: false,
                        ..RangeOption::default()
                    },
                    true,
                );

                'outer: while let Some(values) = values.next().await {
                    for value in values? {
                        let key = value.key();
                        if let Some(next_id) = next_available_index(
                            value.value(),
                            key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?,
                            &reserved_ids,
                        ) {
                            document_id = next_id;
                            //assign_source = 3;

                            break 'outer;
                        }
                    }
                }
            }

            // If no ids were found, assign the first available id that is not reserved
            if document_id == u32::MAX {
                document_id = 1024;
                for document_id_ in 0..BITS_PER_BLOCK {
                    if !reserved_ids.contains(&document_id_) {
                        document_id = document_id_;
                        //assign_source = 4;

                        break;
                    }
                }
            }

            // Reserve the id
            let key = IndexKey {
                account_id,
                collection,
                document_id,
                field: u8::MAX,
                key: &[],
            }
            .serialize();
            trx.get(&key, false).await?; // Read to create conflict range
            trx.set(&key, &now().serialize());

            match trx.commit().await {
                Ok(_) => {
                    //println!("assigned id: {document_id} {assign_source}");

                    return Ok(document_id);
                }
                Err(err) => {
                    if start.elapsed() < MAX_COMMIT_TIME {
                        err.on_error().await?;
                    } else {
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }

    pub async fn assign_change_id(&self, account_id: u32, collection: u8) -> crate::Result<u64> {
        let start = Instant::now();
        let counter = KeySerializer::new(std::mem::size_of::<u32>() + 2)
            .write(SUBSPACE_VALUES)
            .write_leb128(account_id)
            .write(collection)
            .finalize();

        loop {
            // Read id
            let trx = self.db.create_trx()?;
            let id = if let Some(bytes) = trx.get(&counter, false).await? {
                u64::deserialize(&bytes)? + 1
            } else {
                0
            };
            trx.set(&counter, &id.serialize());

            match trx.commit().await {
                Ok(_) => {
                    return Ok(id);
                }
                Err(err) => {
                    if start.elapsed() < MAX_COMMIT_TIME {
                        err.on_error().await?;
                    } else {
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub async fn destroy(&self) {
        let trx = self.db.create_trx().unwrap();
        trx.clear_range(&[0u8], &[u8::MAX]);
        trx.commit().await.unwrap();
    }
}

#[inline(always)]
fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
