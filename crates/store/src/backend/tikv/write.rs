/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, iter, time::{Duration, Instant}};
use std::collections::Bound;
use tikv_client::{Backoff, BoundRange, CheckLevel, Key as TikvKey, RetryOptions, TimestampExt, Transaction, Value};
use rand::Rng;
use roaring::RoaringBitmap;
use tikv_client::TransactionOptions;
use tikv_client::proto::kvrpcpb::{Assertion, Mutation, Op};
use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId, ValueOp,
        MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN, WITH_SUBSPACE,
};
use crate::write::key;
use super::{into_error, read::{ChunkedValue}, TikvStore, ReadVersion, MAX_VALUE_SIZE, MAX_SCAN_KEYS_SIZE};

impl TikvStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = u64::MAX;

        let mut backoff = self.raw_backoff.clone();

        loop {
            let mut result = AssignedIds::default();

            let mut trx = self.write_trx_no_backoff().await?;

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
                        document_id = *document_id_;
                    }
                    Operation::ChangeId {
                        change_id: change_id_,
                    } => {
                        change_id = *change_id_;
                    }
                    Operation::Value { class, op } => {
                        let mut key_vec = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            WITH_SUBSPACE,
                            (&result).into(),
                        );
                        let mut key = self.new_key_serializer(key_vec.len(), false)
                            .write(key_vec.as_slice())
                            .finalize();
                        let do_chunk = !class.is_counter(collection);

                        match op {
                            ValueOp::Set(value) => {
                                let value = value.resolve(&result)?;

                                if !value.is_empty() && do_chunk {
                                    for (pos, chunk) in value.chunks(MAX_VALUE_SIZE as usize).enumerate() {
                                        match pos.cmp(&1) {
                                            Ordering::Less => {}
                                            Ordering::Equal => {
                                                key.push(0);
                                            }
                                            Ordering::Greater => {
                                                if pos < u8::MAX as usize {
                                                    *key.last_mut().unwrap() += 1;
                                                } else {
                                                    trx.rollback().await.map_err(into_error)?;
                                                    return Err(trc::StoreEvent::TikvError
                                                        .ctx(
                                                            trc::Key::Reason,
                                                            "Value is too large",
                                                        ));
                                                }
                                            }
                                        }
                                        trx.put(key.clone(), chunk).await.map_err(into_error)?;
                                    }
                                } else {
                                    trx.put(key, value.into_owned()).await.map_err(into_error)?;
                                }
                            }
                            ValueOp::AtomicAdd(by) => {
                                get_and_add(&mut trx, key, *by).await?;
                            }
                            ValueOp::AddAndGet(by) => {
                                let num = get_and_add(&mut trx, key, *by).await?;
                                result.push_counter_id(num);
                            }
                            ValueOp::Clear => {
                                if do_chunk {
                                    let end_vec = self.new_key_serializer(key.len() + 1, false)
                                        .write(key.as_slice())
                                        .write(u8::MAX)
                                        .finalize();
                                    let mut begin = Bound::Included(TikvKey::from(key));
                                    let end = Bound::Included(TikvKey::from(end_vec));

                                    'outer: loop {
                                        let range = BoundRange::new(begin, end.clone());
                                        let mut keys_iter = trx.scan_keys(range, MAX_SCAN_KEYS_SIZE)
                                            .await
                                            .map_err(into_error)?
                                            .peekable();

                                        let mut count = 0;
                                        while let Some(key) = keys_iter.next() {
                                            count += 1;
                                            if keys_iter.peek().is_none() {
                                                if count < MAX_SCAN_KEYS_SIZE {
                                                    trx.delete(key).await.map_err(into_error)?;
                                                    break 'outer;
                                                } else {
                                                    begin = Bound::Excluded(key.clone());
                                                    trx.delete(key).await.map_err(into_error)?;
                                                    continue 'outer;
                                                }
                                            } else {
                                                trx.delete(key).await.map_err(into_error)?;
                                            }
                                        }

                                        // Empty
                                        break;
                                    }

                                } else {
                                    trx.delete(key).await.map_err(into_error)?;
                                }
                            }
                        }
                    }
                    Operation::Index {  field, key, set } => {
                        let key_vec = IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key,
                        }.serialize(0);
                        let key = self.new_key_serializer(key_vec.len(), false)
                            .write(key_vec.as_slice())
                            .finalize();

                        if *set {
                            trx.put(key, &[]).await.map_err(into_error)?;
                        } else {
                            trx.delete(key).await.map_err(into_error)?;
                        }
                    }
                    Operation::Bitmap { class, set } => {
                        let assign_id = *set
                            && matches!(class, BitmapClass::DocumentIds)
                            && document_id == u32::MAX;

                        if assign_id {
                            let begin_vec = BitmapKey {
                                account_id,
                                collection,
                                class: BitmapClass::DocumentIds,
                                document_id: 0,
                            }.serialize(WITH_SUBSPACE);
                            let begin = self.new_key_serializer(begin_vec.len(), false)
                                .write(begin_vec.as_slice())
                                .finalize();
                            let end_vec = BitmapKey {
                                account_id,
                                collection,
                                class: BitmapClass::DocumentIds,
                                document_id: u32::MAX,
                            }.serialize(WITH_SUBSPACE);
                            let end = self.new_key_serializer(end_vec.len(), false)
                                .write(end_vec.as_slice())
                                .finalize();

                            let key_len = begin.len();
                            let mut begin_bound = Bound::Included(TikvKey::from(begin));
                            let end_bound = Bound::Included(TikvKey::from(end));

                            let mut found_ids = RoaringBitmap::new();
                            'outer: loop {
                                let range = BoundRange::new(begin_bound, end_bound.clone());
                                let mut keys_iter = trx.scan_keys(range, MAX_SCAN_KEYS_SIZE)
                                    .await
                                    .map_err(into_error)?
                                    .peekable();
                                let mut count = 0;

                                while let Some(key) = keys_iter.next() {
                                    count += 1;
                                    if key.len() == key_len {
                                        let found_id = self.remove_prefix((&key).into())
                                            .deserialize_be_u32(key_len - U32_LEN)?;
                                        found_ids.insert(found_id);
                                    } else {
                                        if count < MAX_SCAN_KEYS_SIZE {

                                            break 'outer;
                                        } else {
                                            begin_bound = Bound::Excluded(key);
                                            continue 'outer;
                                        }
                                    }
                                    let key_slice = self.remove_prefix((&key).into());
                                    found_ids.insert(key_slice.deserialize_be_u32(key_len - U32_LEN)?);
                                    if keys_iter.peek().is_none() {
                                        if count < MAX_SCAN_KEYS_SIZE {

                                            break 'outer;
                                        } else {
                                            begin_bound = Bound::Excluded(key);
                                            continue 'outer;
                                        }
                                    }
                                }

                                // Empty
                                break;
                            }

                            document_id = found_ids.random_available_id();
                            result.push_document_id(document_id);
                        }

                        let key_vec = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            WITH_SUBSPACE,
                            (&result).into(),
                        );
                        let key = self.new_key_serializer(key_vec.len(), false)
                            .write(key_vec.as_slice())
                            .finalize();

                        if *set {
                            let mut begin = Bound::Included(TikvKey::from(key));
                            let end_vec = class.serialize(
                                account_id,
                                collection,
                                document_id + 1,
                                WITH_SUBSPACE,
                                (&result).into(),
                            );

                            loop {
                                let end_key = TikvKey::from(self.new_key_serializer(end_vec.len(), false)
                                    .write(end_vec.as_slice())
                                    .finalize());
                                let end = Bound::Included(end_key);

                                let range = BoundRange::new(begin, end);
                                let keys: Vec<TikvKey> = trx.scan_keys(range, MAX_SCAN_KEYS_SIZE)
                                    .await
                                    .map_err(into_error)?
                                    .collect();

                                if keys.len() < MAX_SCAN_KEYS_SIZE as usize {
                                    trx.lock_keys(keys).await.map_err(into_error)?;
                                    break;
                                } else {
                                    // Guaranteed to have the last value
                                    begin = Bound::Excluded(keys.last().unwrap().clone());
                                    trx.lock_keys(keys).await.map_err(into_error)?;
                                    continue;
                                }
                            }
                        } else {
                            trx.delete(key).await.map_err(into_error)?;
                        }
                    }
                    Operation::Log { set } => {
                        let key = LogKey {
                            account_id,
                            collection,
                            change_id,
                        }.serialize(WITH_SUBSPACE);
                        let key_vec = self.new_key_serializer(key.len(), false)
                            .write(key.as_slice())
                            .finalize();

                        trx.put(key_vec, set.resolve(&result)?.as_ref()).await.map_err(into_error)?;
                    }
                    Operation::AssertValue {
                        class,
                        assert_value,
                    } => {
                        let key_vec = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            WITH_SUBSPACE,
                            (&result).into(),
                        );
                        let key = self.new_key_serializer(key_vec.len(), false)
                            .write(key_vec.as_slice())
                            .finalize();

                        let matches = match self.read_chunked_value(&key, &mut trx).await {
                            Ok(ChunkedValue::Single(bytes)) => assert_value.matches(bytes.as_slice()),
                            Ok(ChunkedValue::Chunked { bytes, .. }) => {
                                assert_value.matches(bytes.as_ref())
                            }
                            Ok(ChunkedValue::None) => {
                                assert_value.is_none()
                            }
                            Err(_) => false,
                        };

                        if !matches {
                            trx.rollback().await.map_err(into_error)?;
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                    }
                }
            }

            if self.commit(trx, Some(&mut backoff)).await? {
                return Ok(result)
            } else {
                continue;
            }
        }
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        //let mut delete_keys = Vec::new();

        for subspace in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            let from_key = [subspace, 0u8];
            let to_key = [subspace, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX];

            // Since we are deleting all of them anyways. No point moving the start bound
            let begin = Bound::Included(TikvKey::from(self.new_key_serializer(from_key.len(), false)
                .write(from_key.as_slice())
                .finalize()));
            let end = Bound::Included(TikvKey::from(self.new_key_serializer(to_key.len(), false)
                .write(to_key.as_slice())
                .finalize()));
            let range = BoundRange::new(begin, end);

            let mut backoff = self.raw_backoff.clone();

            // Might possibly cause infinite loop
            // TODO: Check
            'outer: loop {
                let mut trx = self.write_trx_no_backoff().await?;
                let mut keys_iter = trx.scan_keys(range.clone(), MAX_SCAN_KEYS_SIZE)
                    .await
                    .map_err(into_error)?
                    .peekable();

                let mut count = 0;
                let mut last_key = TikvKey::default();
                while let Some(key) = keys_iter.next() {
                    count += 1;
                    if let Some(value) = trx.get_for_update(key.clone()).await.map_err(into_error)? {
                        if deserialize_i64_le((&key).into(), value.as_slice())? == 0 {
                            trx.delete(key.clone()).await.map_err(into_error)?;
                        }
                    }
                    if keys_iter.peek().is_none() {
                        last_key = key;
                    }
                }

                if self.commit(trx, Some(&mut backoff)).await? {
                } else {
                    continue;
                }

                if count < MAX_SCAN_KEYS_SIZE {
                    break 'outer;
                }

                break;
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let from_vec = from.serialize(WITH_SUBSPACE);
        let to_vec = to.serialize(WITH_SUBSPACE);
        let mut trx = self.write_trx_with_backoff().await?;

        let mut begin = Bound::Included(TikvKey::from(self.new_key_serializer(from_vec.len(), false)
            .write(from_vec.as_slice())
            .finalize()));

        'outer: loop {
            let end = Bound::Included(TikvKey::from(self.new_key_serializer(to_vec.len(), false)
                .write(from_vec.as_slice())
                .finalize()));

            let range = BoundRange::new(begin, end);
            let mut keys_iter = trx.scan_keys(range, MAX_SCAN_KEYS_SIZE)
                .await
                .map_err(into_error)?
                .peekable();

            let mut count = 0;
            while let Some(key) = keys_iter.next() {
                count += 1;
                if keys_iter.peek().is_none() {
                    if count < MAX_SCAN_KEYS_SIZE {
                        trx.delete(key).await.map_err(into_error)?;
                        break 'outer;
                    } else {
                        begin = Bound::Excluded(key.clone());
                        trx.delete(key).await.map_err(into_error)?;
                        continue 'outer;
                    }
                } else {
                    trx.delete(key).await.map_err(into_error)?;
                }
            }

            break;
        }

        trx.commit().await.map_err(into_error)?;
        Ok(())
    }

    // async fn atomic_subtract(&self, key: impl Into<TikvKey> + Clone, by: i64) -> trc::Result<()> {
    //     let mut backoff = self.raw_backoff.clone();
    //
    //     loop {
    //         let key = key.clone().into();
    //         let mut trx = self.write_trx_no_backoff().await?;
    //         if let Some(previous) = trx.get_for_update(key.clone()).await.map_err(into_error)? {
    //             let subtrahend = deserialize_i64_le((&key).into(), &previous)?;
    //             let difference = subtrahend - by;
    //
    //             if difference == 0 {
    //                 trx.delete(key).await.map_err(into_error)?;
    //             } else {
    //                 trx.put(key, difference.to_le_bytes().as_slice()).await.map_err(into_error)?;
    //             }
    //         } else {
    //             trx.put(key, by.to_le_bytes().as_slice()).await.map_err(into_error)?;
    //         }
    //
    //         if self.commit(trx, Some(&mut backoff)).await? {
    //             return Ok(());
    //         } else {
    //             continue;
    //         }
    //     }
    // }
    //
    // async fn atomic_add(&self, key: impl Into<TikvKey> + Clone, by: i64) -> trc::Result<()> {
    //     let mut backoff = self.raw_backoff.clone();
    //
    //     loop {
    //         let key = key.clone().into();
    //         let mut trx = self.write_trx_no_backoff().await?;
    //         if let Some(previous) = trx.get_for_update(key.clone()).await.map_err(into_error)? {
    //             let addend = deserialize_i64_le((&key).into(), &previous)?;
    //             let sum = addend + by;
    //
    //             trx.put(key, sum.to_le_bytes().as_slice()).await.map_err(into_error)?;
    //         } else {
    //             trx.put(key, by.to_le_bytes().as_slice()).await.map_err(into_error)?;
    //         }
    //
    //         if self.commit(trx, Some(&mut backoff)).await? {
    //             return Ok(());
    //         } else {
    //             continue;
    //         }
    //     }
    // }

    async fn commit(&self, mut trx: Transaction, ext_backoff: Option<&mut Backoff>) -> trc::Result<bool> {
        if let Err(e) = trx.commit().await {
            if let Some(backoff) = ext_backoff {
                let Some(backoff_duration) = backoff.next_delay_duration() else {
                    return Err(into_error(e));
                };
                tokio::time::sleep(backoff_duration).await;
                Ok(false)
            } else {
                Err(into_error(e))
            }
        } else {
            Ok(true)
        }
    }

    async fn write_trx_no_backoff(&self) -> trc::Result<Transaction> {
        // TODO: Put inside struct
        let write_trx_options = TransactionOptions::new_pessimistic()
            .drop_check(CheckLevel::Warn)
            .use_async_commit()
            .retry_options(RetryOptions::none());

        self.trx_client
            .begin_with_options(write_trx_options)
            .await
            .map_err(into_error)
    }

    async fn write_trx_with_backoff(&self) -> trc::Result<Transaction> {
        self.trx_client
            .begin_with_options(self.write_trx_options.clone())
            .await
            .map_err(into_error)
    }
}

async fn get_and_add(trx: &mut Transaction, key: impl Into<TikvKey>, by: i64) -> trc::Result<i64> {
    let key = key.into();
    if let Some(previous) = trx.get_for_update(key.clone()).await.map_err(into_error)? {
        let addend = deserialize_i64_le((&key).into(), &previous)?;
        let sum = addend + by;
        trx.put(key, sum.to_le_bytes().as_slice()).await.map_err(into_error)?;
        Ok(sum)
    } else {
        trx.put(key, by.to_le_bytes().as_slice()).await.map_err(into_error)?;
        Ok(by)
    }
}