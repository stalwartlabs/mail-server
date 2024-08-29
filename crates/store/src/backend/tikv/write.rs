/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, iter, time::{Duration, Instant}};
use std::collections::Bound;
use std::ops::DerefMut;
use tikv_client::{Backoff, BoundRange, CheckLevel, Key as TikvKey, RetryOptions, TimestampExt, Transaction, Value};
use rand::Rng;
use roaring::RoaringBitmap;
use tikv_client::TransactionOptions;
use tikv_client::proto::kvrpcpb::{Assertion, Mutation, Op};
use tikv_client::transaction::ResolveLocksOptions;
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
use super::write::chunking::{put_chunked_value, delete_chunked_value};
use super::read::chunking::get_chunked_value;
use super::{into_error, TikvStore, MAX_VALUE_SIZE, MAX_SCAN_KEYS_SIZE};

impl TikvStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let mut backoff = self.backoff.clone();

        loop {
            let mut trx = self.write_trx_no_backoff().await?;

            match self.write_trx(&mut trx, &batch).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    let _ = trx.rollback().await;
                    let version = self.version.lock().clone();
                    self.trx_client.gc(version).await.map_err(into_error)?;
                    //self.trx_client.cleanup_locks(BoundRange::range_from(TikvKey::from(vec![])), &ts, ResolveLocksOptions::default()).await.map_err(into_error)?;
                    let Some(backoff_duration) = backoff.next_delay_duration() else {
                        return Err(err);
                    };
                    println!("backoff for {} secs with {} attempts", backoff_duration.as_secs_f32(), backoff.current_attempts());
                    tokio::time::sleep(backoff_duration).await;
                    continue;
                }
            }
        }


    }

    async fn write_trx(&self, trx: &mut Transaction, batch: &Batch) -> trc::Result<AssignedIds> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = u64::MAX;
        let mut result = AssignedIds::default();

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
                    let key = class.serialize(
                        account_id,
                        collection,
                        document_id,
                        WITH_SUBSPACE,
                        (&result).into(),
                    );
                    println!("writing key: {:?}", key);
                    let do_chunk = !class.is_counter(collection);

                    match op {
                        ValueOp::Set(value) => {
                            let value = value.resolve(&result)?;
                            if do_chunk {
                                put_chunked_value(&key, &value, trx, false).await?;
                            } else {
                                trx.put(key, value.as_ref()).await.map_err(into_error)?;
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            get_and_add(trx, key, *by).await?;
                        }
                        ValueOp::AddAndGet(by) => {
                            let num = get_and_add(trx, key, *by).await?;
                            result.push_counter_id(num);
                        }
                        ValueOp::Clear => {
                            if do_chunk {
                                delete_chunked_value(&key, trx, false).await?;
                            } else {
                                trx.delete(key).await.map_err(into_error)?;
                            }
                        }
                    }
                }
                Operation::Index {  field, key, set } => {
                    let key = IndexKey {
                        account_id,
                        collection,
                        document_id,
                        field: *field,
                        key,
                    }.serialize(0);
                    println!("writing index key: {:?}", key);

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
                        let mut begin = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::DocumentIds,
                            document_id: 0,
                        }.serialize(WITH_SUBSPACE);
                        let mut end = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::DocumentIds,
                            document_id: u32::MAX,
                        }.serialize(WITH_SUBSPACE);
                        end.push(u8::MIN); // Null byte to make the end inclusive


                        let key_len = begin.len();

                        let mut found_ids = RoaringBitmap::new();

                        'outer: loop {
                            println!("scanning keys {:?} and {:?}", begin, end);
                            let mut keys = trx.scan_keys((begin, end.clone()), MAX_SCAN_KEYS_SIZE)
                                .await
                                .map_err(into_error)?
                                .peekable();

                            let mut count = 0;
                            while let Some(key) = keys.next() {
                                count += 1;
                                let key_slice: &[u8] = key.as_ref().into();
                                println!("found key {:?}", key_slice);
                                if key_slice.len() == key_len {
                                    found_ids.insert(key_slice.deserialize_be_u32(key_len - U32_LEN)?);
                                } else {
                                    break 'outer;
                                }

                                if keys.peek().is_none() {
                                    if count < MAX_SCAN_KEYS_SIZE {
                                        break 'outer;
                                    } else {
                                        begin = key.into();
                                        begin.push(u8::MIN); // Null byte to make the beginning exclusive
                                        continue 'outer;
                                    }
                                }
                            }
                            // Empty
                            break;
                        }

                        document_id = found_ids.random_available_id();
                        println!("using document id: {} from found IDs: {:?}", document_id, found_ids);
                        result.push_document_id(document_id);
                    }

                    let key = class.serialize(
                        account_id,
                        collection,
                        document_id,
                        WITH_SUBSPACE,
                        (&result).into(),
                    );

                    if *set {
                        trx.lock_keys([key.clone()]).await.map_err(into_error)?;
                        trx.put(key, &[]).await.map_err(into_error)?;
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

                    trx.put(key, set.resolve(&result)?.as_ref()).await.map_err(into_error)?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key = class.serialize(
                        account_id,
                        collection,
                        document_id,
                        WITH_SUBSPACE,
                        (&result).into(),
                    );

                    let matches = match get_chunked_value(&key, trx).await {
                        Ok(Some(bytes)) => assert_value.matches(bytes.as_slice()),
                        Ok(None) => {
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

        if let Some(ts) = trx.commit().await.map_err(into_error)? {
            let mut previous = self.version.lock();
            *previous = ts;
        }
        if ! result.counter_ids.is_empty() || ! result.document_ids.is_empty() {
            println!("success with counters: [{:?}] and doc ids: [{:?}]", result.counter_ids, result.document_ids);
        }
        Ok(result)
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        //let mut delete_keys = Vec::new();

        for subspace in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            let from_key = [subspace, 0u8];
            let to_key = [subspace, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX];

            // Since we are deleting all of them anyways. No point moving the start bound
            let mut begin = Bound::Included(TikvKey::from(from_key.to_vec()));

            let mut backoff = self.backoff.clone();

            'outer: loop {
                let end = Bound::Included(TikvKey::from(to_key.to_vec()));
                let range = BoundRange::new(begin, end);

                let mut trx = self.write_trx_no_backoff().await?;
                let mut keys_iter = trx.scan_keys(range.clone(), MAX_SCAN_KEYS_SIZE)
                    .await
                    .map_err(into_error)?;

                let mut count = 0;
                let mut last_key = TikvKey::default();
                while let Some(key) = keys_iter.next() {
                    count += 1;
                    if let Some(value) = trx.get_for_update(key.clone()).await.map_err(into_error)? {
                        if deserialize_i64_le((&key).into(), value.as_slice())? == 0 {
                            trx.delete(key.clone()).await.map_err(into_error)?;
                        }
                    }
                    last_key = key;
                }

                if self.commit(trx, Some(&mut backoff)).await? {} else {
                    begin = Bound::Excluded(last_key);
                    continue;
                }

                if count < MAX_SCAN_KEYS_SIZE {
                    break 'outer;
                } else {
                    begin = Bound::Excluded(last_key);
                    continue;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let begin_range = Bound::Included(TikvKey::from(from.serialize(WITH_SUBSPACE)));
        let end_range = Bound::Included(TikvKey::from(to.serialize(WITH_SUBSPACE)));
        let range = BoundRange::new(begin_range, end_range);

        let mut trx = self.write_trx_with_backoff().await?;

        loop {
            let keys = trx
                .scan_keys(range.clone(), MAX_SCAN_KEYS_SIZE)
                .await
                .map_err(into_error)?;

            let mut count = 0;
            for key in keys {
                count += 1;
                trx.delete(key).await.map_err(into_error)?;
            }

            if count != MAX_SCAN_KEYS_SIZE {
                break;
            }
        }

        trx.commit().await.map_err(into_error)?;
        Ok(())
    }

    pub(crate) async fn commit(&self, mut trx: Transaction, ext_backoff: Option<&mut Backoff>) -> trc::Result<bool> {
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

    pub(super) async fn write_trx_no_backoff(&self) -> trc::Result<Transaction> {
        let write_trx_options = TransactionOptions::new_optimistic()
            .drop_check(CheckLevel::Warn)
            .use_async_commit()
            .retry_options(RetryOptions::none());

        self.trx_client
            .begin_with_options(write_trx_options)
            .await
            .map_err(into_error)
    }

    pub(super) async fn write_trx_with_backoff(&self) -> trc::Result<Transaction> {
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

pub(super) mod chunking {
    use super::*;

    pub(in super::super) async fn delete_chunked_value(
        key: &[u8],
        trx: &mut Transaction,
        commit: bool,
    ) -> trc::Result<()> {
        let begin_key = key.to_vec();

        let end_key = KeySerializer::new(key.len() + 1)
            .write(key)
            .write(u8::MAX)
            .finalize();

        let keys = trx.scan_keys((begin_key, end_key), 256)
            .await
            .map_err(into_error)?;

        for chunk_key in keys {
            trx.delete(chunk_key).await.map_err(into_error)?;
        }

        if commit {
            trx.commit().await.map_err(into_error)?;
        }

        Ok(())
    }

    pub(in super::super) async fn put_chunked_value(
        key: &[u8],
        value: &[u8],
        trx: &mut Transaction,
        commit: bool
    ) -> trc::Result<()> {
        let mut chunk_iter = value.chunks(MAX_VALUE_SIZE);

        if chunk_iter.len() > 1 + 256 {
            // Expected to be thrown back so might as well roll it back.
            trx.rollback().await.map_err(into_error)?;
            return Err(trc::StoreEvent::TikvError
                .ctx(
                    trc::Key::Reason,
                    "Value is too large",
                ));
        }

        let first_chunk = chunk_iter.next().unwrap_or_else(|| &[]);
        trx.put(key.to_vec(), first_chunk).await.map_err(into_error)?;

        for (chunk_pos, value_chunk) in chunk_iter.enumerate() {
            let chunk_key = KeySerializer::new(key.len() + 1)
                .write(key)
                .write(chunk_pos as u8)
                .finalize();
            trx.put(chunk_key, value_chunk).await.map_err(into_error)?;
        }

        if commit {
            trx.commit().await.map_err(into_error)?;
        }

        Ok(())
    }
}