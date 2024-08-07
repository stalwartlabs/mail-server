/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    time::{Duration, Instant},
};
use std::collections::Bound;
use std::num::Wrapping;
use tikv_client::{Backoff, BoundRange, Key as TikvKey, TimestampExt, Transaction, Value};
use rand::Rng;
use roaring::RoaringBitmap;
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
use super::{into_error, read::{read_chunked_value_transaction, ChunkedValue}, TikvStore, ReadVersion, MAX_VALUE_SIZE, MAX_KEYS, ReadTransaction};

impl TikvStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = u64::MAX;
        let mut result = AssignedIds::default();

        // TODO: IDFK man this feels wrong. What if an error happened without calling this?
        let mut atomic_subtracts_rollback = vec![];
        let mut batch_mutate = vec![];

        let mut trx = self.trx_client.begin_optimistic().await.map_err(into_error)?;

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
                    //println!("{:?}", class);
                    let mut key = class.serialize(
                        account_id,
                        collection,
                        document_id,
                        WITH_SUBSPACE,
                        (&result).into(),
                    );
                    let do_chunk = !class.is_counter(collection);

                    match op {
                        ValueOp::Set(value) => {
                            let value = value.resolve(&result)?;
                            if !value.is_empty() && do_chunk {
                                for (pos, chunk) in value.chunks(MAX_VALUE_SIZE).enumerate() {
                                    match pos.cmp(&1) {
                                        Ordering::Less => {}
                                        Ordering::Equal => {
                                            key.push(0);
                                        }
                                        Ordering::Greater => {
                                            if pos < u8::MAX as usize {
                                                *key.last_mut().unwrap() += 1;
                                            } else {
                                                //trx.rollback().await.map_err(into_error)?;
                                                return Err(trc::StoreEvent::TikvError
                                                    .ctx(
                                                        trc::Key::Reason,
                                                        "Value is too large",
                                                    ));
                                            }
                                        }
                                    }
                                    // TODO: Costly clone
                                    let mutation = Mutation {
                                        op: Op::Put.into(),
                                        key: key.to_vec(),
                                        value: chunk.to_vec(),
                                        assertion: Assertion::None.into(),
                                    };
                                    batch_mutate.push(mutation);
                                }
                            } else {
                                // TODO: Costly clone
                                let mutation = Mutation {
                                    op: Op::Put.into(),
                                    key: key.to_vec(),
                                    value: value.to_vec(),
                                    assertion: Assertion::None.into(),
                                };
                                batch_mutate.push(mutation);
                                //trx.put(key.clone(), value.as_ref()).await.map_err(into_error)?;
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            // Duplicating AddAndGet because TiKV has no atomic add
                            // TODO: Costly clone
                            let atomic_add_key = key.clone();
                            self.atomic_add(atomic_add_key.clone(), *by).await?;
                            atomic_subtracts_rollback.push(self.atomic_subtract(atomic_add_key.clone(), *by));
                        }
                        ValueOp::AddAndGet(by) => {
                            // TODO: Costly clone
                            let num = if let Some(bytes) =
                                trx.get_for_update(key.clone()).await.map_err(into_error)?
                            {
                                deserialize_i64_le(&key, &bytes)? + *by
                            } else {
                                *by
                            };
                            // TODO: Costly clone
                            //trx.put(key.clone(), &num.to_le_bytes()[..]).await.map_err(into_error)?;
                            let mutation = Mutation {
                                op: Op::Put.into(),
                                key: key.to_vec(),
                                value: num.to_le_bytes().to_vec(),
                                assertion: Assertion::None.into(),
                            };
                            batch_mutate.push(mutation);
                            result.push_counter_id(num);
                        }
                        ValueOp::Clear => {
                            if do_chunk {
                                let range = BoundRange::new(
                                    // TODO: Costly clone jesus christ
                                    Bound::Included(key.clone().into()),
                                    Bound::Included(KeySerializer::new(key.len() + 1)
                                        .write(key.as_slice())
                                        .write(u8::MAX)
                                        .finalize().into()),
                                );
                                // TODO: Repeat after reaching max keys
                                let mut keys = trx.scan_keys(range, u32::MAX).await.map_err(into_error)?;


                                while let Some(key) = keys.next() {
                                    //trx.delete(key).await.map_err(into_error)?;
                                    let mutation = Mutation {
                                        op: Op::Del.into(),
                                        key: key.into(),
                                        value: Default::default(),
                                        assertion: Assertion::None.into(),
                                    };
                                    batch_mutate.push(mutation);
                                }
                            } else {
                                // TODO: Costly clone
                                //trx.delete(key).await.map_err(into_error)?;
                                let mutation = Mutation {
                                    op: Op::Del.into(),
                                    key: key.into(),
                                    value: Default::default(),
                                    assertion: Assertion::None.into(),
                                };
                                batch_mutate.push(mutation);
                            }
                        }
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
                        .serialize(WITH_SUBSPACE);

                    if *set {
                        //trx.put(key, &[]).await.map_err(into_error)?;
                        let mutation = Mutation {
                            op: Op::Put.into(),
                            key,
                            value: vec![],
                            assertion: Assertion::None.into(),
                        };
                        batch_mutate.push(mutation);
                    } else {
                        //trx.delete(key).await.map_err(into_error)?;
                        let mutation = Mutation {
                            op: Op::Del.into(),
                            key,
                            value: Default::default(),
                            assertion: Assertion::None.into(),
                        };
                        batch_mutate.push(mutation);
                    }
                }
                Operation::Bitmap { class, set } => {
                    // Find the next available document id
                    let assign_id = *set
                        && matches!(class, BitmapClass::DocumentIds)
                        && document_id == u32::MAX;
                    if assign_id {
                        let begin = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::DocumentIds,
                            document_id: 0,
                        }
                            .serialize(WITH_SUBSPACE);
                        let end = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::DocumentIds,
                            document_id: u32::MAX,
                        }
                            .serialize(WITH_SUBSPACE);
                        let key_len = begin.len();
                        // TODO: Do repeat logic
                        let mut values = trx.scan_keys((begin, end), MAX_KEYS).await.map_err(into_error)?;
                        let mut found_ids = RoaringBitmap::new();
                        while let Some(key) = values.next() {
                            if key.len() == key_len {
                                let key_vec: Vec<u8> = key.into();
                                found_ids.insert(key_vec.as_slice().deserialize_be_u32(key_len - U32_LEN)?);
                            } else {
                                break;
                            }
                        }
                        document_id = found_ids.random_available_id();
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
                        if assign_id {
                            let keys_iter = trx.scan_keys((key.clone(), class.serialize(
                                account_id,
                                collection,
                                document_id + 1,
                                WITH_SUBSPACE,
                                (&result).into(),
                            )), u32::MAX).await.map_err(into_error)?;
                            trx.lock_keys(keys_iter).await.map_err(into_error)?;
                        }
                        let mutation = Mutation {
                            op: Op::Put.into(),
                            key,
                            value: vec![],
                            assertion: Assertion::None.into(),
                        };
                        batch_mutate.push(mutation);
                        //trx.put(key, &[]).await.map_err(into_error)?;
                    } else {
                        let mutation = Mutation {
                            op: Op::Del.into(),
                            key,
                            value: Default::default(),
                            assertion: Assertion::None.into(),
                        };
                        batch_mutate.push(mutation);
                        //trx.delete(key).await.map_err(into_error)?;
                    }
                }
                Operation::Log { set } => {
                    let key = LogKey {
                        account_id,
                        collection,
                        change_id,
                    }
                        .serialize(WITH_SUBSPACE);
                    let mutation = Mutation {
                        op: Op::Put.into(),
                        key,
                        value: set.resolve(&result)?.into_owned(),
                        assertion: Assertion::None.into(),
                    };
                    batch_mutate.push(mutation);
                    //trx.put(key, set.resolve(&result)?.as_ref()).await.map_err(into_error)?;
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

                    let matches = match read_chunked_value_transaction(&key, &mut trx).await {
                        Ok(ChunkedValue::Single(bytes)) => assert_value.matches(bytes.as_ref()),
                        Ok(ChunkedValue::Chunked { bytes, .. }) => {
                            assert_value.matches(bytes.as_ref())
                        }
                        Ok(ChunkedValue::None) => assert_value.is_none(),
                        Err(_) => false,
                    };

                    if !matches {
                        trx.rollback().await.map_err(into_error)?;
                        return Err(trc::StoreEvent::AssertValueFailed.into());
                    }
                }
            }
        }

        batch_mutate.reverse();
        trx.batch_mutate(batch_mutate).await.map_err(into_error)?;

        // Already handles retry logic through retry and backoff
        if let Err(e) = trx.commit().await {
            // the committer should have done the repeats and still failed
            trx.rollback().await.map_err(into_error)?;
            for fut in atomic_subtracts_rollback {
                fut.await?;
            }
            return Err(into_error(e));
        }
        // Success, we don't care about the timestamp for now, but it's in to do
        return Ok(result);
    }

    pub(crate) async fn commit(&self, mut trx: Transaction, will_retry: bool) -> trc::Result<bool> {
        match trx.commit().await {
            Ok(result) => {
                let Some(commit_timestamp) = result else {
                    // There was nothing to commit?
                    // .ok_or_else(|| trc::StoreEvent::TikvError
                    //                     .reason("couldn't get commit timestamp".to_string()))
                    return Ok(true);
                };
                let mut version = self.version.lock();
                // I hate this
                if commit_timestamp.version() > version.version.version() {
                    *version = ReadVersion::new(commit_timestamp);
                }
                Ok(true)
            }
            Err(err) => {
                trx.rollback().await.map_err(into_error)?;
                if will_retry {
                    Ok(false)
                } else {
                    Err(into_error(err))
                }
            }
        }
    }
    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        // Obtain all zero counters
        for subspace in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            let from_key = vec![subspace, 0u8];
            let to_key = vec![subspace, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX];

            const CHUNK_LIMIT: u32 = 1024;

            loop {
                let mut key_count = 0;

                let mut trx = self.trx_client
                    .begin_with_options(self.write_trx_options.clone())
                    .await
                    .map_err(into_error)?;

                let mut keys = trx.scan_keys((from_key.clone(), to_key.clone()), CHUNK_LIMIT).await.map_err(into_error)?;
                for key in keys {
                    key_count += 1;
                    trx.delete(key).await.map_err(into_error)?;
                }

                self.commit(trx, false).await?;
                if key_count != CHUNK_LIMIT {
                    break;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let from = from.serialize(WITH_SUBSPACE);
        let to = to.serialize(WITH_SUBSPACE);

        let mut trx = self.trx_client
            .begin_with_options(self.write_trx_options.clone())
            .await
            .map_err(into_error)?;

        // Have to manually get the range first;
        // TODO: Chunked key scans and locks
        let mut keys = trx.scan_keys((from, to), MAX_KEYS).await.map_err(into_error)?;
        let key_vec: Vec<tikv_client::Key> = keys.collect();
        // TODO: Expensive clone :(
        trx.lock_keys(key_vec.clone()).await.map_err(into_error)?;
        for key in key_vec {
            trx.delete(key).await.map_err(into_error)?;
        }

        self.commit(trx, false).await.map(|_| ())
    }

    pub(crate) async fn atomic_compare_and_clear(&self, key: Vec<u8>, by: &[u8]) -> trc::Result<bool> {
        // Raw clients do not have retry logic
        // TODO: Unpyramid of Doom
        let mut backoff = self.raw_backoff.clone();
        loop {
            let value = match self.raw_client.get(key.clone()).await {
                Ok(value_opt) => {
                    if let Some(value) = value_opt {
                        value
                    } else {
                        // Nothing to compare as there is nothing to clear.
                        return Ok(false)
                    }
                }
                Err(e) => {
                    if let Some(wait) = backoff.next_delay_duration() {
                        tokio::time::sleep(wait).await;
                        continue;
                    } else {
                        return Err(into_error(e));
                    }
                }
            };

            return if by == value.as_slice() {
                match self.raw_client.delete(key.clone()).await {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        if let Some(wait) = backoff.next_delay_duration() {
                            tokio::time::sleep(wait).await;
                            continue;
                        } else {
                            return Err(into_error(e));
                        }
                    }
                }
            } else {
                Ok(false)
            }
        }
    }

    pub(crate) async fn atomic_add(&self, key: Vec<u8>, by: i64) -> trc::Result<Option<i64>> {
        // Raw clients do not have retry logic
        // TODO: Unpyramid of Doom
        let mut backoff = self.raw_backoff.clone();
        loop {
            let maybe_set_value = match self.raw_client.get(key.clone()).await {
                Ok(value_opt) => value_opt,
                Err(e) => {
                    if let Some(wait) = backoff.next_delay_duration() {
                        tokio::time::sleep(wait).await;
                        continue;
                    } else {
                        return Err(into_error(e));
                    }
                }
            };

            let sum = match &maybe_set_value {
                None => Wrapping(by),
                Some(original) => Wrapping(deserialize_i64_le(key.as_slice(), original.as_slice())?) + Wrapping(by)
            };
            let (_previous, swapped) = match self.raw_client
                .compare_and_swap(key.to_vec(), maybe_set_value, sum.0.to_le_bytes().to_vec())
                .await {
                Ok(result) => result,
                Err(e) => {
                    if let Some(wait) = backoff.next_delay_duration() {
                        tokio::time::sleep(wait).await;
                        continue;
                    } else {
                        return Err(into_error(e));
                    }
                }
            };

            return if swapped {
                Ok(Some(sum.0))
            } else {
                // TODO: Possible logic error but my eyes hurt already
                Ok(None)
            }
        }
    }

    pub(crate) async fn atomic_subtract(&self, key: Vec<u8>, minuend: i64) -> trc::Result<Option<i64>> {
        // Raw clients do not have retry logic
        // TODO: Unpyramid of Doom
        let mut backoff = self.raw_backoff.clone();
        loop {
            let value = match self.raw_client.get(key.clone()).await {
                Ok(value_opt) => value_opt.ok_or_else(|| {
                    trc::StoreEvent::TikvError
                        .reason("cannot do an atomic subtract on unset key-value")
                })?,
                Err(e) => {
                    if let Some(wait) = backoff.next_delay_duration() {
                        tokio::time::sleep(wait).await;
                        continue;
                    } else {
                        return Err(into_error(e));
                    }
                }
            };

            let subtrahend = Wrapping(deserialize_i64_le(key.as_slice(), value.as_slice())?);

            let difference = subtrahend - Wrapping(minuend);

            let (_previous, swapped) = match self.raw_client
                .compare_and_swap(key.to_vec(), Some(subtrahend.0.to_le_bytes().to_vec()), difference.0.to_le_bytes().to_vec())
                .await {
                Ok(result) => result,
                Err(e) => {
                    if let Some(wait) = backoff.next_delay_duration() {
                        tokio::time::sleep(wait).await;
                        continue;
                    } else {
                        return Err(into_error(e));
                    }
                }
            };

            return if swapped {
                Ok(Some(difference.0))
            } else {
                if let Some(wait) = backoff.next_delay_duration() {
                    tokio::time::sleep(wait).await;
                    continue;
                } else {
                    return Err(trc::StoreEvent::TikvError
                        .reason("failed to subtract"));
                        //.ctx(key.clone().into(), minuend));
                }
            }
        }
    }
}
