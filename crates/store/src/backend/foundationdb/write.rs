/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    time::{Duration, Instant},
};

use foundationdb::{
    options::{self, MutationType, StreamingMode},
    FdbError, KeySelector, RangeOption, Transaction,
};
use futures::TryStreamExt;
use rand::Rng;
use roaring::RoaringBitmap;

use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId, ValueOp,
        MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN, WITH_SUBSPACE,
};

use super::{
    into_error,
    read::{read_chunked_value, ChunkedValue},
    FdbStore, ReadVersion, MAX_VALUE_SIZE,
};

impl FdbStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = u64::MAX;
            let mut result = AssignedIds::default();

            let trx = self.db.create_trx().map_err(into_error)?;

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
                                                    trx.cancel();
                                                    return Err(trc::StoreEvent::FoundationdbError
                                                        .ctx(
                                                            trc::Key::Reason,
                                                            "Value is too large",
                                                        ));
                                                }
                                            }
                                        }
                                        trx.set(&key, chunk);
                                    }
                                } else {
                                    trx.set(&key, value.as_ref());
                                }
                            }
                            ValueOp::AtomicAdd(by) => {
                                trx.atomic_op(&key, &by.to_le_bytes()[..], MutationType::Add);
                            }
                            ValueOp::AddAndGet(by) => {
                                let num = if let Some(bytes) =
                                    trx.get(&key, false).await.map_err(into_error)?
                                {
                                    deserialize_i64_le(&key, &bytes)? + *by
                                } else {
                                    *by
                                };
                                trx.set(&key, &num.to_le_bytes()[..]);
                                result.push_counter_id(num);
                            }
                            ValueOp::Clear => {
                                if do_chunk {
                                    trx.clear_range(
                                        &key,
                                        &KeySerializer::new(key.len() + 1)
                                            .write(key.as_slice())
                                            .write(u8::MAX)
                                            .finalize(),
                                    );
                                } else {
                                    trx.clear(&key);
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
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
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
                            let mut values = trx.get_ranges_keyvalues(
                                RangeOption {
                                    begin: KeySelector::first_greater_or_equal(begin),
                                    end: KeySelector::first_greater_or_equal(end),
                                    mode: StreamingMode::WantAll,
                                    reverse: false,
                                    ..RangeOption::default()
                                },
                                true,
                            );
                            let mut found_ids = RoaringBitmap::new();
                            while let Some(value) = values.try_next().await.map_err(into_error)? {
                                let key = value.key();
                                if key.len() == key_len {
                                    found_ids.insert(key.deserialize_be_u32(key_len - U32_LEN)?);
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
                                trx.add_conflict_range(
                                    &key,
                                    &class.serialize(
                                        account_id,
                                        collection,
                                        document_id + 1,
                                        WITH_SUBSPACE,
                                        (&result).into(),
                                    ),
                                    options::ConflictRangeType::Read,
                                )
                                .map_err(into_error)?;
                            }

                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Log { set } => {
                        let key = LogKey {
                            account_id,
                            collection,
                            change_id,
                        }
                        .serialize(WITH_SUBSPACE);
                        trx.set(&key, set.resolve(&result)?.as_ref());
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

                        let matches = match read_chunked_value(&key, &trx, false).await {
                            Ok(ChunkedValue::Single(bytes)) => assert_value.matches(bytes.as_ref()),
                            Ok(ChunkedValue::Chunked { bytes, .. }) => {
                                assert_value.matches(bytes.as_ref())
                            }
                            Ok(ChunkedValue::None) => assert_value.is_none(),
                            Err(_) => false,
                        };

                        if !matches {
                            trx.cancel();
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                    }
                }
            }

            if self
                .commit(
                    trx,
                    retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME,
                )
                .await?
            {
                return Ok(result);
            } else {
                let backoff = rand::thread_rng().gen_range(50..=300);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                retry_count += 1;
            }
        }
    }

    pub(crate) async fn commit(&self, trx: Transaction, will_retry: bool) -> trc::Result<bool> {
        match trx.commit().await {
            Ok(result) => {
                let commit_version = result.committed_version().map_err(into_error)?;
                let mut version = self.version.lock();
                if commit_version > version.version {
                    *version = ReadVersion::new(commit_version);
                }
                Ok(true)
            }
            Err(err) => {
                if will_retry {
                    err.on_error().await.map_err(into_error)?;
                    Ok(false)
                } else {
                    Err(into_error(FdbError::from(err)))
                }
            }
        }
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        // Obtain all zero counters
        let mut delete_keys = Vec::new();
        for subspace in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            let trx = self.db.create_trx().map_err(into_error)?;
            let from_key = [subspace, 0u8];
            let to_key = [subspace, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX];

            let mut values = trx.get_ranges_keyvalues(
                RangeOption {
                    begin: KeySelector::first_greater_or_equal(&from_key[..]),
                    end: KeySelector::first_greater_or_equal(&to_key[..]),
                    mode: options::StreamingMode::WantAll,
                    reverse: false,
                    ..Default::default()
                },
                true,
            );

            while let Some(value) = values.try_next().await.map_err(into_error)? {
                if value.value().iter().all(|byte| *byte == 0) {
                    delete_keys.push(value.key().to_vec());
                }
            }
        }

        if delete_keys.is_empty() {
            return Ok(());
        }

        // Delete keys
        let integer = 0i64.to_le_bytes();
        for chunk in delete_keys.chunks(1024) {
            let mut retry_count = 0;
            loop {
                let trx = self.db.create_trx().map_err(into_error)?;
                for key in chunk {
                    trx.atomic_op(key, &integer, MutationType::CompareAndClear);
                }

                if self.commit(trx, retry_count < MAX_COMMIT_ATTEMPTS).await? {
                    break;
                } else {
                    retry_count += 1;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let from = from.serialize(WITH_SUBSPACE);
        let to = to.serialize(WITH_SUBSPACE);

        let trx = self.db.create_trx().map_err(into_error)?;
        trx.clear_range(&from, &to);
        self.commit(trx, false).await.map(|_| ())
    }
}
