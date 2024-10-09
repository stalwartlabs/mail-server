/*
 * SPDX-FileCopyrightText: 2024 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    time::Duration,
};

use etcd_client::{Compare, CompareOp, DeleteOptions, GetOptions, Txn, TxnOp};
use rand::Rng;
use roaring::RoaringBitmap;

use super::{into_error, EtcdStore, MAX_VALUE_SIZE};

use crate::{
    backend::deserialize_i64_le, write::{
        key::{DeserializeBigEndian, KeySerializer},
        AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId, ValueOp,
    }, BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN, WITH_SUBSPACE
};

impl EtcdStore {

    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let mut retry_count = 0;
        let mut client = self.client.clone();

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = u64::MAX;
            let mut result = AssignedIds::default();

            let trx = Txn::new();
            let mut trx_operations: Vec<TxnOp> = vec![];
            let mut trx_compare: Vec<Compare> = vec![];

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
                                                    return Err(trc::StoreEvent::EtcdError
                                                        .ctx(
                                                            trc::Key::Reason,
                                                            "Value is too large",
                                                        ));
                                                }
                                            }
                                        }
                                        trx_operations.push(TxnOp::put(&*key, chunk, None));
                                    }
                                } else {
                                    trx_operations.push(TxnOp::put(key, value.as_ref(), None));
                                }
                            }
                            ValueOp::AtomicAdd(by) => {
                                let res = client.get(&*key, None).await.map_err(into_error)?;
                                let initial_value = match res.kvs().first() {
                                    Some(data) => deserialize_i64_le(&key, &data.value())?,
                                    None => 0
                                };

                                // Ensure no change has been made, maybe use the revision instead ?
                                trx_compare.push(
                                    Compare::value(
                                        &*key,
                                        CompareOp::Equal,
                                        initial_value.to_le_bytes()
                                    )
                                );

                                let num = initial_value + *by;

                                trx_operations.push(
                                    TxnOp::put(&*key, &num.to_le_bytes()[..], None)
                                );
                            }
                            ValueOp::AddAndGet(by) => {
                                let res = client.get(&*key, None).await.map_err(into_error)?;
                                let initial_value = match res.kvs().first() {
                                    Some(data) => deserialize_i64_le(&*key, &data.value())?,
                                    None => 0
                                };

                                let num = initial_value + *by;

                                trx_operations.push(
                                    TxnOp::put(key, &num.to_le_bytes()[..], None)
                                );
                                result.push_counter_id(num);
                            }
                            ValueOp::Clear => {
                                if do_chunk {
                                    let end_key = KeySerializer::new(key.len() + 1)
                                        .write(key.as_slice())
                                        .write(u8::MAX)
                                        .finalize();
                                    trx_operations.push(
                                        TxnOp::delete(key, Some(DeleteOptions::new().with_range(end_key)))
                                    );
                                } else {
                                    trx_operations.push(
                                        TxnOp::delete(key, None)
                                    );
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
                            trx_operations.push(
                                TxnOp::put(key, &[], None)
                            );
                        } else {
                            trx_operations.push(
                                TxnOp::delete(key, None)
                            );
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
                            let mut values = match client.get(begin, Some(GetOptions::new().with_range(end))).await {
                                Ok(mut res) => res.take_kvs().into_iter(),
                                Err(err) => return Err(trc::StoreEvent::EtcdError
                                    .ctx(
                                        trc::Key::Reason,
                                        err.to_string(),
                                    ))
                            };
                            let mut found_ids = RoaringBitmap::new();
                            while let Some(value) = values.next() {
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
                            trx_operations.push(
                                TxnOp::put(key, &[], None)
                            );
                        } else {
                            trx_operations.push(
                                TxnOp::delete(key, None)
                            );
                        }
                    }
                    Operation::Log { set } => {
                        let key = LogKey {
                            account_id,
                            collection,
                            change_id,
                        }
                        .serialize(WITH_SUBSPACE);

                        trx_operations.push(
                            TxnOp::put(key, set.resolve(&result)?.as_ref(), None)
                        );
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

                        ;

                        let matches = match client.get(key, None).await {
                            Ok(res) => match res.kvs().first() {
                                Some(value) => assert_value.matches(value.value()),
                                None => false,
                            },
                            Err(_) => false,
                        };

                        if !matches {
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                    }
                }
            }

            if let Ok(response) = client
                .txn(trx.when(trx_compare).and_then(trx_operations))
                .await
            {
                return Ok(result);
            } else {
                let backoff = rand::thread_rng().gen_range(50..=300);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                retry_count += 1;
            }
        }
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let mut client = self.client.clone();
        for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER] {
            client.delete(vec![subspace],  Some(DeleteOptions::new().with_prefix()))
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let key_subspace: u8 = from.subspace();
        let from = from.serialize(0);
        let to = to.serialize(0);

        let mut client = self.get_prefix_client(key_subspace);

        client.delete(from,  Some(DeleteOptions::new().with_range(to)))
        .await
        .map_err(into_error)
        .map(|_| ())
    }
}
