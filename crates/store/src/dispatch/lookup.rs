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

use crate::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        now, BatchBuilder, Operation, ValueClass, ValueOp,
    },
    Deserialize, IterateParams, LookupKey, LookupStore, LookupValue, QueryResult, Store, Value,
    ValueKey, U64_LEN,
};

impl LookupStore {
    pub async fn query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> crate::Result<T> {
        let result = match self {
            LookupStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.query(query, params).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.query(query, params).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.query(query, params).await,
                _ => Err(crate::Error::InternalError(
                    "Store does not support queries".into(),
                )),
            },
            LookupStore::Memory(store) => store.query(query, params),
        };

        tracing::trace!( context = "store", event = "query", query = query, result = ?result);

        result
    }

    pub async fn key_set(&self, key: Vec<u8>, value: LookupValue<Vec<u8>>) -> crate::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let (class, op) = match value {
                    LookupValue::Value { value, expires } => (
                        ValueClass::Key { key },
                        ValueOp::Set(
                            KeySerializer::new(value.len() + U64_LEN)
                                .write(if expires > 0 {
                                    now() + expires
                                } else {
                                    u64::MAX
                                })
                                .write(value.as_slice())
                                .finalize(),
                        ),
                    ),
                    LookupValue::Counter { num } => (ValueClass::Key { key }, ValueOp::Add(num)),
                    LookupValue::None => return Ok(()),
                };

                let mut batch = BatchBuilder::new();
                batch.ops.push(Operation::Value { class, op });
                store.write(batch.build()).await
            }
            LookupStore::Memory(_) => unimplemented!(),
        }
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: LookupKey,
    ) -> crate::Result<LookupValue<T>> {
        match self {
            LookupStore::Store(store) => match key {
                LookupKey::Key(key) => store
                    .get_value::<LookupValue<T>>(ValueKey {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Key { key },
                    })
                    .await
                    .map(|value| value.unwrap_or(LookupValue::None)),
                LookupKey::Counter(key) => store
                    .get_counter(ValueKey {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Key { key },
                    })
                    .await
                    .map(|num| LookupValue::Counter { num }),
            },
            LookupStore::Memory(_) => unimplemented!(),
        }
    }

    pub async fn purge_expired(&self) -> crate::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let from_key = ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Key { key: vec![0u8] },
                };
                let to_key = ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Key {
                        key: vec![u8::MAX; 10],
                    },
                };

                let current_time = now();
                let mut expired_keys = Vec::new();
                store
                    .iterate(IterateParams::new(from_key, to_key), |key, value| {
                        if value.deserialize_be_u64(0)? < current_time {
                            expired_keys.push(key.to_vec());
                        }
                        Ok(true)
                    })
                    .await?;
                if !expired_keys.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_keys {
                        batch.ops.push(Operation::Value {
                            class: ValueClass::Key { key },
                            op: ValueOp::Clear,
                        });
                        if batch.ops.len() >= 1000 {
                            store.write(batch.build()).await?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.ops.is_empty() {
                        store.write(batch.build()).await?;
                    }
                }
            }
            LookupStore::Memory(_) => {}
        }

        Ok(())
    }
}

impl<T: Deserialize> Deserialize for LookupValue<T> {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        bytes.deserialize_be_u64(0).and_then(|expires| {
            Ok(if expires > now() {
                LookupValue::Value {
                    value: T::deserialize(bytes.get(U64_LEN..).unwrap_or_default())?,
                    expires,
                }
            } else {
                LookupValue::None
            })
        })
    }
}
