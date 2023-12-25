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

use crate::{backend::memory::MemoryStore, Row};
#[allow(unused_imports)]
use crate::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        now, BatchBuilder, Operation, ValueClass, ValueOp,
    },
    Deserialize, IterateParams, LookupKey, LookupStore, LookupValue, QueryResult, Store, Value,
    ValueKey, U64_LEN,
};

impl LookupStore {
    #[allow(unreachable_patterns)]
    #[allow(unused_variables)]
    pub async fn query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> crate::Result<T> {
        let result = match self {
            #[cfg(feature = "sqlite")]
            LookupStore::Store(Store::SQLite(store)) => store.query(query, params).await,
            #[cfg(feature = "postgres")]
            LookupStore::Store(Store::PostgreSQL(store)) => store.query(query, params).await,
            #[cfg(feature = "mysql")]
            LookupStore::Store(Store::MySQL(store)) => store.query(query, params).await,
            _ => Err(crate::Error::InternalError(
                "Store does not support queries".into(),
            )),
        };

        tracing::trace!( context = "store", event = "query", query = query, result = ?result);

        result
    }

    pub async fn key_set(&self, key: Vec<u8>, value: LookupValue<Vec<u8>>) -> crate::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let (class, op) = match value {
                    LookupValue::Value { value, expires } => (
                        ValueClass::Key(key),
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
                    LookupValue::Counter { num } => (ValueClass::Key(key), ValueOp::Add(num)),
                    LookupValue::None => return Ok(()),
                };

                let mut batch = BatchBuilder::new();
                batch.ops.push(Operation::Value { class, op });
                store.write(batch.build()).await
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_set(key, value).await,
            LookupStore::Query(lookup) => lookup
                .store
                .query::<usize>(
                    &lookup.query,
                    vec![String::from_utf8(key).unwrap_or_default().into()],
                )
                .await
                .map(|_| ()),
            LookupStore::Memory(_) => Err(crate::Error::InternalError(
                "This store does not support key_set".into(),
            )),
        }
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
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
                        class: ValueClass::Key(key),
                    })
                    .await
                    .map(|value| value.unwrap_or(LookupValue::None)),
                LookupKey::Counter(key) => store
                    .get_counter(ValueKey {
                        account_id: 0,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Key(key),
                    })
                    .await
                    .map(|num| LookupValue::Counter { num }),
            },
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_get(key).await,
            LookupStore::Memory(store) => {
                let key = String::from(key);
                match store.as_ref() {
                    MemoryStore::List(list) => Ok(if list.contains(&key) {
                        LookupValue::Value {
                            value: T::from(Value::Bool(true)),
                            expires: 0,
                        }
                    } else {
                        LookupValue::None
                    }),
                    MemoryStore::Map(map) => Ok(map
                        .get(&key)
                        .map(|value| LookupValue::Value {
                            value: T::from(value.to_owned()),
                            expires: 0,
                        })
                        .unwrap_or(LookupValue::None)),
                }
            }
            LookupStore::Query(lookup) => lookup
                .store
                .query::<Option<Row>>(&lookup.query, vec![String::from(key).into()])
                .await
                .map(|row| {
                    row.and_then(|row| row.values.into_iter().next())
                        .map(|value| LookupValue::Value {
                            value: T::from(value),
                            expires: 0,
                        })
                        .unwrap_or(LookupValue::None)
                }),
        }
    }

    pub async fn purge_expired(&self) -> crate::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let from_key = ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Key(vec![0u8]),
                };
                let to_key = ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Key(vec![u8::MAX; 10]),
                };

                let current_time = now();
                let mut expired_keys = Vec::new();
                store
                    .iterate(IterateParams::new(from_key, to_key), |key, value| {
                        if value.deserialize_be_u64(0)? < current_time {
                            expired_keys.push(key.get(1..).unwrap_or_default().to_vec());
                        }
                        Ok(true)
                    })
                    .await?;
                if !expired_keys.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_keys {
                        batch.ops.push(Operation::Value {
                            class: ValueClass::Key(key),
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
            #[cfg(feature = "redis")]
            LookupStore::Redis(_) => {}
            LookupStore::Memory(_) | LookupStore::Query(_) => {}
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

impl From<Value<'static>> for String {
    fn from(value: Value<'static>) -> Self {
        match value {
            Value::Text(string) => string.into_owned(),
            Value::Blob(bytes) => String::from_utf8_lossy(bytes.as_ref()).into_owned(),
            Value::Bool(boolean) => boolean.to_string(),
            Value::Null => String::new(),
            Value::Integer(num) => num.to_string(),
            Value::Float(num) => num.to_string(),
        }
    }
}
