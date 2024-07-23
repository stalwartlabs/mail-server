/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;
use utils::config::Rate;

use crate::{write::LookupClass, Row};
#[allow(unused_imports)]
use crate::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        now, BatchBuilder, Operation, ValueClass, ValueOp,
    },
    Deserialize, IterateParams, LookupStore, QueryResult, Store, Value, ValueKey, U64_LEN,
};

impl LookupStore {
    #[allow(unreachable_patterns)]
    #[allow(unused_variables)]
    pub async fn query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> trc::Result<T> {
        let result = match self {
            #[cfg(feature = "sqlite")]
            LookupStore::Store(Store::SQLite(store)) => store.query(query, &params).await,
            #[cfg(feature = "postgres")]
            LookupStore::Store(Store::PostgreSQL(store)) => store.query(query, &params).await,
            #[cfg(feature = "mysql")]
            LookupStore::Store(Store::MySQL(store)) => store.query(query, &params).await,
            _ => Err(trc::StoreEvent::NotSupported.into_err()),
        };

        trc::event!(
            Store(trc::StoreEvent::SqlQuery),
            Query = query.to_string(),
            Parameters = params.as_slice(),
            Result = &result,
        );

        result.caused_by(trc::location!())
    }

    pub async fn key_set(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        expires: Option<u64>,
    ) -> trc::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Key(key)),
                    op: ValueOp::Set(
                        KeySerializer::new(value.len() + U64_LEN)
                            .write(expires.map_or(u64::MAX, |expires| now() + expires))
                            .write(value.as_slice())
                            .finalize()
                            .into(),
                    ),
                });
                store.write(batch.build()).await.map(|_| ())
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_set(key, value, expires).await,
            LookupStore::Query(lookup) => lookup
                .store
                .query::<usize>(
                    &lookup.query,
                    vec![String::from_utf8(key).unwrap_or_default().into()],
                )
                .await
                .map(|_| ()),
            LookupStore::Memory(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_incr(
        &self,
        key: Vec<u8>,
        value: i64,
        expires: Option<u64>,
        return_value: bool,
    ) -> trc::Result<i64> {
        match self {
            LookupStore::Store(store) => {
                let mut batch = BatchBuilder::new();

                if let Some(expires) = expires {
                    batch.ops.push(Operation::Value {
                        class: ValueClass::Lookup(LookupClass::Key(key.clone())),
                        op: ValueOp::Set(
                            KeySerializer::new(U64_LEN * 2)
                                .write(0u64)
                                .write(now() + expires)
                                .finalize()
                                .into(),
                        ),
                    });
                }

                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Counter(key)),
                    op: if return_value {
                        ValueOp::AddAndGet(value)
                    } else {
                        ValueOp::AtomicAdd(value)
                    },
                });

                store.write(batch.build()).await.and_then(|r| {
                    if return_value {
                        r.last_counter_id()
                    } else {
                        Ok(0)
                    }
                })
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_incr(key, value, expires).await,
            LookupStore::Query(_) | LookupStore::Memory(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete(&self, key: Vec<u8>) -> trc::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Key(key)),
                    op: ValueOp::Clear,
                });
                store.write(batch.build()).await.map(|_| ())
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_delete(key).await,
            LookupStore::Query(_) | LookupStore::Memory(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_delete(&self, key: Vec<u8>) -> trc::Result<()> {
        match self {
            LookupStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Counter(key)),
                    op: ValueOp::Clear,
                });
                store.write(batch.build()).await.map(|_| ())
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_delete(key).await,
            LookupStore::Query(_) | LookupStore::Memory(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
        &self,
        key: Vec<u8>,
    ) -> trc::Result<Option<T>> {
        match self {
            LookupStore::Store(store) => store
                .get_value::<LookupValue<T>>(ValueKey::from(ValueClass::Lookup(LookupClass::Key(
                    key,
                ))))
                .await
                .map(|value| value.and_then(|v| v.into())),
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_get(key).await,
            LookupStore::Query(lookup) => lookup
                .store
                .query::<Option<Row>>(
                    &lookup.query,
                    vec![String::from_utf8(key).unwrap_or_default().into()],
                )
                .await
                .map(|row| {
                    row.and_then(|row| row.values.into_iter().next())
                        .map(|value| T::from(value))
                }),
            LookupStore::Memory(store) => Ok(store
                .get(std::str::from_utf8(&key).unwrap_or_default())
                .map(|value| T::from(value.clone()))),
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_get(&self, key: Vec<u8>) -> trc::Result<i64> {
        match self {
            LookupStore::Store(store) => {
                store
                    .get_counter(ValueKey::from(ValueClass::Lookup(LookupClass::Counter(
                        key,
                    ))))
                    .await
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.counter_get(key).await,
            LookupStore::Query(_) | LookupStore::Memory(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_exists(&self, key: Vec<u8>) -> trc::Result<bool> {
        match self {
            LookupStore::Store(store) => store
                .get_value::<LookupValue<()>>(ValueKey::from(ValueClass::Lookup(LookupClass::Key(
                    key,
                ))))
                .await
                .map(|value| matches!(value, Some(LookupValue::Value(())))),
            #[cfg(feature = "redis")]
            LookupStore::Redis(store) => store.key_exists(key).await,
            LookupStore::Query(lookup) => lookup
                .store
                .query::<Option<Row>>(
                    &lookup.query,
                    vec![String::from_utf8(key).unwrap_or_default().into()],
                )
                .await
                .map(|row| row.is_some()),
            LookupStore::Memory(store) => Ok(store
                .get(std::str::from_utf8(&key).unwrap_or_default())
                .is_some()),
        }
        .caused_by(trc::location!())
    }

    pub async fn is_rate_allowed(
        &self,
        key: &[u8],
        rate: &Rate,
        soft_check: bool,
    ) -> trc::Result<Option<u64>> {
        let now = now();
        let range_start = now / rate.period.as_secs();
        let range_end = (range_start * rate.period.as_secs()) + rate.period.as_secs();
        let expires_in = range_end - now;

        let mut bucket = Vec::with_capacity(key.len() + U64_LEN);
        bucket.extend_from_slice(key);
        bucket.extend_from_slice(range_start.to_be_bytes().as_slice());

        let requests = if !soft_check {
            self.counter_incr(bucket, 1, expires_in.into(), true)
                .await
                .caused_by(trc::location!())?
        } else {
            self.counter_get(bucket).await.caused_by(trc::location!())? + 1
        };

        if requests <= rate.requests as i64 {
            Ok(None)
        } else {
            Ok(Some(expires_in))
        }
    }

    pub async fn purge_lookup_store(&self) -> trc::Result<()> {
        match self {
            LookupStore::Store(store) => {
                // Delete expired keys and counters
                let from_key = ValueKey::from(ValueClass::Lookup(LookupClass::Key(vec![0u8])));
                let to_key =
                    ValueKey::from(ValueClass::Lookup(LookupClass::Key(vec![u8::MAX; 10])));

                let current_time = now();
                let mut expired_keys = Vec::new();
                let mut expired_counters = Vec::new();
                store
                    .iterate(IterateParams::new(from_key, to_key), |key, value| {
                        let expiry = value.deserialize_be_u64(0).caused_by(trc::location!())?;
                        if expiry == 0 {
                            if value
                                .deserialize_be_u64(U64_LEN)
                                .caused_by(trc::location!())?
                                <= current_time
                            {
                                expired_counters.push(key.to_vec());
                            }
                        } else if expiry <= current_time {
                            expired_keys.push(key.to_vec());
                        }
                        Ok(true)
                    })
                    .await
                    .caused_by(trc::location!())?;

                if !expired_keys.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_keys {
                        batch.ops.push(Operation::Value {
                            class: ValueClass::Lookup(LookupClass::Key(key)),
                            op: ValueOp::Clear,
                        });
                        if batch.ops.len() >= 1000 {
                            store
                                .write(batch.build())
                                .await
                                .caused_by(trc::location!())?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.ops.is_empty() {
                        store
                            .write(batch.build())
                            .await
                            .caused_by(trc::location!())?;
                    }
                }

                if !expired_counters.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_counters {
                        batch.ops.push(Operation::Value {
                            class: ValueClass::Lookup(LookupClass::Counter(key.clone())),
                            op: ValueOp::Clear,
                        });
                        batch.ops.push(Operation::Value {
                            class: ValueClass::Lookup(LookupClass::Key(key)),
                            op: ValueOp::Clear,
                        });
                        if batch.ops.len() >= 1000 {
                            store
                                .write(batch.build())
                                .await
                                .caused_by(trc::location!())?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.ops.is_empty() {
                        store
                            .write(batch.build())
                            .await
                            .caused_by(trc::location!())?;
                    }
                }
            }
            #[cfg(feature = "redis")]
            LookupStore::Redis(_) => {}
            LookupStore::Query(_) | LookupStore::Memory(_) => {}
        }

        Ok(())
    }

    pub fn is_sql(&self) -> bool {
        match self {
            LookupStore::Store(store) => store.is_sql(),
            _ => false,
        }
    }
}

enum LookupValue<T> {
    Value(T),
    None,
}

impl<T: Deserialize> Deserialize for LookupValue<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes.deserialize_be_u64(0).and_then(|expires| {
            Ok(if expires > now() {
                LookupValue::Value(
                    T::deserialize(bytes.get(U64_LEN..).unwrap_or_default())
                        .caused_by(trc::location!())?,
                )
            } else {
                LookupValue::None
            })
        })
    }
}

impl<T> From<LookupValue<T>> for Option<T> {
    fn from(value: LookupValue<T>) -> Self {
        match value {
            LookupValue::Value(value) => Some(value),
            LookupValue::None => None,
        }
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
