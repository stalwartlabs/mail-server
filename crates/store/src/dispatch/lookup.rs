/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use trc::AddContext;
use utils::config::Rate;

#[allow(unused_imports)]
use crate::{
    Deserialize, InMemoryStore, IterateParams, QueryResult, Store, U64_LEN, Value, ValueKey,
    write::{
        BatchBuilder, Operation, ValueClass, ValueOp,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use crate::{
    SerializeInfallible,
    backend::http::lookup::HttpStoreGet,
    write::{InMemoryClass, assert::AssertValue},
};

pub struct KeyValue<T> {
    pub key: Vec<u8>,
    pub value: T,
    pub expires: Option<u64>,
}

impl InMemoryStore {
    pub async fn key_set(&self, kv: KeyValue<Vec<u8>>) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Key(kv.key)),
                    op: ValueOp::Set {
                        value: KeySerializer::new(kv.value.len() + U64_LEN)
                            .write(kv.expires.map_or(u64::MAX, |expires| now() + expires))
                            .write(kv.value.as_slice())
                            .finalize(),
                        version_offset: None,
                    },
                });
                store.write(batch.build_all()).await.map(|_| ())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_set(kv).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_incr(&self, kv: KeyValue<i64>, return_value: bool) -> trc::Result<i64> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();

                if let Some(expires) = kv.expires {
                    batch.any_op(Operation::Value {
                        class: ValueClass::InMemory(InMemoryClass::Key(kv.key.clone())),
                        op: ValueOp::Set {
                            value: KeySerializer::new(U64_LEN * 2)
                                .write(0u64)
                                .write(now() + expires)
                                .finalize(),
                            version_offset: None,
                        },
                    });
                }

                if return_value {
                    batch.any_op(Operation::Value {
                        class: ValueClass::InMemory(InMemoryClass::Counter(kv.key)),
                        op: ValueOp::AddAndGet(kv.value),
                    });

                    store
                        .write(batch.build_all())
                        .await
                        .and_then(|r| r.last_counter_id())
                } else {
                    batch.any_op(Operation::Value {
                        class: ValueClass::InMemory(InMemoryClass::Counter(kv.key)),
                        op: ValueOp::AtomicAdd(kv.value),
                    });

                    store.write(batch.build_all()).await.map(|_| 0)
                }
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.counter_incr(kv).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Key(key.into().into_bytes())),
                    op: ValueOp::Clear,
                });
                store.write(batch.build_all()).await.map(|_| ())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete(key.into().as_bytes()).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_delete(key).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Counter(key.into().into_bytes())),
                    op: ValueOp::Clear,
                });
                store.write(batch.build_all()).await.map(|_| ())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete(key.into().as_bytes()).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.counter_delete(key).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                if prefix.is_empty() {
                    return Ok(());
                }

                let from_range = prefix.to_vec();
                let mut to_range = Vec::with_capacity(prefix.len() + 3);
                to_range.extend_from_slice(prefix);
                to_range.extend_from_slice([u8::MAX, u8::MAX, u8::MAX].as_ref());

                store
                    .delete_range(
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Counter(
                            from_range.clone(),
                        ))),
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Counter(
                            to_range.clone(),
                        ))),
                    )
                    .await?;

                store
                    .delete_range(
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(from_range))),
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(to_range))),
                    )
                    .await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete_prefix(prefix).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_delete_prefix(prefix).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
        &self,
        key: impl Into<LookupKey<'_>>,
    ) -> trc::Result<Option<T>> {
        match self {
            InMemoryStore::Store(store) => store
                .get_value::<LookupValue<T>>(ValueKey::from(ValueClass::InMemory(
                    InMemoryClass::Key(key.into().into_bytes()),
                )))
                .await
                .map(|value| value.and_then(|v| v.into())),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_get(key.into().as_bytes()).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_get(key).await,
            InMemoryStore::Static(store) => Ok(store
                .get(key.into().as_str())
                .map(|value| T::from(value.clone()))),
            InMemoryStore::Http(store) => {
                Ok(store.get(key.into().as_str()).map(|value| T::from(value)))
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_get(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<i64> {
        match self {
            InMemoryStore::Store(store) => {
                store
                    .get_counter(ValueKey::from(ValueClass::InMemory(
                        InMemoryClass::Counter(key.into().into_bytes()),
                    )))
                    .await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.counter_get(key.into().as_bytes()).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.counter_get(key).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_exists(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {
        match self {
            InMemoryStore::Store(store) => store
                .get_value::<LookupValue<()>>(ValueKey::from(ValueClass::InMemory(
                    InMemoryClass::Key(key.into().into_bytes()),
                )))
                .await
                .map(|value| matches!(value, Some(LookupValue::Value(())))),
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_exists(key.into().as_bytes()).await,
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.key_exists(key).await,
            InMemoryStore::Static(store) => Ok(store.get(key.into().as_str()).is_some()),
            InMemoryStore::Http(store) => Ok(store.contains(key.into().as_str())),
        }
        .caused_by(trc::location!())
    }

    pub async fn is_rate_allowed(
        &self,
        prefix: u8,
        key: &[u8],
        rate: &Rate,
        soft_check: bool,
    ) -> trc::Result<Option<u64>> {
        let now = now();
        let range_start = now / rate.period.as_secs();
        let range_end = (range_start * rate.period.as_secs()) + rate.period.as_secs();
        let expires_in = range_end - now;

        let mut bucket = Vec::with_capacity(key.len() + U64_LEN + 1);
        bucket.push(prefix);
        bucket.extend_from_slice(key);
        bucket.extend_from_slice(range_start.to_be_bytes().as_slice());

        let requests = if !soft_check {
            self.counter_incr(KeyValue::new(bucket, 1).expires(expires_in), true)
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

    pub async fn try_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<bool> {
        match self {
            InMemoryStore::Store(store) => {
                let key = KeyValue::<()>::build_key(prefix, key);
                let lock_expiry = match store
                    .get_value::<u64>(ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(
                        key.clone(),
                    ))))
                    .await
                {
                    Ok(lock_expiry) => lock_expiry,
                    Err(err)
                        if err.matches(trc::EventType::Store(trc::StoreEvent::DataCorruption)) =>
                    {
                        // TODO remove in 1.0
                        let mut batch = BatchBuilder::new();
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Key(key.clone())),
                            op: ValueOp::Clear,
                        });
                        store
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                        None
                    }
                    Err(err) => {
                        return Err(err
                            .details("Failed to read lock.")
                            .caused_by(trc::location!()));
                    }
                };

                let now = now();
                if lock_expiry.is_some_and(|expiry| expiry > now) {
                    return Ok(false);
                }

                let key: ValueClass = ValueClass::InMemory(InMemoryClass::Key(key));
                let mut batch = BatchBuilder::new();
                batch.assert_value(
                    key.clone(),
                    match lock_expiry {
                        Some(value) => AssertValue::U64(value),
                        None => AssertValue::None,
                    },
                );
                batch.set(key.clone(), (now + duration).serialize());
                match store.write(batch.build_all()).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.is_assertion_failure() => Ok(false),
                    Err(err) => Err(err
                        .details("Failed to lock event.")
                        .caused_by(trc::location!())),
                }
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store
                .key_incr(&KeyValue::<()>::build_key(prefix, key), 1, duration.into())
                .await
                .map(|count| count == 1),
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store
                .counter_incr(KeyValue::with_prefix(prefix, key, 1).expires(duration))
                .await
                .map(|count| count == 1),
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn remove_lock(&self, prefix: u8, key: &[u8]) -> trc::Result<()> {
        self.key_delete(KeyValue::<()>::build_key(prefix, key))
            .await
    }

    pub async fn purge_in_memory_store(&self) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                // Delete expired keys and counters
                let from_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![0u8])));
                let to_key =
                    ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![u8::MAX; 10])));

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
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Key(key)),
                            op: ValueOp::Clear,
                        });
                        if batch.is_large_batch() {
                            store
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.is_empty() {
                        store
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                    }
                }

                if !expired_counters.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_counters {
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Counter(key.clone())),
                            op: ValueOp::Clear,
                        });
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Key(key)),
                            op: ValueOp::Clear,
                        });
                        if batch.is_large_batch() {
                            store
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.is_empty() {
                        store
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                    }
                }
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => {}
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(_) => {}
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {}
        }

        Ok(())
    }

    pub fn is_sql(&self) -> bool {
        match self {
            InMemoryStore::Store(store) => store.is_sql(),
            _ => false,
        }
    }

    pub fn is_redis(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            InMemoryStore::Static(_) => false,
            _ => false,
        }
    }
}

pub enum LookupKey<'x> {
    String(String),
    StringRef(&'x str),
    Bytes(Vec<u8>),
    BytesRef(&'x [u8]),
}

impl<'x> From<&'x str> for LookupKey<'x> {
    fn from(key: &'x str) -> Self {
        LookupKey::StringRef(key)
    }
}

impl<'x> From<&'x String> for LookupKey<'x> {
    fn from(key: &'x String) -> Self {
        LookupKey::StringRef(key.as_str())
    }
}

impl<'x> From<&'x [u8]> for LookupKey<'x> {
    fn from(key: &'x [u8]) -> Self {
        LookupKey::BytesRef(key)
    }
}

impl<'x> From<Cow<'x, str>> for LookupKey<'x> {
    fn from(key: Cow<'x, str>) -> Self {
        match key {
            Cow::Borrowed(key) => LookupKey::StringRef(key),
            Cow::Owned(key) => LookupKey::String(key),
        }
    }
}

impl From<String> for LookupKey<'static> {
    fn from(key: String) -> Self {
        LookupKey::String(key)
    }
}

impl From<Vec<u8>> for LookupKey<'static> {
    fn from(key: Vec<u8>) -> Self {
        LookupKey::Bytes(key)
    }
}

impl LookupKey<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            LookupKey::String(string) => string,
            LookupKey::StringRef(string) => string,
            LookupKey::Bytes(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
            LookupKey::BytesRef(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            LookupKey::String(string) => string.into_bytes(),
            LookupKey::StringRef(string) => string.as_bytes().to_vec(),
            LookupKey::Bytes(bytes) => bytes,
            LookupKey::BytesRef(bytes) => bytes.to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            LookupKey::String(string) => string.as_bytes(),
            LookupKey::StringRef(string) => string.as_bytes(),
            LookupKey::Bytes(bytes) => bytes.as_slice(),
            LookupKey::BytesRef(bytes) => bytes,
        }
    }
}

impl<T> KeyValue<T> {
    pub fn build_key(prefix: u8, key: impl AsRef<[u8]>) -> Vec<u8> {
        let key_ = key.as_ref();
        let mut key = Vec::with_capacity(key_.len() + 1);
        key.push(prefix);
        key.extend_from_slice(key_);
        key
    }

    pub fn with_prefix(prefix: u8, key: impl AsRef<[u8]>, value: T) -> Self {
        Self {
            key: Self::build_key(prefix, key),
            value,
            expires: None,
        }
    }

    pub fn new(key: impl Into<Vec<u8>>, value: T) -> Self {
        Self {
            key: key.into(),
            value,
            expires: None,
        }
    }

    pub fn expires(mut self, expires: u64) -> Self {
        self.expires = expires.into();
        self
    }

    pub fn expires_opt(mut self, expires: Option<u64>) -> Self {
        self.expires = expires;
        self
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
