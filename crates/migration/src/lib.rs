/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use changelog::reset_changelog;
use common::{DATABASE_SCHEMA_VERSION, KV_LOCK_HOUSEKEEPER, Server};
use jmap_proto::types::{collection::Collection, property::Property};
use principal::{migrate_principal, migrate_principals};
use queue::migrate_queue;
use report::migrate_reports;
use store::{
    Deserialize, IterateParams, SUBSPACE_PROPERTY, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SerializeInfallible, U32_LEN, Value, ValueKey,
    dispatch::{DocumentSet, lookup::KeyValue},
    rand::{self, seq::SliceRandom},
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;

pub mod changelog;
pub mod email;
pub mod encryption;
pub mod identity;
pub mod mailbox;
pub mod object;
pub mod principal;
pub mod push;
pub mod queue;
pub mod report;
pub mod sieve;
pub mod submission;
pub mod threads;

const LOCK_WAIT_TIME_ACCOUNT: u64 = 3 * 60;
const LOCK_WAIT_TIME_CORE: u64 = 5 * 60;
const LOCK_RETRY_TIME: Duration = Duration::from_secs(30);

pub async fn try_migrate(server: &Server) -> trc::Result<()> {
    if std::env::var("FORCE_MIGRATE_QUEUE").is_ok() {
        migrate_queue(server).await.caused_by(trc::location!())?;
    }
    if let Some(account_id) = std::env::var("FORCE_MIGRATE_ACCOUNT")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        migrate_principal(server, account_id)
            .await
            .caused_by(trc::location!())?;
    }

    if server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        })
        .await
        .caused_by(trc::location!())?
        == Some(DATABASE_SCHEMA_VERSION)
    {
        return Ok(());
    }

    if !is_new_install(server).await.caused_by(trc::location!())? {
        let force_lock = std::env::var("FORCE_LOCK").is_ok();
        let in_memory = server.in_memory_store();
        let principal_ids;

        loop {
            if force_lock
                || in_memory
                    .try_lock(
                        KV_LOCK_HOUSEKEEPER,
                        b"migrate_core_lock",
                        LOCK_WAIT_TIME_CORE,
                    )
                    .await
                    .caused_by(trc::location!())?
            {
                if in_memory
                    .key_get::<()>(KeyValue::<()>::build_key(
                        KV_LOCK_HOUSEKEEPER,
                        b"migrate_core_done",
                    ))
                    .await
                    .caused_by(trc::location!())?
                    .is_none()
                {
                    migrate_queue(server).await.caused_by(trc::location!())?;
                    migrate_reports(server).await.caused_by(trc::location!())?;
                    reset_changelog(server).await.caused_by(trc::location!())?;
                    principal_ids = migrate_principals(server)
                        .await
                        .caused_by(trc::location!())?;

                    in_memory
                        .key_set(
                            KeyValue::new(
                                KeyValue::<()>::build_key(
                                    KV_LOCK_HOUSEKEEPER,
                                    b"migrate_core_done",
                                ),
                                b"1".to_vec(),
                            )
                            .expires(86400),
                        )
                        .await
                        .caused_by(trc::location!())?;
                } else {
                    principal_ids = server
                        .get_document_ids(u32::MAX, Collection::Principal)
                        .await
                        .caused_by(trc::location!())?
                        .unwrap_or_default();

                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Details = format!("Migration completed by another node.",)
                    );
                }

                in_memory
                    .remove_lock(KV_LOCK_HOUSEKEEPER, b"migrate_core_lock")
                    .await
                    .caused_by(trc::location!())?;
                break;
            } else {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details = format!("Migration lock busy, waiting 30 seconds.",)
                );

                tokio::time::sleep(LOCK_RETRY_TIME).await;
            }
        }

        if !principal_ids.is_empty() {
            let mut principal_ids = principal_ids.into_iter().collect::<Vec<_>>();
            principal_ids.shuffle(&mut rand::rng());

            loop {
                let mut skipped_principal_ids = Vec::new();
                let mut num_migrated = 0;

                for principal_id in principal_ids {
                    let lock_key = format!("migrate_{principal_id}_lock");
                    let done_key = format!("migrate_{principal_id}_done");

                    if force_lock
                        || in_memory
                            .try_lock(
                                KV_LOCK_HOUSEKEEPER,
                                lock_key.as_bytes(),
                                LOCK_WAIT_TIME_ACCOUNT,
                            )
                            .await
                            .caused_by(trc::location!())?
                    {
                        if in_memory
                            .key_get::<()>(KeyValue::<()>::build_key(
                                KV_LOCK_HOUSEKEEPER,
                                done_key.as_bytes(),
                            ))
                            .await
                            .caused_by(trc::location!())?
                            .is_none()
                        {
                            migrate_principal(server, principal_id)
                                .await
                                .caused_by(trc::location!())?;

                            num_migrated += 1;

                            in_memory
                                .key_set(
                                    KeyValue::new(
                                        KeyValue::<()>::build_key(
                                            KV_LOCK_HOUSEKEEPER,
                                            done_key.as_bytes(),
                                        ),
                                        b"1".to_vec(),
                                    )
                                    .expires(86400),
                                )
                                .await
                                .caused_by(trc::location!())?;
                        }

                        in_memory
                            .remove_lock(KV_LOCK_HOUSEKEEPER, lock_key.as_bytes())
                            .await
                            .caused_by(trc::location!())?;
                    } else {
                        skipped_principal_ids.push(principal_id);
                    }
                }

                if !skipped_principal_ids.is_empty() {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Details = format!(
                            "Migrated {num_migrated} accounts and {} are locked by another node, waiting 30 seconds.",
                            skipped_principal_ids.len()
                        )
                    );
                    tokio::time::sleep(LOCK_RETRY_TIME).await;
                    principal_ids = skipped_principal_ids;
                } else {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Details = format!("Account migration completed.",)
                    );
                    break;
                }
            }
        }
    }

    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        }),
        DATABASE_SCHEMA_VERSION.serialize(),
    );
    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

async fn is_new_install(server: &Server) -> trc::Result<bool> {
    for subspace in [
        SUBSPACE_QUEUE_MESSAGE,
        SUBSPACE_REPORT_IN,
        SUBSPACE_REPORT_OUT,
        SUBSPACE_PROPERTY,
    ] {
        let mut has_data = false;

        server
            .store()
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; 16],
                    },
                )
                .no_values(),
                |_, _| {
                    has_data = true;

                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if has_data {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn get_properties<U, I, P>(
    server: &Server,
    account_id: u32,
    collection: Collection,
    iterate: &I,
    property: P,
) -> trc::Result<Vec<(u32, U)>>
where
    I: DocumentSet + Send + Sync,
    P: AsRef<Property> + Sync + Send,
    U: Deserialize + 'static,
{
    let property: u8 = property.as_ref().into();
    let collection: u8 = collection.into();
    let expected_results = iterate.len();
    let mut results = Vec::with_capacity(expected_results);

    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(
                ValueKey {
                    account_id,
                    collection,
                    document_id: iterate.min(),
                    class: ValueClass::Property(property),
                },
                ValueKey {
                    account_id,
                    collection,
                    document_id: iterate.max(),
                    class: ValueClass::Property(property),
                },
            ),
            |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                if iterate.contains(document_id) {
                    results.push((document_id, U::deserialize(value)?));
                    Ok(expected_results == 0 || results.len() < expected_results)
                } else {
                    Ok(true)
                }
            },
        )
        .await
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
                .id(property.to_string())
        })
        .map(|_| results)
}

pub struct LegacyBincode<T: serde::de::DeserializeOwned> {
    pub inner: T,
}

impl<T: serde::de::DeserializeOwned> LegacyBincode<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: serde::de::DeserializeOwned> From<Value<'static>> for LegacyBincode<T> {
    fn from(_: Value<'static>) -> Self {
        unreachable!("From Value called on LegacyBincode<T>")
    }
}

impl<T: serde::de::DeserializeOwned + Sized + Sync + Send> Deserialize for LegacyBincode<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        lz4_flex::decompress_size_prepended(bytes)
            .map_err(|err| {
                trc::StoreEvent::DecompressError
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .and_then(|result| {
                bincode::deserialize(&result).map_err(|err| {
                    trc::StoreEvent::DataCorruption
                        .ctx(trc::Key::Value, bytes)
                        .caused_by(trc::location!())
                        .reason(err)
                })
            })
            .map(|inner| Self { inner })
    }
}

/*

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventData {
    pub event: ICalendar,
    pub time_ranges: Box<[ComponentTimeRange]>,
    pub alarms: Box<[Alarm]>,
    pub base_offset: i64,
    pub base_time_utc: u32,
    pub duration: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Alarm {
    pub comp_id: u16,
    pub alarms: Box<[AlarmDelta]>,
}


*/
