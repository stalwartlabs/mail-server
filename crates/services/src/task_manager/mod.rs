/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use alarm::SendAlarmTask;
use bayes::BayesTrainTask;
use common::config::server::ServerProtocol;
use common::listener::limiter::ConcurrencyLimiter;
use common::listener::{ServerInstance, TcpAcceptor};
use common::{IPC_CHANNEL_BUFFER, LONG_1Y_SLUMBER};
use common::{Inner, KV_LOCK_TASK, Server, core::BuildServer};
use fts::FtsIndexTask;
use groupware::calendar::alarm::CalendarAlarm;
use jmap_proto::types::collection::Collection;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
use store::rand;
use store::rand::seq::SliceRandom;
use store::{
    IterateParams, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    ahash::AHashMap,
    write::{
        BatchBuilder, TaskQueueClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use tokio::sync::{mpsc, watch};
use trc::TaskQueueEvent;
use utils::snowflake::SnowflakeIdGenerator;
use utils::{BLOB_HASH_LEN, BlobHash};

pub mod alarm;
pub mod bayes;
pub mod fts;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Task {
    account_id: u32,
    document_id: u32,
    due: u64,
    action: TaskAction,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TaskAction {
    Index { hash: BlobHash },
    BayesTrain { hash: BlobHash, learn_spam: bool },
    SendAlarm { alarm: CalendarAlarm },
}

const FTS_LOCK_EXPIRY: u64 = 60 * 5;
const BAYES_LOCK_EXPIRY: u64 = 60 * 30;
const ALARM_EXPIRY: u64 = 60 * 2;

pub(crate) struct TaskManagerIpc {
    tx_fts: mpsc::Sender<Task>,
    tx_bayes: mpsc::Sender<Task>,
    tx_alarm: mpsc::Sender<Task>,
    locked: AHashMap<Vec<u8>, Locked>,
    revision: u64,
}

struct Locked {
    expires: Instant,
    revision: u64,
}

pub fn spawn_task_manager(inner: Arc<Inner>) {
    // Create three mpsc channels for the different task types
    let (tx_index_1, rx_index_1) = mpsc::channel::<Task>(IPC_CHANNEL_BUFFER);
    let (tx_index_2, rx_index_2) = mpsc::channel::<Task>(IPC_CHANNEL_BUFFER);
    let (tx_index_3, rx_index_3) = mpsc::channel::<Task>(IPC_CHANNEL_BUFFER);

    // Create dummy server instance for alarms
    let server_instance = Arc::new(ServerInstance {
        id: "_local".to_string(),
        protocol: ServerProtocol::Smtp,
        acceptor: TcpAcceptor::Plain,
        limiter: ConcurrencyLimiter::new(100),
        shutdown_rx: watch::channel(false).1,
        proxy_networks: vec![],
        span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
    });

    for mut rx_index in [rx_index_1, rx_index_2, rx_index_3] {
        let inner = inner.clone();
        let server_instance = server_instance.clone();

        tokio::spawn(async move {
            while let Some(task) = rx_index.recv().await {
                let server = inner.build_server();
                // Lock task
                if server.try_lock_task(&task).await {
                    let success = match &task.action {
                        TaskAction::Index { hash } => server.fts_index(&task, hash).await,
                        TaskAction::BayesTrain { hash, learn_spam } => {
                            server.bayes_train(&task, hash, *learn_spam).await
                        }
                        TaskAction::SendAlarm { alarm } => {
                            if server.core.groupware.alarms_enabled {
                                server
                                    .send_alarm(&task, alarm, server_instance.clone())
                                    .await
                            } else {
                                true
                            }
                        }
                    };

                    // Remove entry from queue
                    if success {
                        if let Err(err) = server
                            .core
                            .storage
                            .data
                            .write(
                                BatchBuilder::new()
                                    .with_account_id(task.account_id)
                                    .with_collection(Collection::Email)
                                    .update_document(task.document_id)
                                    .clear(task.value_class())
                                    .build_all(),
                            )
                            .await
                        {
                            trc::error!(
                                err.account_id(task.account_id)
                                    .document_id(task.document_id)
                                    .details("Failed to remove task from queue.")
                            );
                        }

                        if task.remove_lock() {
                            server.remove_index_lock(&task).await;
                        }
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        let mut ipc = TaskManagerIpc {
            tx_fts: tx_index_1,
            tx_bayes: tx_index_2,
            tx_alarm: tx_index_3,
            locked: Default::default(),
            revision: 0,
        };
        let rx = inner.ipc.task_tx.clone();
        loop {
            // Index any queued tasks
            let sleep_for = inner.build_server().process_tasks(&mut ipc).await;

            // Wait for a signal or sleep until the next task is due
            let _ = tokio::time::timeout(sleep_for, rx.notified()).await;
        }
    });
}

pub(crate) trait TaskQueueManager: Sync + Send {
    fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> impl Future<Output = Duration> + Send;
    fn try_lock_task(&self, event: &Task) -> impl Future<Output = bool> + Send;
    fn remove_index_lock(&self, event: &Task) -> impl Future<Output = ()> + Send;
}

impl TaskQueueManager for Server {
    async fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> Duration {
        let from_key = ValueKey::<ValueClass> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                due: 0,
                hash: BlobHash::default(),
            }),
        };
        let to_key = ValueKey::<ValueClass> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                due: u64::MAX,
                hash: BlobHash::default(),
            }),
        };

        // Retrieve tasks pending to be processed
        let mut tasks = Vec::new();
        let now_timestamp = now();
        let now = Instant::now();
        let mut next_event = None;
        ipc.revision += 1;
        let _ = self
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let task = Task::deserialize(key, value)?;
                    if task.due <= now_timestamp {
                        match ipc.locked.entry(key.to_vec()) {
                            Entry::Occupied(mut entry) => {
                                let locked = entry.get_mut();
                                if locked.expires <= now {
                                    locked.expires = Instant::now()
                                        + std::time::Duration::from_secs(task.lock_expiry() + 1);
                                    tasks.push(task);
                                }
                                locked.revision = ipc.revision;
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(Locked {
                                    expires: Instant::now()
                                        + std::time::Duration::from_secs(task.lock_expiry() + 1),
                                    revision: ipc.revision,
                                });
                                tasks.push(task);
                            }
                        }

                        Ok(true)
                    } else {
                        next_event = Some(task.due);
                        Ok(false)
                    }
                },
            )
            .await
            .map_err(|err| {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to iterate over index emails")
                );
            });

        if !tasks.is_empty() || !ipc.locked.is_empty() {
            trc::event!(
                TaskQueue(TaskQueueEvent::TaskAcquired),
                Total = tasks.len(),
                Details = ipc.locked.len(),
            );
        }

        // Shuffle tasks
        if tasks.len() > 1 {
            tasks.shuffle(&mut rand::rng());
        }

        for event in tasks {
            let tx = match &event.action {
                TaskAction::Index { .. } => &ipc.tx_fts,
                TaskAction::BayesTrain { .. } => &ipc.tx_bayes,
                TaskAction::SendAlarm { .. } => &ipc.tx_alarm,
            };
            if tx.send(event).await.is_err() {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Error sending task.",
                    CausedBy = trc::location!()
                );
            }
        }

        // Delete expired locks
        let now = Instant::now();
        ipc.locked
            .retain(|_, locked| locked.expires > now && locked.revision == ipc.revision);
        next_event.map_or(LONG_1Y_SLUMBER, |timestamp| {
            Duration::from_secs(timestamp.saturating_sub(store::write::now()))
        })
    }

    async fn try_lock_task(&self, event: &Task) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_TASK, &event.lock_key(), event.lock_expiry())
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::TaskLocked),
                        AccountId = event.account_id,
                        DocumentId = event.document_id,
                        Expires = trc::Value::Timestamp(now() + event.lock_expiry()),
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.account_id(event.account_id)
                        .document_id(event.document_id)
                        .details("Failed to lock task")
                );

                false
            }
        }
    }

    async fn remove_index_lock(&self, event: &Task) {
        let key = event.lock_key();
        if let Err(err) = self.in_memory_store().remove_lock(KV_LOCK_TASK, &key).await {
            trc::error!(
                err.details("Failed to unlock task")
                    .ctx(trc::Key::Key, key)
                    .caused_by(trc::location!())
            );
        }
    }
}

impl Task {
    fn remove_lock(&self) -> bool {
        // Bayes locks are not removed to avoid constant retraining
        matches!(
            self.action,
            TaskAction::Index { .. } | TaskAction::SendAlarm { .. }
        )
    }

    fn lock_key(&self) -> Vec<u8> {
        match &self.action {
            TaskAction::Index { .. } => KeySerializer::new((U32_LEN * 2) + U64_LEN + 1)
                .write(0u8)
                .write(self.due)
                .write_leb128(self.account_id)
                .write_leb128(self.document_id)
                .finalize(),
            TaskAction::BayesTrain { .. } => KeySerializer::new((U32_LEN * 2) + 1)
                .write(1u8)
                .write_leb128(self.account_id)
                .write_leb128(self.document_id)
                .finalize(),
            TaskAction::SendAlarm { .. } => KeySerializer::new((U32_LEN * 2) + U64_LEN + 1)
                .write(2u8)
                .write(self.due)
                .write_leb128(self.account_id)
                .write_leb128(self.document_id)
                .finalize(),
        }
    }

    fn lock_expiry(&self) -> u64 {
        match self.action {
            TaskAction::Index { .. } => FTS_LOCK_EXPIRY,
            TaskAction::BayesTrain { .. } => BAYES_LOCK_EXPIRY,
            TaskAction::SendAlarm { .. } => ALARM_EXPIRY,
        }
    }

    fn value_class(&self) -> ValueClass {
        ValueClass::TaskQueue(match &self.action {
            TaskAction::Index { hash } => TaskQueueClass::IndexEmail {
                hash: hash.clone(),
                due: self.due,
            },
            TaskAction::BayesTrain { hash, learn_spam } => TaskQueueClass::BayesTrain {
                hash: hash.clone(),
                due: self.due,
                learn_spam: *learn_spam,
            },
            TaskAction::SendAlarm { alarm } => TaskQueueClass::SendAlarm {
                event_id: alarm.event_id,
                alarm_id: alarm.alarm_id,
                due: self.due,
            },
        })
    }

    fn deserialize(key: &[u8], value: &[u8]) -> trc::Result<Self> {
        Ok(Task {
            due: key.deserialize_be_u64(0)?,
            account_id: key.deserialize_be_u32(U64_LEN)?,
            document_id: key.deserialize_be_u32(U64_LEN + U32_LEN + 1)?,
            action: match key.get(U64_LEN + U32_LEN) {
                Some(0) => TaskAction::Index {
                    hash: key
                        .get(
                            U64_LEN + U32_LEN + U32_LEN + 1
                                ..U64_LEN + U32_LEN + U32_LEN + BLOB_HASH_LEN + 1,
                        )
                        .and_then(|bytes| BlobHash::try_from_hash_slice(bytes).ok())
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?,
                },
                Some(1) => TaskAction::BayesTrain {
                    learn_spam: true,
                    hash: key
                        .get(
                            U64_LEN + U32_LEN + U32_LEN + 1
                                ..U64_LEN + U32_LEN + U32_LEN + BLOB_HASH_LEN + 1,
                        )
                        .and_then(|bytes| BlobHash::try_from_hash_slice(bytes).ok())
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?,
                },
                Some(2) => TaskAction::BayesTrain {
                    learn_spam: false,
                    hash: key
                        .get(
                            U64_LEN + U32_LEN + U32_LEN + 1
                                ..U64_LEN + U32_LEN + U32_LEN + BLOB_HASH_LEN + 1,
                        )
                        .and_then(|bytes| BlobHash::try_from_hash_slice(bytes).ok())
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?,
                },
                Some(3) => TaskAction::SendAlarm {
                    alarm: CalendarAlarm {
                        event_id: key.deserialize_be_u16(U64_LEN + U32_LEN + U32_LEN + 1)?,
                        alarm_id: key
                            .deserialize_be_u16(U64_LEN + U32_LEN + U32_LEN + U16_LEN + 1)?,
                        event_start: value.deserialize_be_u64(0)? as i64,
                        event_end: value.deserialize_be_u64(U64_LEN)? as i64,
                        event_start_tz: value.deserialize_be_u16(U64_LEN * 2)?,
                        event_end_tz: value.deserialize_be_u16((U64_LEN * 2) + U16_LEN)?,
                        alarm_time: 0,
                    },
                },
                _ => return Err(trc::Error::corrupted_key(key, None, trc::location!())),
            },
        })
    }
}
