/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::{
    collections::hash_map::RandomState,
    fmt::Display,
    sync::{atomic::AtomicU8, Arc},
    time::Duration,
};

use auth::{rate_limit::ConcurrencyLimiters, AccessToken};
use common::{
    manager::webadmin::WebAdminManager,
    webhooks::{WebhookPayload, WebhookType},
    Core, DeliveryEvent, SharedCore,
};
use dashmap::DashMap;
use directory::QueryBy;
use email::cache::Threads;
use jmap_proto::{
    error::method::MethodError,
    method::{
        query::{QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    types::{collection::Collection, property::Property},
};
use services::{
    delivery::spawn_delivery_manager,
    housekeeper::{self, init_housekeeper, spawn_housekeeper},
    state::{self, init_state_manager, spawn_state_manager},
};

use smtp::core::SMTP;
use store::{
    dispatch::DocumentSet,
    fts::FtsFilter,
    query::{sort::Pagination, Comparator, Filter, ResultSet, SortedResultSet},
    roaring::RoaringBitmap,
    write::{
        key::DeserializeBigEndian, AssignedIds, BatchBuilder, BitmapClass, DirectoryClass,
        TagValue, ValueClass,
    },
    BitmapKey, Deserialize, IterateParams, ValueKey, U32_LEN,
};
use tokio::sync::mpsc;
use utils::{
    config::Config,
    lru_cache::{LruCache, LruCached},
    map::ttl_dashmap::{TtlDashMap, TtlMap},
    snowflake::SnowflakeIdGenerator,
};

pub mod api;
pub mod auth;
pub mod blob;
pub mod changes;
pub mod email;
pub mod identity;
pub mod mailbox;
pub mod principal;
pub mod push;
pub mod quota;
pub mod services;
pub mod sieve;
pub mod submission;
pub mod thread;
pub mod vacation;
pub mod websocket;

pub const LONG_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Clone)]
pub struct JMAP {
    pub core: Arc<Core>,
    pub shared_core: SharedCore,
    pub inner: Arc<Inner>,
    pub smtp: SMTP,
}

#[derive(Clone)]
pub struct JmapInstance {
    pub core: SharedCore,
    pub jmap_inner: Arc<Inner>,
    pub smtp_inner: Arc<smtp::core::Inner>,
}

pub struct Inner {
    pub sessions: TtlDashMap<String, u32>,
    pub access_tokens: TtlDashMap<u32, Arc<AccessToken>>,
    pub snowflake_id: SnowflakeIdGenerator,
    pub webadmin: WebAdminManager,
    pub config_version: AtomicU8,

    pub concurrency_limiter: DashMap<u32, Arc<ConcurrencyLimiters>>,

    pub state_tx: mpsc::Sender<state::Event>,
    pub housekeeper_tx: mpsc::Sender<housekeeper::Event>,

    pub cache_threads: LruCache<u32, Arc<Threads>>,
}

#[derive(Debug)]
pub enum IngestError {
    Temporary,
    OverQuota,
    Permanent { code: [u8; 3], reason: String },
}

impl JMAP {
    pub async fn init(
        config: &mut Config,
        delivery_rx: mpsc::Receiver<DeliveryEvent>,
        core: SharedCore,
        smtp_inner: Arc<smtp::core::Inner>,
    ) -> JmapInstance {
        // Init state manager and housekeeper
        let (state_tx, state_rx) = init_state_manager();
        let (housekeeper_tx, housekeeper_rx) = init_housekeeper();
        let shard_amount = config
            .property::<u64>("cache.shard")
            .unwrap_or(32)
            .next_power_of_two() as usize;
        let capacity = config.property("cache.capacity").unwrap_or(100);

        let inner = Inner {
            webadmin: WebAdminManager::new(),
            sessions: TtlDashMap::with_capacity(capacity, shard_amount),
            access_tokens: TtlDashMap::with_capacity(capacity, shard_amount),
            snowflake_id: config
                .property::<u64>("cluster.node-id")
                .map(SnowflakeIdGenerator::with_node_id)
                .unwrap_or_default(),
            concurrency_limiter: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                RandomState::default(),
                shard_amount,
            ),
            state_tx,
            housekeeper_tx,
            cache_threads: LruCache::with_capacity(
                config.property("cache.thread.size").unwrap_or(2048),
            ),
            config_version: 0.into(),
        };

        // Unpack webadmin
        if let Err(err) = inner.webadmin.unpack(&core.load().storage.blob).await {
            tracing::warn!(event = "error", error = ?err, "Failed to unpack webadmin bundle.");
        }

        let jmap_instance = JmapInstance {
            core,
            jmap_inner: Arc::new(inner),
            smtp_inner,
        };

        // Spawn delivery manager
        spawn_delivery_manager(jmap_instance.clone(), delivery_rx);

        // Spawn state manager
        spawn_state_manager(jmap_instance.clone(), state_rx);

        // Spawn housekeeper
        spawn_housekeeper(jmap_instance.clone(), housekeeper_rx);

        jmap_instance
    }

    pub async fn get_property<U>(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        property: impl AsRef<Property>,
    ) -> Result<Option<U>, MethodError>
    where
        U: Deserialize + 'static,
    {
        let property = property.as_ref();
        match self
            .core
            .storage
            .data
            .get_value::<U>(ValueKey {
                account_id,
                collection: collection.into(),
                document_id,
                class: ValueClass::Property(property.into()),
            })
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                document_id = document_id,
                                property = ?property,
                                error = ?err,
                                "Failed to retrieve property");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn get_properties<U, I, P>(
        &self,
        account_id: u32,
        collection: Collection,
        iterate: &I,
        property: P,
    ) -> Result<Vec<(u32, U)>, MethodError>
    where
        I: DocumentSet + Send + Sync,
        P: AsRef<Property>,
        U: Deserialize + 'static,
    {
        let property: u8 = property.as_ref().into();
        let collection: u8 = collection.into();
        let expected_results = iterate.len();
        let mut results = Vec::with_capacity(expected_results);

        self.core
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
            .map_err(|err| {
                tracing::error!(event = "error",
            context = "store",
            account_id = account_id,
            collection = ?collection,
            property = ?property,
            error = ?err,
            "Failed to retrieve properties");
                MethodError::ServerPartialFail
            })?;

        Ok(results)
    }

    pub async fn get_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> Result<Option<RoaringBitmap>, MethodError> {
        match self
            .core
            .storage
            .data
            .get_bitmap(BitmapKey::document_ids(account_id, collection))
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Failed to retrieve document ids bitmap");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn get_tag(
        &self,
        account_id: u32,
        collection: Collection,
        property: impl AsRef<Property>,
        value: impl Into<TagValue<u32>>,
    ) -> Result<Option<RoaringBitmap>, MethodError> {
        let property = property.as_ref();
        match self
            .core
            .storage
            .data
            .get_bitmap(BitmapKey {
                account_id,
                collection: collection.into(),
                class: BitmapClass::Tag {
                    field: property.into(),
                    value: value.into(),
                },
                document_id: 0,
            })
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                property = ?property,
                                error = ?err,
                                "Failed to retrieve tag bitmap");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn prepare_set_response<T>(
        &self,
        request: &SetRequest<T>,
        collection: Collection,
    ) -> Result<SetResponse, MethodError> {
        Ok(
            SetResponse::from_request(request, self.core.jmap.set_max_objects)?.with_state(
                self.assert_state(
                    request.account_id.document_id(),
                    collection,
                    &request.if_in_state,
                )
                .await?,
            ),
        )
    }

    pub async fn get_quota(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> Result<i64, MethodError> {
        Ok(if access_token.primary_id == account_id {
            access_token.quota as i64
        } else {
            self.core
                .storage
                .directory
                .query(QueryBy::Id(account_id), false)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "get_quota",
                        account_id = account_id,
                        error = ?err,
                        "Failed to obtain disk quota for account.");
                    MethodError::ServerPartialFail
                })?
                .map(|p| p.quota as i64)
                .unwrap_or_default()
        })
    }

    pub async fn get_used_quota(&self, account_id: u32) -> Result<i64, MethodError> {
        self.core
            .storage
            .data
            .get_counter(DirectoryClass::UsedQuota(account_id))
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "get_used_quota",
                account_id = account_id,
                error = ?err,
                "Failed to obtain used disk quota for account.");
                MethodError::ServerPartialFail
            })
    }

    pub async fn has_available_quota(
        &self,
        account_id: u32,
        account_quota: i64,
        item_size: i64,
    ) -> Result<bool, MethodError> {
        if account_quota == 0 {
            return Ok(true);
        }
        let used_quota = self.get_used_quota(account_id).await?;
        if used_quota + item_size <= account_quota {
            Ok(true)
        } else {
            // Send webhook
            if self
                .core
                .has_webhook_subscribers(WebhookType::AccountOverQuota)
            {
                self.smtp
                    .inner
                    .ipc
                    .send_webhook(
                        WebhookType::AccountOverQuota,
                        WebhookPayload::AccountOverQuota {
                            account_id,
                            quota_limit: account_quota as usize,
                            quota_used: used_quota as usize,
                            object_size: item_size as usize,
                        },
                    )
                    .await;
            }

            Ok(false)
        }
    }

    pub async fn filter(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<Filter>,
    ) -> Result<ResultSet, MethodError> {
        self.core
            .storage
            .data
            .filter(account_id, collection, filters)
            .await
            .map_err(|err| {
                tracing::error!(event = "error",
                                context = "filter",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Failed to execute filter.");

                MethodError::ServerPartialFail
            })
    }

    pub async fn fts_filter<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<FtsFilter<T>>,
    ) -> Result<RoaringBitmap, MethodError> {
        self.core
            .storage
            .fts
            .query(account_id, collection, filters)
            .await
            .map_err(|err| {
                tracing::error!(event = "error",
                                context = "fts-filter",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Failed to execute filter.");

                MethodError::ServerPartialFail
            })
    }

    pub async fn build_query_response<T>(
        &self,
        result_set: &ResultSet,
        request: &QueryRequest<T>,
    ) -> Result<(QueryResponse, Option<Pagination>), MethodError> {
        let total = result_set.results.len() as usize;
        let (limit_total, limit) = if let Some(limit) = request.limit {
            if limit > 0 {
                let limit = std::cmp::min(limit, self.core.jmap.query_max_results);
                (std::cmp::min(limit, total), limit)
            } else {
                (0, 0)
            }
        } else {
            (
                std::cmp::min(self.core.jmap.query_max_results, total),
                self.core.jmap.query_max_results,
            )
        };
        Ok((
            QueryResponse {
                account_id: request.account_id,
                query_state: self
                    .get_state(result_set.account_id, result_set.collection)
                    .await?,
                can_calculate_changes: true,
                position: 0,
                ids: vec![],
                total: if request.calculate_total.unwrap_or(false) {
                    Some(total)
                } else {
                    None
                },
                limit: if total > limit { Some(limit) } else { None },
            },
            if limit_total > 0 {
                Pagination::new(
                    limit_total,
                    request.position.unwrap_or(0),
                    request.anchor.map(|a| a.document_id()),
                    request.anchor_offset.unwrap_or(0),
                )
                .into()
            } else {
                None
            },
        ))
    }

    pub async fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        paginate: Pagination,
        mut response: QueryResponse,
    ) -> Result<QueryResponse, MethodError> {
        // Sort results
        let collection = result_set.collection;
        let account_id = result_set.account_id;
        response.update_results(
            match self
                .core
                .storage
                .data
                .sort(result_set, comparators, paginate)
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Sort failed");
                    return Err(MethodError::ServerPartialFail);
                }
            },
        )?;

        Ok(response)
    }

    pub async fn write_batch(&self, batch: BatchBuilder) -> Result<AssignedIds, MethodError> {
        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .map_err(|err| {
                match err {
                    store::Error::InternalError(err) => {
                        tracing::error!(
                        event = "error",
                        context = "write_batch",
                        error = ?err,
                        "Failed to write batch.");
                        MethodError::ServerPartialFail
                    }
                    store::Error::AssertValueFailed => {
                        // This should not occur, as we are not using assertions.
                        tracing::debug!(
                            event = "assert_failed",
                            context = "write_batch",
                            "Failed to assert value."
                        );
                        MethodError::ServerUnavailable
                    }
                }
            })
    }

    pub async fn write_batch_expect_id(&self, batch: BatchBuilder) -> Result<u32, MethodError> {
        self.write_batch(batch).await.and_then(|ids| {
            ids.last_document_id().map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "write_batch_expect_id",
                    error = ?err,
                    "Failed to obtain last document id."
                );
                MethodError::ServerPartialFail
            })
        })
    }
}

impl Inner {
    pub fn increment_config_version(&self) {
        self.config_version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl From<JmapInstance> for JMAP {
    fn from(value: JmapInstance) -> Self {
        let shared_core = value.core.clone();
        let core = value.core.load().clone();
        JMAP {
            smtp: SMTP {
                core: core.clone(),
                inner: value.smtp_inner,
            },
            core,
            shared_core,
            inner: value.jmap_inner,
        }
    }
}

trait UpdateResults: Sized {
    fn update_results(&mut self, sorted_results: SortedResultSet) -> Result<(), MethodError>;
}

impl UpdateResults for QueryResponse {
    fn update_results(&mut self, sorted_results: SortedResultSet) -> Result<(), MethodError> {
        // Prepare response
        if sorted_results.found_anchor {
            self.position = sorted_results.position;
            self.ids = sorted_results
                .ids
                .into_iter()
                .map(|id| id.into())
                .collect::<Vec<_>>();
            Ok(())
        } else {
            Err(MethodError::AnchorNotFound)
        }
    }
}
