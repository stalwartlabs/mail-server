/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, future::Future, sync::Arc, time::Duration};

use changes::state::StateManager;
use common::{
    auth::{AccessToken, ResourceToken, TenantInfo},
    manager::boot::{BootManager, IpcReceivers},
    Inner, Server,
};
use directory::QueryBy;
use jmap_proto::{
    method::{
        query::{QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    types::{collection::Collection, property::Property},
};
use services::{
    delivery::spawn_delivery_manager, housekeeper::spawn_housekeeper, index::spawn_index_task,
    state::spawn_state_manager,
};

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
use trc::AddContext;

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

pub trait StartServices: Sync + Send {
    fn start_services(&mut self) -> impl Future<Output = ()> + Send;
}

pub trait SpawnServices {
    fn spawn_services(&mut self, inner: Arc<Inner>);
}

impl StartServices for BootManager {
    async fn start_services(&mut self) {
        // Unpack webadmin
        if let Err(err) = self
            .inner
            .data
            .webadmin
            .unpack(&self.inner.shared_core.load().storage.blob)
            .await
        {
            trc::event!(
                Resource(trc::ResourceEvent::Error),
                Reason = err,
                Details = "Failed to unpack webadmin bundle"
            );
        }

        self.ipc_rxs.spawn_services(self.inner.clone());
    }
}

impl SpawnServices for IpcReceivers {
    fn spawn_services(&mut self, inner: Arc<Inner>) {
        // Spawn delivery manager
        spawn_delivery_manager(inner.clone(), self.delivery_rx.take().unwrap());

        // Spawn state manager
        spawn_state_manager(inner.clone(), self.state_rx.take().unwrap());

        // Spawn housekeeper
        spawn_housekeeper(inner.clone(), self.housekeeper_rx.take().unwrap());

        // Spawn index task
        spawn_index_task(inner);
    }
}

impl JmapMethods for Server {
    async fn get_property<U>(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        property: impl AsRef<Property> + Sync + Send,
    ) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let property = property.as_ref();

        self.core
            .storage
            .data
            .get_value::<U>(ValueKey {
                account_id,
                collection: collection.into(),
                document_id,
                class: ValueClass::Property(property.into()),
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .document_id(document_id)
                    .id(property.to_string())
            })
    }

    async fn get_properties<U, I, P>(
        &self,
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
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .id(property.to_string())
            })
            .map(|_| results)
    }

    async fn get_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> trc::Result<Option<RoaringBitmap>> {
        self.core
            .storage
            .data
            .get_bitmap(BitmapKey::document_ids(account_id, collection))
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    async fn get_tag(
        &self,
        account_id: u32,
        collection: Collection,
        property: impl AsRef<Property> + Sync + Send,
        value: impl Into<TagValue<u32>> + Sync + Send,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let property = property.as_ref();
        self.core
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
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .id(property.to_string())
            })
    }

    async fn prepare_set_response<T: Sync + Send>(
        &self,
        request: &SetRequest<T>,
        collection: Collection,
    ) -> trc::Result<SetResponse> {
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

    async fn get_resource_token(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<ResourceToken> {
        Ok(if access_token.primary_id == account_id {
            ResourceToken {
                account_id,
                quota: access_token.quota,
                tenant: access_token.tenant,
            }
        } else {
            let mut quotas = ResourceToken {
                account_id,
                ..Default::default()
            };

            if let Some(principal) = self
                .core
                .storage
                .directory
                .query(QueryBy::Id(account_id), false)
                .await
                .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))?
            {
                quotas.quota = principal.quota();

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() {
                    if let Some(tenant_id) = principal.tenant() {
                        quotas.tenant = TenantInfo {
                            id: tenant_id,
                            quota: self
                                .core
                                .storage
                                .directory
                                .query(QueryBy::Id(tenant_id), false)
                                .await
                                .add_context(|err| {
                                    err.caused_by(trc::location!()).account_id(tenant_id)
                                })?
                                .map(|tenant| tenant.quota())
                                .unwrap_or_default(),
                        }
                        .into();
                    }
                }

                // SPDX-SnippetEnd
            }

            quotas
        })
    }

    async fn get_used_quota(&self, account_id: u32) -> trc::Result<i64> {
        self.core
            .storage
            .data
            .get_counter(DirectoryClass::UsedQuota(account_id))
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))
    }

    async fn has_available_quota(&self, quotas: &ResourceToken, item_size: u64) -> trc::Result<()> {
        if quotas.quota != 0 {
            let used_quota = self.get_used_quota(quotas.account_id).await? as u64;

            if used_quota + item_size > quotas.quota {
                return Err(trc::LimitEvent::Quota
                    .into_err()
                    .ctx(trc::Key::Limit, quotas.quota)
                    .ctx(trc::Key::Size, used_quota));
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            if let Some(tenant) = quotas.tenant.filter(|tenant| tenant.quota != 0) {
                let used_quota = self.get_used_quota(tenant.id).await? as u64;

                if used_quota + item_size > tenant.quota {
                    return Err(trc::LimitEvent::TenantQuota
                        .into_err()
                        .ctx(trc::Key::Limit, tenant.quota)
                        .ctx(trc::Key::Size, used_quota));
                }
            }
        }

        // SPDX-SnippetEnd

        Ok(())
    }

    async fn filter(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<Filter>,
    ) -> trc::Result<ResultSet> {
        self.core
            .storage
            .data
            .filter(account_id, collection, filters)
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    async fn fts_filter<T: Into<u8> + Display + Clone + std::fmt::Debug + Sync + Send>(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<FtsFilter<T>>,
    ) -> trc::Result<RoaringBitmap> {
        self.core
            .storage
            .fts
            .query(account_id, collection, filters)
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    async fn build_query_response<T: Sync + Send>(
        &self,
        result_set: &ResultSet,
        request: &QueryRequest<T>,
    ) -> trc::Result<(QueryResponse, Option<Pagination>)> {
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

    async fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        paginate: Pagination,
        mut response: QueryResponse,
    ) -> trc::Result<QueryResponse> {
        // Sort results
        let collection = result_set.collection;
        let account_id = result_set.account_id;
        response.update_results(
            self.core
                .storage
                .data
                .sort(result_set, comparators, paginate)
                .await
                .add_context(|err| {
                    err.caused_by(trc::location!())
                        .account_id(account_id)
                        .collection(collection)
                })?,
        )?;

        Ok(response)
    }

    async fn write_batch(&self, batch: BatchBuilder) -> trc::Result<AssignedIds> {
        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .caused_by(trc::location!())
    }

    async fn write_batch_expect_id(&self, batch: BatchBuilder) -> trc::Result<u32> {
        self.write_batch(batch)
            .await
            .and_then(|ids| ids.last_document_id().caused_by(trc::location!()))
    }

    fn increment_config_version(&self) {
        self.inner
            .data
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub trait JmapMethods: Sync + Send {
    fn get_property<U>(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        property: impl AsRef<Property> + Sync + Send,
    ) -> impl Future<Output = trc::Result<Option<U>>> + Send
    where
        U: Deserialize + 'static;

    fn get_properties<U, I, P>(
        &self,
        account_id: u32,
        collection: Collection,
        iterate: &I,
        property: P,
    ) -> impl Future<Output = trc::Result<Vec<(u32, U)>>> + Send
    where
        I: DocumentSet + Send + Sync,
        P: AsRef<Property> + Sync + Send,
        U: Deserialize + 'static;

    fn get_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> impl Future<Output = trc::Result<Option<RoaringBitmap>>> + Send;

    fn get_tag(
        &self,
        account_id: u32,
        collection: Collection,
        property: impl AsRef<Property> + Sync + Send,
        value: impl Into<TagValue<u32>> + Sync + Send,
    ) -> impl Future<Output = trc::Result<Option<RoaringBitmap>>> + Send;

    fn prepare_set_response<T: Sync + Send>(
        &self,
        request: &SetRequest<T>,
        collection: Collection,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;

    fn get_resource_token(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<ResourceToken>> + Send;

    fn get_used_quota(&self, account_id: u32) -> impl Future<Output = trc::Result<i64>> + Send;

    fn has_available_quota(
        &self,
        quotas: &ResourceToken,
        item_size: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn filter(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<Filter>,
    ) -> impl Future<Output = trc::Result<ResultSet>> + Send;

    fn fts_filter<T: Into<u8> + Display + Clone + std::fmt::Debug + Sync + Send>(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<FtsFilter<T>>,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn build_query_response<T: Sync + Send>(
        &self,
        result_set: &ResultSet,
        request: &QueryRequest<T>,
    ) -> impl Future<Output = trc::Result<(QueryResponse, Option<Pagination>)>> + Send;

    fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        paginate: Pagination,
        response: QueryResponse,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;

    fn write_batch(
        &self,
        batch: BatchBuilder,
    ) -> impl Future<Output = trc::Result<AssignedIds>> + Send;

    fn write_batch_expect_id(
        &self,
        batch: BatchBuilder,
    ) -> impl Future<Output = trc::Result<u32>> + Send;

    fn increment_config_version(&self);
}

trait UpdateResults: Sized {
    fn update_results(&mut self, sorted_results: SortedResultSet) -> trc::Result<()>;
}

impl UpdateResults for QueryResponse {
    fn update_results(&mut self, sorted_results: SortedResultSet) -> trc::Result<()> {
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
            Err(trc::JmapEvent::AnchorNotFound.into_err())
        }
    }
}
