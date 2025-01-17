/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, future::Future, sync::Arc, time::Duration};

use changes::state::StateManager;
use common::{
    manager::boot::{BootManager, IpcReceivers},
    Inner, Server,
};
use jmap_proto::{
    method::{
        query::{QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    types::collection::Collection,
};
use services::{
    housekeeper::spawn_housekeeper, index::spawn_email_queue_task, state::spawn_state_manager,
};

use store::{
    fts::FtsFilter,
    query::{sort::Pagination, Comparator, Filter, ResultSet, SortedResultSet},
    roaring::RoaringBitmap,
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
        // Spawn state manager
        spawn_state_manager(inner.clone(), self.state_rx.take().unwrap());

        // Spawn housekeeper
        spawn_housekeeper(inner.clone(), self.housekeeper_rx.take().unwrap());

        // Spawn index task
        spawn_email_queue_task(inner);
    }
}

impl JmapMethods for Server {
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

    fn increment_config_version(&self) {
        self.inner
            .data
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub trait JmapMethods: Sync + Send {
    fn prepare_set_response<T: Sync + Send>(
        &self,
        request: &SetRequest<T>,
        collection: Collection,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;

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
