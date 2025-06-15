/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use common::Server;
use jmap_proto::{
    method::{
        query::{QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    types::{collection::Collection, state::State},
};
use std::{fmt::Display, future::Future};
use store::{
    fts::FtsFilter,
    query::{Comparator, Filter, ResultSet, SortedResultSet, sort::Pagination},
    roaring::RoaringBitmap,
};
use trc::AddContext;

pub mod api;
pub mod blob;
pub mod changes;
pub mod email;
pub mod identity;
pub mod mailbox;
pub mod principal;
pub mod push;
pub mod quota;
pub mod sieve;
pub mod submission;
pub mod thread;
pub mod vacation;
pub mod websocket;

impl JmapMethods for Server {
    async fn prepare_set_response<T: Sync + Send>(
        &self,
        request: &SetRequest<T>,
        asserted_state: State,
    ) -> trc::Result<SetResponse> {
        Ok(
            SetResponse::from_request(request, self.core.jmap.set_max_objects)?
                .with_state(asserted_state),
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
        query_state: State,
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
                query_state,
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
        paginate: Pagination<'_>,
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
}

pub trait JmapMethods: Sync + Send {
    fn prepare_set_response<T: Sync + Send>(
        &self,
        request: &SetRequest<T>,
        asserted_state: State,
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
        query_state: State,
        request: &QueryRequest<T>,
    ) -> impl Future<Output = trc::Result<(QueryResponse, Option<Pagination>)>> + Send;

    fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        paginate: Pagination,
        response: QueryResponse,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
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
