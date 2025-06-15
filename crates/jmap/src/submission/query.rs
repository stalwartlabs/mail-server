/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::submission::UndoStatus;
use jmap_proto::{
    method::query::{
        Comparator, Filter, QueryRequest, QueryResponse, RequestArguments, SortProperty,
    },
    types::{
        collection::{Collection, SyncCollection},
        property::Property,
    },
};
use std::future::Future;
use store::{
    SerializeInfallible,
    query::{self},
};

use crate::{JmapMethods, changes::state::StateManager};

pub trait EmailSubmissionQuery: Sync + Send {
    fn email_submission_query(
        &self,
        request: QueryRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl EmailSubmissionQuery for Server {
    async fn email_submission_query(
        &self,
        mut request: QueryRequest<RequestArguments>,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::IdentityIds(ids) => {
                    filters.push(query::Filter::Or);
                    for id in ids {
                        filters.push(query::Filter::eq(
                            Property::IdentityId,
                            id.document_id().serialize(),
                        ));
                    }
                    filters.push(query::Filter::End);
                }
                Filter::EmailIds(ids) => {
                    filters.push(query::Filter::Or);
                    for id in ids {
                        filters.push(query::Filter::eq(Property::EmailId, id.id().serialize()));
                    }
                    filters.push(query::Filter::End);
                }
                Filter::ThreadIds(ids) => {
                    filters.push(query::Filter::Or);
                    for id in ids {
                        filters.push(query::Filter::eq(
                            Property::ThreadId,
                            id.document_id().serialize(),
                        ));
                    }
                    filters.push(query::Filter::End);
                }
                Filter::UndoStatus(undo_status) => filters.push(query::Filter::eq(
                    Property::UndoStatus,
                    UndoStatus::parse(&undo_status)
                        .unwrap_or(UndoStatus::Pending)
                        .as_index()
                        .serialize(),
                )),
                Filter::Before(before) => filters.push(query::Filter::lt(
                    Property::SendAt,
                    (before.timestamp() as u64).serialize(),
                )),
                Filter::After(after) => filters.push(query::Filter::gt(
                    Property::SendAt,
                    (after.timestamp() as u64).serialize(),
                )),
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
                other => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details(other.to_string()));
                }
            }
        }

        let result_set = self
            .filter(account_id, Collection::EmailSubmission, filters)
            .await?;

        let (response, paginate) = self
            .build_query_response(
                &result_set,
                self.get_state(account_id, SyncCollection::EmailSubmission)
                    .await?,
                &request,
            )
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::descending(SortProperty::SentAt)])
            {
                comparators.push(match comparator.property {
                    SortProperty::EmailId => {
                        query::Comparator::field(Property::EmailId, comparator.is_ascending)
                    }
                    SortProperty::ThreadId => {
                        query::Comparator::field(Property::ThreadId, comparator.is_ascending)
                    }
                    SortProperty::SentAt => {
                        query::Comparator::field(Property::SendAt, comparator.is_ascending)
                    }
                    other => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(other.to_string()));
                    }
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }
    }
}
