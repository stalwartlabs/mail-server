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

use jmap_proto::{
    error::method::MethodError,
    method::query::{
        Comparator, Filter, QueryRequest, QueryResponse, RequestArguments, SortProperty,
    },
    types::{collection::Collection, property::Property},
};
use store::query::{self};

use crate::JMAP;

impl JMAP {
    pub async fn email_submission_query(
        &self,
        mut request: QueryRequest<RequestArguments>,
    ) -> Result<QueryResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::IdentityIds(ids) => {
                    filters.push(query::Filter::Or);
                    for id in ids {
                        filters.push(query::Filter::eq(Property::IdentityId, id.document_id()));
                    }
                    filters.push(query::Filter::End);
                }
                Filter::EmailIds(ids) => {
                    filters.push(query::Filter::Or);
                    for id in ids {
                        filters.push(query::Filter::eq(Property::EmailId, id.id()));
                    }
                    filters.push(query::Filter::End);
                }
                Filter::ThreadIds(ids) => {
                    filters.push(query::Filter::Or);
                    for id in ids {
                        filters.push(query::Filter::eq(Property::ThreadId, id.document_id()));
                    }
                    filters.push(query::Filter::End);
                }
                Filter::UndoStatus(undo_status) => {
                    filters.push(query::Filter::eq(Property::UndoStatus, undo_status))
                }
                Filter::Before(before) => filters.push(query::Filter::lt(
                    Property::SendAt,
                    before.timestamp() as u64,
                )),
                Filter::After(after) => filters.push(query::Filter::gt(
                    Property::SendAt,
                    after.timestamp() as u64,
                )),
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
                other => return Err(MethodError::UnsupportedFilter(other.to_string())),
            }
        }

        let result_set = self
            .filter(account_id, Collection::EmailSubmission, filters)
            .await?;

        let (response, paginate) = self.build_query_response(&result_set, &request).await?;

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
                    other => return Err(MethodError::UnsupportedSort(other.to_string())),
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }
    }
}
