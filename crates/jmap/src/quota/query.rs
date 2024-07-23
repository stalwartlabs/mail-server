/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    method::query::{QueryRequest, QueryResponse, RequestArguments},
    types::{id::Id, state::State},
};

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn quota_query(
        &self,
        request: QueryRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        Ok(QueryResponse {
            account_id: request.account_id,
            query_state: State::Initial,
            can_calculate_changes: false,
            position: 0,
            ids: if access_token.quota > 0 {
                vec![Id::new(0)]
            } else {
                vec![]
            },
            total: Some(1),
            limit: None,
        })

        /*

        let account_id = request.account_id.document_id();

        let mut filters = Vec::with_capacity(request.filter.len());

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Name(value) => filters.push(query::Filter::has_text(
                    Property::Name,
                    &value,
                    Language::None,
                )),
                Filter::Type(value) => filters.push(query::Filter::has_text(
                    Property::Type,
                    &value,
                    Language::None,
                )),
                Filter::Scope(value) => filters.push(query::Filter::has_text(
                    Property::Scope,
                    &value,
                    Language::None,
                )),
                Filter::ResourceType(value) => filters.push(query::Filter::has_text(
                    Property::ResourceType,
                    &value,
                    Language::None,
                )),
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
                other => return Err(trc::JmapEvent::UnsupportedFilter.into_err().details(other.to_string())),
            }
        }

        let result_set = self
            .filter(account_id, Collection::Quota, filters)
            .await?;

        let (response, paginate) = self.build_query_response(&result_set, &request).await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::descending(SortProperty::Name)])
            {
                comparators.push(match comparator.property {
                    SortProperty::Name => {
                        query::Comparator::field(Property::Name, comparator.is_ascending)
                    }
                    SortProperty::Used => {
                        query::Comparator::field(Property::Used, comparator.is_ascending)
                    }
                    other => return Err(trc::JmapEvent::UnsupportedSort.into_err().details(other.to_string())),
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }*/
    }
}
