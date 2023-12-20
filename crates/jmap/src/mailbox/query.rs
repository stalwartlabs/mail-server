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
    method::query::{Comparator, Filter, QueryRequest, QueryResponse, SortProperty},
    object::{mailbox::QueryArguments, Object},
    types::{acl::Acl, collection::Collection, property::Property, value::Value},
};
use store::{
    ahash::{AHashMap, AHashSet},
    query::{self, sort::Pagination},
    roaring::RoaringBitmap,
};

use crate::{auth::AccessToken, UpdateResults, JMAP};

impl JMAP {
    pub async fn mailbox_query(
        &self,
        mut request: QueryRequest<QueryArguments>,
        access_token: &AccessToken,
    ) -> Result<QueryResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let sort_as_tree = request.arguments.sort_as_tree.unwrap_or(false);
        let filter_as_tree = request.arguments.filter_as_tree.unwrap_or(false);
        let mut filters = Vec::with_capacity(request.filter.len());
        let mailbox_ids = self.mailbox_get_or_create(account_id).await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::ParentId(parent_id) => filters.push(query::Filter::eq(
                    Property::ParentId,
                    parent_id.map(|id| id.document_id() + 1).unwrap_or(0),
                )),
                Filter::Name(name) => {
                    #[cfg(feature = "test_mode")]
                    {
                        // Used for concurrent requests tests
                        if name == "__sleep" {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                    filters.push(query::Filter::has_text(Property::Name, &name));
                }
                Filter::Role(role) => {
                    if let Some(role) = role {
                        filters.push(query::Filter::eq(Property::Role, role));
                    } else {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(Property::Role, ()));
                        filters.push(query::Filter::End);
                    }
                }
                Filter::HasAnyRole(has_role) => {
                    if !has_role {
                        filters.push(query::Filter::Not);
                    }
                    filters.push(query::Filter::is_in_bitmap(Property::Role, ()));
                    if !has_role {
                        filters.push(query::Filter::End);
                    }
                }
                Filter::IsSubscribed(is_subscribed) => {
                    if !is_subscribed {
                        filters.push(query::Filter::Not);
                    }
                    filters.push(query::Filter::eq(
                        Property::IsSubscribed,
                        access_token.primary_id,
                    ));
                    if !is_subscribed {
                        filters.push(query::Filter::End);
                    }
                }
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }

                other => return Err(MethodError::UnsupportedFilter(other.to_string())),
            }
        }

        let mut result_set = self
            .filter(account_id, Collection::Mailbox, filters)
            .await?;
        if access_token.is_shared(account_id) {
            result_set.apply_mask(
                self.shared_documents(access_token, account_id, Collection::Mailbox, Acl::Read)
                    .await?,
            );
        }
        let (mut response, mut paginate) = self.build_query_response(&result_set, &request).await?;

        // Build mailbox tree
        let mut hierarchy = AHashMap::default();
        let mut tree = AHashMap::default();
        if (filter_as_tree || sort_as_tree)
            && (paginate.is_some()
                || (response.total.map_or(false, |total| total > 0) && filter_as_tree))
        {
            for document_id in mailbox_ids {
                let parent_id = self
                    .get_property::<Object<Value>>(
                        account_id,
                        Collection::Mailbox,
                        document_id,
                        Property::Value,
                    )
                    .await?
                    .and_then(|o| {
                        o.properties
                            .get(&Property::ParentId)
                            .and_then(|id| id.as_id().map(|id| id.document_id()))
                    })
                    .unwrap_or(0);
                hierarchy.insert(document_id + 1, parent_id);
                tree.entry(parent_id)
                    .or_insert_with(AHashSet::default)
                    .insert(document_id + 1);
            }

            if filter_as_tree {
                let mut filtered_ids = RoaringBitmap::new();

                for document_id in &result_set.results {
                    let mut keep = false;
                    let mut jmap_id = document_id + 1;

                    for _ in 0..self.config.mailbox_max_depth {
                        if let Some(&parent_id) = hierarchy.get(&jmap_id) {
                            if parent_id == 0 {
                                keep = true;
                                break;
                            } else if !result_set.results.contains(parent_id - 1) {
                                break;
                            } else {
                                jmap_id = parent_id;
                            }
                        } else {
                            break;
                        }
                    }

                    if keep {
                        filtered_ids.push(document_id);
                    }
                }
                if filtered_ids.len() != result_set.results.len() {
                    let total = filtered_ids.len() as usize;
                    if response.total.is_some() {
                        response.total = Some(total);
                    }
                    if let Some(paginate) = &mut paginate {
                        if paginate.limit > total {
                            paginate.limit = total;
                        }
                    }
                    result_set.results = filtered_ids;
                }
            }
        }

        if let Some(mut paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::ascending(SortProperty::ParentId)])
            {
                comparators.push(match comparator.property {
                    SortProperty::Name => {
                        query::Comparator::field(Property::Name, comparator.is_ascending)
                    }
                    SortProperty::SortOrder => {
                        query::Comparator::field(Property::SortOrder, comparator.is_ascending)
                    }
                    SortProperty::ParentId => {
                        query::Comparator::field(Property::ParentId, comparator.is_ascending)
                    }

                    other => return Err(MethodError::UnsupportedSort(other.to_string())),
                });
            }

            // Sort as tree
            if sort_as_tree {
                let dummy_paginate = Pagination::new(result_set.results.len() as usize, 0, None, 0);
                response = self
                    .sort(result_set, comparators, dummy_paginate, response)
                    .await?;

                let mut stack = Vec::new();
                let mut jmap_id = 0;

                'outer: for _ in 0..(response.ids.len() * 10 * self.config.mailbox_max_depth) {
                    let (mut children, mut it) = if let Some(children) = tree.remove(&jmap_id) {
                        (children, response.ids.iter())
                    } else if let Some(prev) = stack.pop() {
                        prev
                    } else {
                        break;
                    };

                    while let Some(&id) = it.next() {
                        jmap_id = id.document_id() + 1;
                        if children.remove(&jmap_id) {
                            if !paginate.add(0, id.document_id()) {
                                break 'outer;
                            } else {
                                stack.push((children, it));
                                continue 'outer;
                            }
                        }
                    }

                    if !children.is_empty() {
                        jmap_id = *children.iter().next().unwrap();
                        children.remove(&jmap_id);
                        stack.push((children, it));
                    }
                }
                debug_assert_eq!(response.ids.len(), paginate.ids.len(), "{tree:#?}");
                response.update_results(paginate.build())?;
            } else {
                response = self
                    .sort(result_set, comparators, paginate, response)
                    .await?;
            }
        }

        Ok(response)
    }
}
