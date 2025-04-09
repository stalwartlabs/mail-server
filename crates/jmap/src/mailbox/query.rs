/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, config::jmap::settings::SpecialUse};
use email::mailbox::cache::MessageMailboxCache;
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse, SortProperty},
    object::mailbox::QueryArguments,
    types::{acl::Acl, collection::Collection, property::Property},
};
use store::{
    ahash::AHashSet,
    query::{self, sort::Pagination},
    roaring::RoaringBitmap,
};

use crate::{JmapMethods, UpdateResults};
use std::{collections::BTreeMap, future::Future};

pub trait MailboxQuery: Sync + Send {
    fn mailbox_query(
        &self,
        request: QueryRequest<QueryArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl MailboxQuery for Server {
    async fn mailbox_query(
        &self,
        mut request: QueryRequest<QueryArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let sort_as_tree = request.arguments.sort_as_tree.unwrap_or(false);
        let filter_as_tree = request.arguments.filter_as_tree.unwrap_or(false);
        let mut filters = Vec::with_capacity(request.filter.len());
        let mailboxes = self.get_cached_mailboxes(account_id).await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::ParentId(parent_id) => {
                    let parent_id = parent_id.map(|id| id.document_id());
                    filters.push(query::Filter::is_in_set(
                        mailboxes
                            .items
                            .iter()
                            .filter(|(_, mailbox)| mailbox.parent_id == parent_id)
                            .map(|(id, _)| id)
                            .collect::<RoaringBitmap>(),
                    ));
                }
                Filter::Name(name) => {
                    #[cfg(feature = "test_mode")]
                    {
                        // Used for concurrent requests tests
                        if name == "__sleep" {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                    filters.push(query::Filter::is_in_set(
                        mailboxes
                            .items
                            .iter()
                            .filter(|(_, mailbox)| mailbox.name.contains(&name))
                            .map(|(id, _)| id)
                            .collect::<RoaringBitmap>(),
                    ));
                }
                Filter::Role(role) => {
                    if let Some(role) = role {
                        filters.push(query::Filter::is_in_set(
                            mailboxes
                                .items
                                .iter()
                                .filter(|(_, mailbox)| {
                                    mailbox.role.as_str().is_some_and(|r| r == role)
                                })
                                .map(|(id, _)| id)
                                .collect::<RoaringBitmap>(),
                        ));
                    } else {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_set(
                            mailboxes
                                .items
                                .iter()
                                .filter(|(_, mailbox)| matches!(mailbox.role, SpecialUse::None))
                                .map(|(id, _)| id)
                                .collect::<RoaringBitmap>(),
                        ));
                        filters.push(query::Filter::End);
                    }
                }
                Filter::HasAnyRole(has_role) => {
                    if !has_role {
                        filters.push(query::Filter::Not);
                    }
                    filters.push(query::Filter::is_in_set(
                        mailboxes
                            .items
                            .iter()
                            .filter(|(_, mailbox)| matches!(mailbox.role, SpecialUse::None))
                            .map(|(id, _)| id)
                            .collect::<RoaringBitmap>(),
                    ));
                    if !has_role {
                        filters.push(query::Filter::End);
                    }
                }
                Filter::IsSubscribed(is_subscribed) => {
                    if !is_subscribed {
                        filters.push(query::Filter::Not);
                    }
                    filters.push(query::Filter::is_in_set(
                        mailboxes
                            .items
                            .iter()
                            .filter(|(_, mailbox)| {
                                mailbox.subscribers.contains(&access_token.primary_id)
                            })
                            .map(|(id, _)| id)
                            .collect::<RoaringBitmap>(),
                    ));
                    if !is_subscribed {
                        filters.push(query::Filter::End);
                    }
                }
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

        let mut result_set = self
            .filter(account_id, Collection::Mailbox, filters)
            .await?;
        if access_token.is_shared(account_id) {
            result_set.apply_mask(
                self.shared_containers(access_token, account_id, Collection::Mailbox, Acl::Read)
                    .await?,
            );
        }
        let (mut response, mut paginate) = self.build_query_response(&result_set, &request).await?;

        // Filter as tree
        if filter_as_tree {
            let mut filtered_ids = RoaringBitmap::new();

            for document_id in &result_set.results {
                let mut check_id = document_id;
                for _ in 0..self.core.jmap.mailbox_max_depth {
                    if let Some(mailbox) = mailboxes.items.get(&check_id) {
                        if let Some(parent_id) = mailbox.parent_id {
                            if result_set.results.contains(parent_id) {
                                check_id = parent_id;
                            } else {
                                break;
                            }
                        } else {
                            filtered_ids.insert(document_id);
                        }
                    }
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

        if let Some(mut paginate) = paginate {
            let todo = "sort from cache";
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

                    other => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(other.to_string()));
                    }
                });
            }

            // Sort as tree
            if sort_as_tree {
                let dummy_paginate = Pagination::new(result_set.results.len() as usize, 0, None, 0);
                response = self
                    .sort(result_set, comparators, dummy_paginate, response)
                    .await?;
                let sorted_tree = mailboxes
                    .items
                    .iter()
                    .map(|(id, mailbox)| (mailbox.path.as_str(), *id))
                    .collect::<BTreeMap<_, _>>();
                let ids = response
                    .ids
                    .iter()
                    .map(|id| id.document_id())
                    .collect::<AHashSet<_>>();

                for (_, document_id) in sorted_tree {
                    if ids.contains(&document_id) && !paginate.add(0, document_id) {
                        break;
                    }
                }

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
