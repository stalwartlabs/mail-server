/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::MessageCacheState};
use common::{Server, auth::AccessToken, config::jmap::settings::SpecialUse};
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse, SortProperty},
    object::mailbox::QueryArguments,
    types::{acl::Acl, collection::Collection},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};
use store::{
    query::{self},
    roaring::RoaringBitmap,
};

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
        let mailboxes = self.get_cached_messages(account_id).await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::ParentId(parent_id) => {
                    let parent_id = parent_id.map(|id| id.document_id()).unwrap_or(u32::MAX);
                    filters.push(query::Filter::is_in_set(
                        mailboxes
                            .mailboxes
                            .items
                            .iter()
                            .filter(|mailbox| mailbox.parent_id == parent_id)
                            .map(|m| m.document_id)
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
                    let name = name.to_lowercase();
                    filters.push(query::Filter::is_in_set(
                        mailboxes
                            .mailboxes
                            .items
                            .iter()
                            .filter(|mailbox| mailbox.name.to_lowercase().contains(&name))
                            .map(|m| m.document_id)
                            .collect::<RoaringBitmap>(),
                    ));
                }
                Filter::Role(role) => {
                    if let Some(role) = role {
                        filters.push(query::Filter::is_in_set(
                            mailboxes
                                .mailboxes
                                .items
                                .iter()
                                .filter(|mailbox| mailbox.role.as_str().is_some_and(|r| r == role))
                                .map(|m| m.document_id)
                                .collect::<RoaringBitmap>(),
                        ));
                    } else {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_set(
                            mailboxes
                                .mailboxes
                                .items
                                .iter()
                                .filter(|mailbox| matches!(mailbox.role, SpecialUse::None))
                                .map(|m| m.document_id)
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
                            .mailboxes
                            .items
                            .iter()
                            .filter(|mailbox| !matches!(mailbox.role, SpecialUse::None))
                            .map(|m| m.document_id)
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
                            .mailboxes
                            .items
                            .iter()
                            .filter(|mailbox| {
                                mailbox.subscribers.contains(&access_token.primary_id)
                            })
                            .map(|m| m.document_id)
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
            result_set.apply_mask(mailboxes.shared_mailboxes(access_token, Acl::Read));
        }
        let (mut response, mut paginate) = self
            .build_query_response(&result_set, mailboxes.get_state(true), &request)
            .await?;

        // Filter as tree
        if filter_as_tree {
            let mut filtered_ids = RoaringBitmap::new();

            for document_id in &result_set.results {
                let mut check_id = document_id;
                for _ in 0..self.core.jmap.mailbox_max_depth {
                    if let Some(mailbox) = mailboxes.mailbox_by_id(&check_id) {
                        if let Some(parent_id) = mailbox.parent_id() {
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

        if let Some(paginate) = paginate {
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));

            // Sort as tree
            if sort_as_tree {
                let sorted_list = mailboxes
                    .mailboxes
                    .items
                    .iter()
                    .map(|mailbox| (mailbox.path.as_str(), mailbox.document_id))
                    .collect::<BTreeMap<_, _>>();
                comparators.push(query::Comparator::sorted_list(
                    sorted_list.into_values().collect(),
                    true,
                ));
            }

            // Parse sort criteria
            for comparator in request
                .sort
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| vec![Comparator::ascending(SortProperty::ParentId)])
            {
                comparators.push(match comparator.property {
                    SortProperty::Name => {
                        let sorted_list = mailboxes
                            .mailboxes
                            .items
                            .iter()
                            .map(|mailbox| (mailbox.name.as_str(), mailbox.document_id))
                            .collect::<BTreeSet<_>>();

                        query::Comparator::sorted_list(
                            sorted_list.into_iter().map(|v| v.1).collect(),
                            comparator.is_ascending,
                        )
                    }
                    SortProperty::SortOrder => {
                        let sorted_list = mailboxes
                            .mailboxes
                            .items
                            .iter()
                            .map(|mailbox| (mailbox.sort_order, mailbox.document_id))
                            .collect::<BTreeSet<_>>();

                        query::Comparator::sorted_list(
                            sorted_list.into_iter().map(|v| v.1).collect(),
                            comparator.is_ascending,
                        )
                    }
                    SortProperty::ParentId => {
                        let sorted_list = mailboxes
                            .mailboxes
                            .items
                            .iter()
                            .map(|mailbox| {
                                (
                                    mailbox.parent_id().map(|id| id + 1).unwrap_or_default(),
                                    mailbox.document_id,
                                )
                            })
                            .collect::<BTreeSet<_>>();

                        query::Comparator::sorted_list(
                            sorted_list.into_iter().map(|v| v.1).collect(),
                            comparator.is_ascending,
                        )
                    }

                    other => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(other.to_string()));
                    }
                });
            }

            response = self
                .sort(result_set, comparators, paginate, response)
                .await?;
        }

        Ok(response)
    }
}
