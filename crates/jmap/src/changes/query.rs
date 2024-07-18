/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::method::{
    changes::{self, ChangesRequest},
    query::{self, QueryRequest},
    query_changes::{AddedItem, QueryChangesRequest, QueryChangesResponse},
};

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn query_changes(
        &self,
        request: QueryChangesRequest,
        access_token: &AccessToken,
    ) -> trc::Result<QueryChangesResponse> {
        // Query changes
        let changes = self
            .changes(
                ChangesRequest {
                    account_id: request.account_id,
                    since_state: request.since_query_state.clone(),
                    max_changes: request.max_changes,
                    arguments: match &request.arguments {
                        query::RequestArguments::Email(_) => changes::RequestArguments::Email,
                        query::RequestArguments::Mailbox(_) => changes::RequestArguments::Mailbox,
                        query::RequestArguments::EmailSubmission => {
                            changes::RequestArguments::EmailSubmission
                        }
                        query::RequestArguments::Quota => changes::RequestArguments::Quota,
                        _ => {
                            return Err(trc::JmapCause::UnknownMethod
                                .into_err()
                                .details("Unknown method"))
                        }
                    },
                },
                access_token,
            )
            .await?;
        let calculate_total = request.calculate_total.unwrap_or(false);
        let has_changes = changes.has_changes();
        let mut response = QueryChangesResponse {
            account_id: request.account_id,
            old_query_state: changes.old_state,
            new_query_state: changes.new_state,
            total: None,
            removed: vec![],
            added: vec![],
        };

        if has_changes || calculate_total {
            let query = QueryRequest {
                account_id: request.account_id,
                filter: request.filter,
                sort: request.sort,
                position: None,
                anchor: None,
                anchor_offset: None,
                limit: None,
                calculate_total: request.calculate_total,
                arguments: query::RequestArguments::EmailSubmission,
            };
            let is_mutable = query.filter.iter().any(|f| !f.is_immutable())
                || query
                    .sort
                    .as_ref()
                    .map_or(false, |sort| sort.iter().any(|s| !s.is_immutable()));
            let results = match request.arguments {
                query::RequestArguments::Email(arguments) => {
                    self.email_query(query.with_arguments(arguments), access_token)
                        .await?
                }
                query::RequestArguments::Mailbox(arguments) => {
                    self.mailbox_query(query.with_arguments(arguments), access_token)
                        .await?
                }
                query::RequestArguments::EmailSubmission => {
                    self.email_submission_query(query).await?
                }
                query::RequestArguments::Quota => self.quota_query(query, access_token).await?,
                _ => unreachable!(),
            };

            if has_changes {
                if is_mutable {
                    for (index, id) in results.ids.into_iter().enumerate() {
                        if matches!(request.up_to_id, Some(up_to_id) if up_to_id == id) {
                            break;
                        } else if changes.created.contains(&id) || changes.updated.contains(&id) {
                            response.added.push(AddedItem::new(id, index));
                        }
                    }

                    response.removed = changes.updated;
                } else {
                    for (index, id) in results.ids.into_iter().enumerate() {
                        if matches!(request.up_to_id, Some(up_to_id) if up_to_id == id) {
                            break;
                        } else if changes.created.contains(&id) {
                            response.added.push(AddedItem::new(id, index));
                        }
                    }
                }

                if !changes.destroyed.is_empty() {
                    response.removed.extend(changes.destroyed);
                }
            }
            response.total = results.total;
        }

        Ok(response)
    }
}
