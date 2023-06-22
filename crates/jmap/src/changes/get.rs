/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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
    method::changes::{ChangesRequest, ChangesResponse, RequestArguments},
    types::{collection::Collection, property::Property, state::State},
};
use store::query::log::{Change, Changes, Query};

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn changes(
        &self,
        request: ChangesRequest,
        access_token: &AccessToken,
    ) -> Result<ChangesResponse, MethodError> {
        // Map collection and validate ACLs
        let collection = match request.arguments {
            RequestArguments::Email => {
                access_token.assert_has_access(request.account_id, Collection::Email)?;
                Collection::Email
            }
            RequestArguments::Mailbox => {
                access_token.assert_has_access(request.account_id, Collection::Mailbox)?;

                Collection::Mailbox
            }
            RequestArguments::Thread => {
                access_token.assert_has_access(request.account_id, Collection::Email)?;

                Collection::Thread
            }
            RequestArguments::Identity => {
                access_token.assert_is_member(request.account_id)?;

                Collection::Identity
            }
            RequestArguments::EmailSubmission => {
                access_token.assert_is_member(request.account_id)?;

                Collection::EmailSubmission
            }
        };

        let max_changes = if self.config.changes_max_results > 0
            && self.config.changes_max_results < request.max_changes.unwrap_or(0)
        {
            self.config.changes_max_results
        } else {
            request.max_changes.unwrap_or(0)
        };
        let mut response = ChangesResponse {
            account_id: request.account_id,
            old_state: State::Initial,
            new_state: State::Initial,
            has_more_changes: false,
            created: vec![],
            updated: vec![],
            destroyed: vec![],
            updated_properties: None,
        };
        let account_id = request.account_id.document_id();

        let (items_sent, mut changelog) = match &request.since_state {
            State::Initial => {
                let changelog = self.changes_(account_id, collection, Query::All).await?;
                if changelog.changes.is_empty() && changelog.from_change_id == 0 {
                    return Ok(response);
                }

                (0, changelog)
            }
            State::Exact(change_id) => (
                0,
                self.changes_(account_id, collection, Query::Since(*change_id))
                    .await?,
            ),
            State::Intermediate(intermediate_state) => {
                let mut changelog = self
                    .changes_(
                        account_id,
                        collection,
                        Query::RangeInclusive(intermediate_state.from_id, intermediate_state.to_id),
                    )
                    .await?;
                if intermediate_state.items_sent >= changelog.changes.len() {
                    (
                        0,
                        self.changes_(
                            account_id,
                            collection,
                            Query::Since(intermediate_state.to_id),
                        )
                        .await?,
                    )
                } else {
                    changelog.changes.drain(
                        (changelog.changes.len() - intermediate_state.items_sent)
                            ..changelog.changes.len(),
                    );
                    (intermediate_state.items_sent, changelog)
                }
            }
        };

        if max_changes > 0 && changelog.changes.len() > max_changes {
            changelog
                .changes
                .drain(0..(changelog.changes.len() - max_changes));
            response.has_more_changes = true;
        };

        let mut items_changed = false;

        let total_changes = changelog.changes.len();
        if total_changes > 0 {
            for change in changelog.changes {
                match change {
                    Change::Insert(item) => response.created.push(item.into()),
                    Change::Update(item) => {
                        items_changed = true;
                        response.updated.push(item.into())
                    }
                    Change::Delete(item) => response.destroyed.push(item.into()),
                    Change::ChildUpdate(item) => response.updated.push(item.into()),
                };
            }
        }
        response.new_state = if response.has_more_changes {
            State::new_intermediate(
                changelog.from_change_id,
                changelog.to_change_id,
                items_sent + max_changes,
            )
        } else {
            State::new_exact(changelog.to_change_id)
        };

        if !response.updated.is_empty() && !items_changed && collection == Collection::Mailbox {
            response.updated_properties = vec![
                Property::TotalEmails,
                Property::UnreadEmails,
                Property::TotalThreads,
                Property::UnreadThreads,
            ]
            .into()
        }

        Ok(response)
    }

    pub async fn changes_(
        &self,
        account_id: u32,
        collection: Collection,
        query: Query,
    ) -> Result<Changes, MethodError> {
        self.store
            .changes(account_id, collection, query)
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "changes",
                account_id = account_id,
                collection = ?collection,
                error = ?err,
                "Failed to query changes.");
                MethodError::ServerPartialFail
            })
    }
}
