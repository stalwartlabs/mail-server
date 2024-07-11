/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::method::MethodError,
    method::changes::{ChangesRequest, ChangesResponse, RequestArguments},
    types::{collection::Collection, property::Property, state::State},
};
use store::query::log::{Change, Changes, Query};
use trc::AddContext;

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn changes(
        &self,
        request: ChangesRequest,
        access_token: &AccessToken,
    ) -> trc::Result<ChangesResponse> {
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
            RequestArguments::Quota => {
                access_token.assert_is_member(request.account_id)?;

                return Err(MethodError::CannotCalculateChanges.into());
            }
        };

        let max_changes = if self.core.jmap.changes_max_results > 0
            && self.core.jmap.changes_max_results < request.max_changes.unwrap_or(0)
        {
            self.core.jmap.changes_max_results
        } else {
            request.max_changes.unwrap_or(0)
        };
        let mut response = ChangesResponse {
            account_id: request.account_id,
            old_state: request.since_state.clone(),
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
    ) -> trc::Result<Changes> {
        self.core
            .storage
            .data
            .changes(account_id, collection, query)
            .await
            .caused_by(trc::location!())
    }
}
