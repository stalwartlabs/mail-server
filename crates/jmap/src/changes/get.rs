/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::changes::{ChangesRequest, ChangesResponse, RequestArguments},
    types::{collection::Collection, property::Property, state::State},
};
use std::future::Future;
use store::query::log::{Change, Changes, Query};

pub trait ChangesLookup: Sync + Send {
    fn changes(
        &self,
        request: ChangesRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ChangesResponse>> + Send;
}

impl ChangesLookup for Server {
    async fn changes(
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

                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
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
                let changelog =
                    changes(self, account_id, collection, Query::All, &mut response).await?;
                if changelog.changes.is_empty() && changelog.from_change_id == 0 {
                    return Ok(response);
                }

                (0, changelog)
            }
            State::Exact(change_id) => (
                0,
                changes(
                    self,
                    account_id,
                    collection,
                    Query::Since(*change_id),
                    &mut response,
                )
                .await?,
            ),
            State::Intermediate(intermediate_state) => {
                let mut changelog = changes(
                    self,
                    account_id,
                    collection,
                    Query::RangeInclusive(intermediate_state.from_id, intermediate_state.to_id),
                    &mut response,
                )
                .await?;
                if intermediate_state.items_sent >= changelog.changes.len() {
                    (
                        0,
                        changes(
                            self,
                            account_id,
                            collection,
                            Query::Since(intermediate_state.to_id),
                            &mut response,
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

        let total_changes = changelog.changes.len();
        if total_changes > 0 {
            for change in changelog.changes {
                match change {
                    Change::Insert(item) => response.created.push(item.into()),
                    Change::Update(item) => response.updated.push(item.into()),
                    Change::Delete(item) => response.destroyed.push(item.into()),
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

        Ok(response)
    }
}

async fn changes(
    server: &Server,
    account_id: u32,
    collection: Collection,
    query: Query,
    response: &mut ChangesResponse,
) -> trc::Result<Changes> {
    let mut main_changes = server
        .store()
        .changes(account_id, collection, query)
        .await?;
    if matches!(collection, Collection::Mailbox) {
        let child_changes = server
            .store()
            .changes(account_id, collection.as_child_update(), query)
            .await?;

        if !child_changes.changes.is_empty() {
            if child_changes.from_change_id < main_changes.from_change_id {
                main_changes.from_change_id = child_changes.from_change_id;
            }
            if child_changes.to_change_id > main_changes.to_change_id {
                main_changes.to_change_id = child_changes.to_change_id;
            }
            let mut has_child_changes = false;
            for change in child_changes.changes {
                let id = change.id();
                if !main_changes.changes.iter().any(|c| c.id() == id) {
                    main_changes.changes.push(change);
                    has_child_changes = true;
                }
            }

            if has_child_changes {
                response.updated_properties = vec![
                    Property::TotalEmails,
                    Property::UnreadEmails,
                    Property::TotalThreads,
                    Property::UnreadThreads,
                ]
                .into();
            }
        }
    }
    Ok(main_changes)
}
