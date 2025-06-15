/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::changes::{ChangesRequest, ChangesResponse, RequestArguments},
    types::{
        collection::{Collection, SyncCollection},
        property::Property,
        state::State,
    },
};
use std::future::Future;
use store::query::log::{Change, Query};

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
        let (collection, is_container) = match request.arguments {
            RequestArguments::Email => {
                access_token.assert_has_access(request.account_id, Collection::Email)?;
                (SyncCollection::Email, false)
            }
            RequestArguments::Mailbox => {
                access_token.assert_has_access(request.account_id, Collection::Mailbox)?;

                (SyncCollection::Email, true)
            }
            RequestArguments::Thread => {
                access_token.assert_has_access(request.account_id, Collection::Email)?;

                (SyncCollection::Thread, true)
            }
            RequestArguments::Identity => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::Identity, false)
            }
            RequestArguments::EmailSubmission => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::EmailSubmission, false)
            }
            RequestArguments::Quota => {
                access_token.assert_is_member(request.account_id)?;

                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
        };

        let max_changes = std::cmp::min(
            request
                .max_changes
                .filter(|n| *n != 0)
                .unwrap_or(usize::MAX),
            self.core.jmap.changes_max_results.unwrap_or(usize::MAX),
        );
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

        let (items_sent, changelog) = match &request.since_state {
            State::Initial => {
                let changelog = self
                    .store()
                    .changes(account_id, collection, Query::All)
                    .await?;
                if changelog.changes.is_empty() && changelog.from_change_id == 0 {
                    return Ok(response);
                }

                (0, changelog)
            }
            State::Exact(change_id) => (
                0,
                self.store()
                    .changes(account_id, collection, Query::Since(*change_id))
                    .await?,
            ),
            State::Intermediate(intermediate_state) => {
                let changelog = self
                    .store()
                    .changes(
                        account_id,
                        collection,
                        Query::RangeInclusive(intermediate_state.from_id, intermediate_state.to_id),
                    )
                    .await?;
                if (is_container
                    && intermediate_state.items_sent >= changelog.total_container_changes())
                    || (!is_container
                        && intermediate_state.items_sent >= changelog.total_item_changes())
                {
                    (
                        0,
                        self.store()
                            .changes(
                                account_id,
                                collection,
                                Query::Since(intermediate_state.to_id),
                            )
                            .await?,
                    )
                } else {
                    (intermediate_state.items_sent, changelog)
                }
            }
        };

        if changelog.is_truncated && request.since_state != State::Initial {
            return Err(trc::JmapEvent::CannotCalculateChanges
                .into_err()
                .details("Changelog has been truncated"));
        }

        let mut changes = changelog
            .changes
            .into_iter()
            .filter(|change| {
                (is_container && change.is_container_change())
                    || (!is_container && change.is_item_change())
            })
            .skip(items_sent)
            .peekable();

        let mut items_changed = false;
        for change in (&mut changes).take(max_changes) {
            match change {
                Change::InsertContainer(item) | Change::InsertItem(item) => {
                    response.created.push(item.into());
                }
                Change::UpdateContainer(item) | Change::UpdateItem(item) => {
                    response.updated.push(item.into());
                    items_changed = true;
                }
                Change::DeleteContainer(item) | Change::DeleteItem(item) => {
                    response.destroyed.push(item.into());
                }
                Change::UpdateContainerProperty(item) => {
                    response.updated.push(item.into());
                }
            };
        }

        let change_id = (if is_container {
            changelog.container_change_id
        } else {
            changelog.item_change_id
        })
        .unwrap_or(changelog.to_change_id);

        response.has_more_changes = changes.peek().is_some();
        response.new_state = if response.has_more_changes {
            State::new_intermediate(
                changelog.from_change_id,
                change_id,
                items_sent + max_changes,
            )
        } else {
            State::new_exact(change_id)
        };
        if is_container
            && !response.updated.is_empty()
            && !items_changed
            && collection == SyncCollection::Email
        {
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
}

/*async fn changes(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
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
*/
