/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_client::{
    core::query::{Comparator, Filter},
    email,
    mailbox::Role,
};
use jmap_proto::types::{collection::Collection, id::Id, property::Property, state::State};

use store::{
    ahash::{AHashMap, AHashSet},
    write::{log::ChangeLogBuilder, BatchBuilder, MaybeDynamicId, TagValue, F_BITMAP, F_CLEAR},
};

use crate::jmap::{
    assert_is_empty,
    email_changes::{LogAction, ParseState},
    mailbox::destroy_all_mailboxes,
};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email QueryChanges tests...");
    let server = params.server.clone();
    let mailbox1_id = params
        .client
        .set_default_account_id(Id::new(1).to_string())
        .mailbox_create("JMAP Changes 1", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let mailbox2_id = params
        .client
        .mailbox_create("JMAP Changes 2", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    let mut states = vec![State::Initial];
    let mut id_map = AHashMap::default();

    let mut updated_ids = AHashSet::default();
    let mut removed_ids = AHashSet::default();
    let mut type1_ids = AHashSet::default();

    let mut thread_id = 100;

    for (change_num, change) in [
        LogAction::Insert(0),
        LogAction::Insert(1),
        LogAction::Insert(2),
        LogAction::Move(0, 3),
        LogAction::Insert(4),
        LogAction::Insert(5),
        LogAction::Update(1),
        LogAction::Update(2),
        LogAction::Delete(1),
        LogAction::Insert(6),
        LogAction::Insert(7),
        LogAction::Update(2),
        LogAction::Update(4),
        LogAction::Update(5),
        LogAction::Update(6),
        LogAction::Update(7),
        LogAction::Delete(4),
        LogAction::Delete(5),
        LogAction::Delete(6),
        LogAction::Insert(8),
        LogAction::Insert(9),
        LogAction::Insert(10),
        LogAction::Update(3),
        LogAction::Update(2),
        LogAction::Update(8),
        LogAction::Move(9, 11),
        LogAction::Move(10, 12),
        LogAction::Delete(8),
    ]
    .iter()
    .enumerate()
    {
        match &change {
            LogAction::Insert(id) => {
                let jmap_id = Id::from_bytes(
                    params
                        .client
                        .email_import(
                            format!(
                                "From: test_{}\nSubject: test_{}\n\ntest",
                                if change_num % 2 == 0 { 1 } else { 2 },
                                *id
                            )
                            .into_bytes(),
                            [if change_num % 2 == 0 {
                                &mailbox1_id
                            } else {
                                &mailbox2_id
                            }],
                            [if change_num % 2 == 0 { "1" } else { "2" }].into(),
                            Some(*id as i64),
                        )
                        .await
                        .unwrap()
                        .id()
                        .unwrap()
                        .as_bytes(),
                )
                .unwrap();

                id_map.insert(*id, jmap_id);
                if change_num % 2 == 0 {
                    type1_ids.insert(jmap_id);
                }
            }
            LogAction::Update(id) => {
                let id = *id_map.get(id).unwrap();
                let mut changelog = ChangeLogBuilder::new();
                changelog.log_update(Collection::Email, id);
                server.commit_changes(1, changelog).await.unwrap();
                updated_ids.insert(id);
            }
            LogAction::Delete(id) => {
                let id = *id_map.get(id).unwrap();
                params.client.email_destroy(&id.to_string()).await.unwrap();
                removed_ids.insert(id);
            }
            LogAction::Move(from, to) => {
                let id = *id_map.get(from).unwrap();
                let new_id = Id::from_parts(thread_id, id.document_id());
                server
                    .core
                    .storage
                    .data
                    .write(
                        BatchBuilder::new()
                            .with_account_id(1)
                            .with_collection(Collection::Thread)
                            .create_document()
                            .with_collection(Collection::Email)
                            .update_document(id.document_id())
                            .value(Property::ThreadId, id.prefix_id(), F_BITMAP | F_CLEAR)
                            .set(Property::ThreadId, MaybeDynamicId::Dynamic(0))
                            .tag(
                                Property::ThreadId,
                                TagValue::Id(MaybeDynamicId::Dynamic(0)),
                                0,
                            )
                            .custom(server.begin_changes(1).await.unwrap().with_log_move(
                                Collection::Email,
                                id,
                                new_id,
                            ))
                            .build_batch(),
                    )
                    .await
                    .unwrap();

                id_map.insert(*to, new_id);
                if type1_ids.contains(&id) {
                    type1_ids.insert(new_id);
                }
                removed_ids.insert(id);
                thread_id += 1;
            }
            LogAction::UpdateChild(_) => unreachable!(),
        }

        let mut new_state = State::Initial;
        for state in &states {
            for (test_num, query) in vec![
                QueryChanges {
                    filter: None,
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                },
                QueryChanges {
                    filter: Some(email::query::Filter::from("test_1").into()),
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                },
                QueryChanges {
                    filter: Some(email::query::Filter::in_mailbox(&mailbox1_id).into()),
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                },
                QueryChanges {
                    filter: None,
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: id_map
                        .get(&7)
                        .map(|id| id.to_string().into())
                        .unwrap_or(None),
                },
            ]
            .into_iter()
            .enumerate()
            {
                if test_num == 3 && query.up_to_id.is_none() {
                    continue;
                }
                let mut request = params.client.build();
                let query_request = request
                    .query_email_changes(query.since_query_state.to_string())
                    .sort(query.sort);

                if let Some(filter) = query.filter {
                    query_request.filter(filter);
                }

                if let Some(up_to_id) = query.up_to_id {
                    query_request.up_to_id(up_to_id);
                }

                let changes = request.send_query_email_changes().await.unwrap();

                if test_num == 0 || test_num == 1 {
                    // Immutable filters should not return modified ids, only deletions.
                    for id in changes.removed() {
                        let id = Id::from_bytes(id.as_bytes()).unwrap();
                        assert!(
                            removed_ids.contains(&id),
                            "{:?} (id: {})",
                            changes,
                            id_map.iter().find(|(_, v)| **v == id).unwrap().0
                        );
                    }
                }
                if test_num == 1 || test_num == 2 {
                    // Only type 1 results should be added to the list.
                    for item in changes.added() {
                        let id = Id::from_bytes(item.id().as_bytes()).unwrap();
                        assert!(
                            type1_ids.contains(&id),
                            "{:?} (id: {})",
                            changes,
                            id_map.iter().find(|(_, v)| **v == id).unwrap().0
                        );
                    }
                }
                if test_num == 3 {
                    // Only ids up to 7 should be added to the list.
                    for item in changes.added() {
                        let item_id = Id::from_bytes(item.id().as_bytes()).unwrap();
                        let id = id_map.iter().find(|(_, v)| **v == item_id).unwrap().0;
                        assert!(id < &7, "{:?} (id: {})", changes, id);
                    }
                }

                if let State::Initial = state {
                    new_state = State::parse_str(changes.new_query_state()).unwrap();
                }
            }
        }
        states.push(new_state);
    }

    destroy_all_mailboxes(params).await;

    // Delete virtual threads
    let mut batch = BatchBuilder::new();
    batch.with_account_id(1).with_collection(Collection::Thread);
    for thread_id in server
        .get_document_ids(1, Collection::Thread)
        .await
        .unwrap()
        .unwrap_or_default()
    {
        batch.delete_document(thread_id);
    }
    server
        .core
        .storage
        .data
        .write(batch.build_batch())
        .await
        .unwrap();

    assert_is_empty(server).await;
}

#[derive(Debug, Clone)]
pub struct QueryChanges {
    pub filter: Option<Filter<email::query::Filter>>,
    pub sort: Vec<Comparator<email::query::Comparator>>,
    pub since_query_state: State,
    pub max_changes: usize,
    pub up_to_id: Option<String>,
}
