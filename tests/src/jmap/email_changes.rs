/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    parser::{json::Parser, JsonObjectParser},
    types::{collection::Collection, id::Id, state::State},
};
use store::{
    ahash::AHashSet,
    write::{log::ChangeLogBuilder, BatchBuilder},
};

use crate::jmap::assert_is_empty;

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Changes tests...");

    let server = params.server.clone();
    params.client.set_default_account_id(Id::new(1));
    let mut states = vec![State::Initial];

    for (change_id, (changes, expected_changelog)) in [
        (
            vec![
                LogAction::Insert(0),
                LogAction::Insert(1),
                LogAction::Insert(2),
            ],
            vec![vec![vec![0, 1, 2], vec![], vec![]]],
        ),
        (
            vec![
                LogAction::Move(0, 3),
                LogAction::Insert(4),
                LogAction::Insert(5),
                LogAction::Update(1),
                LogAction::Update(2),
            ],
            vec![
                vec![vec![1, 2, 3, 4, 5], vec![], vec![]],
                vec![vec![3, 4, 5], vec![1, 2], vec![0]],
            ],
        ),
        (
            vec![
                LogAction::Delete(1),
                LogAction::Insert(6),
                LogAction::Insert(7),
                LogAction::Update(2),
            ],
            vec![
                vec![vec![2, 3, 4, 5, 6, 7], vec![], vec![]],
                vec![vec![3, 4, 5, 6, 7], vec![2], vec![0, 1]],
                vec![vec![6, 7], vec![2], vec![1]],
            ],
        ),
        (
            vec![
                LogAction::Update(4),
                LogAction::Update(5),
                LogAction::Update(6),
                LogAction::Update(7),
            ],
            vec![
                vec![vec![2, 3, 4, 5, 6, 7], vec![], vec![]],
                vec![vec![3, 4, 5, 6, 7], vec![2], vec![0, 1]],
                vec![vec![6, 7], vec![2, 4, 5], vec![1]],
                vec![vec![], vec![4, 5, 6, 7], vec![]],
            ],
        ),
        (
            vec![
                LogAction::Delete(4),
                LogAction::Delete(5),
                LogAction::Delete(6),
                LogAction::Delete(7),
            ],
            vec![
                vec![vec![2, 3], vec![], vec![]],
                vec![vec![3], vec![2], vec![0, 1]],
                vec![vec![], vec![2], vec![1, 4, 5]],
                vec![vec![], vec![], vec![4, 5, 6, 7]],
                vec![vec![], vec![], vec![4, 5, 6, 7]],
            ],
        ),
        (
            vec![
                LogAction::Insert(8),
                LogAction::Insert(9),
                LogAction::Insert(10),
                LogAction::Update(3),
            ],
            vec![
                vec![vec![2, 3, 8, 9, 10], vec![], vec![]],
                vec![vec![3, 8, 9, 10], vec![2], vec![0, 1]],
                vec![vec![8, 9, 10], vec![2, 3], vec![1, 4, 5]],
                vec![vec![8, 9, 10], vec![3], vec![4, 5, 6, 7]],
                vec![vec![8, 9, 10], vec![3], vec![4, 5, 6, 7]],
                vec![vec![8, 9, 10], vec![3], vec![]],
            ],
        ),
        (
            vec![LogAction::Update(2), LogAction::Update(8)],
            vec![
                vec![vec![2, 3, 8, 9, 10], vec![], vec![]],
                vec![vec![3, 8, 9, 10], vec![2], vec![0, 1]],
                vec![vec![8, 9, 10], vec![2, 3], vec![1, 4, 5]],
                vec![vec![8, 9, 10], vec![2, 3], vec![4, 5, 6, 7]],
                vec![vec![8, 9, 10], vec![2, 3], vec![4, 5, 6, 7]],
                vec![vec![8, 9, 10], vec![2, 3], vec![]],
                vec![vec![], vec![2, 8], vec![]],
            ],
        ),
        (
            vec![
                LogAction::Move(9, 11),
                LogAction::Move(10, 12),
                LogAction::Delete(8),
            ],
            vec![
                vec![vec![2, 3, 11, 12], vec![], vec![]],
                vec![vec![3, 11, 12], vec![2], vec![0, 1]],
                vec![vec![11, 12], vec![2, 3], vec![1, 4, 5]],
                vec![vec![11, 12], vec![2, 3], vec![4, 5, 6, 7]],
                vec![vec![11, 12], vec![2, 3], vec![4, 5, 6, 7]],
                vec![vec![11, 12], vec![2, 3], vec![]],
                vec![vec![11, 12], vec![2], vec![8, 9, 10]],
                vec![vec![11, 12], vec![], vec![8, 9, 10]],
            ],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut changelog = ChangeLogBuilder::with_change_id(change_id as u64);

        for change in changes {
            match change {
                LogAction::Insert(id) => changelog.log_insert(Collection::Email, id),
                LogAction::Update(id) => changelog.log_update(Collection::Email, id),
                LogAction::Delete(id) => changelog.log_delete(Collection::Email, id),
                LogAction::UpdateChild(id) => changelog.log_child_update(Collection::Email, id),
                LogAction::Move(old_id, new_id) => {
                    changelog.log_move(Collection::Email, old_id, new_id)
                }
            }
        }

        server
            .core
            .storage
            .data
            .write(
                BatchBuilder::new()
                    .with_account_id(1)
                    .with_collection(Collection::Email)
                    .custom(changelog)
                    .build_batch(),
            )
            .await
            .unwrap();

        let mut new_state = State::Initial;
        for (test_num, state) in (states).iter().enumerate() {
            let changes = params
                .client
                .email_changes(state.to_string(), None)
                .await
                .unwrap();

            assert_eq!(
                expected_changelog[test_num],
                [changes.created(), changes.updated(), changes.destroyed()]
                    .into_iter()
                    .map(|list| {
                        let mut list = list
                            .iter()
                            .map(|i| Id::from_bytes(i.as_bytes()).unwrap().into())
                            .collect::<Vec<u64>>();
                        list.sort_unstable();
                        list
                    })
                    .collect::<Vec<Vec<_>>>(),
                "test_num: {}, state: {:?}",
                test_num,
                state
            );

            if let State::Initial = state {
                new_state = State::parse_str(changes.new_state()).unwrap();
            }

            for max_changes in 1..=8 {
                let mut insertions = expected_changelog[test_num][0]
                    .iter()
                    .copied()
                    .collect::<AHashSet<_>>();
                let mut updates = expected_changelog[test_num][1]
                    .iter()
                    .copied()
                    .collect::<AHashSet<_>>();
                let mut deletions = expected_changelog[test_num][2]
                    .iter()
                    .copied()
                    .collect::<AHashSet<_>>();

                let mut int_state = state.clone();

                for _ in 0..100 {
                    let changes = params
                        .client
                        .email_changes(int_state.to_string(), max_changes.into())
                        .await
                        .unwrap();

                    assert!(
                        changes.created().len()
                            + changes.updated().len()
                            + changes.destroyed().len()
                            <= max_changes,
                        "{} > {}",
                        changes.created().len()
                            + changes.updated().len()
                            + changes.destroyed().len(),
                        max_changes
                    );

                    changes.created().iter().for_each(|id| {
                        assert!(
                            insertions.remove(&Id::from_bytes(id.as_bytes()).unwrap()),
                            "{:?} != {}",
                            insertions,
                            Id::from_bytes(id.as_bytes()).unwrap()
                        );
                    });
                    changes.updated().iter().for_each(|id| {
                        assert!(
                            updates.remove(&Id::from_bytes(id.as_bytes()).unwrap()),
                            "{:?} != {}",
                            updates,
                            Id::from_bytes(id.as_bytes()).unwrap()
                        );
                    });
                    changes.destroyed().iter().for_each(|id| {
                        assert!(
                            deletions.remove(&Id::from_bytes(id.as_bytes()).unwrap()),
                            "{:?} != {}",
                            deletions,
                            Id::from_bytes(id.as_bytes()).unwrap()
                        );
                    });

                    int_state = State::parse_str(changes.new_state()).unwrap();

                    if !changes.has_more_changes() {
                        break;
                    }
                }

                assert_eq!(
                    insertions.len(),
                    0,
                    "test_num: {}, state: {:?}, pending: {:?}",
                    test_num,
                    state,
                    insertions
                );
                assert_eq!(
                    updates.len(),
                    0,
                    "test_num: {}, state: {:?}, pending: {:?}",
                    test_num,
                    state,
                    updates
                );
                assert_eq!(
                    deletions.len(),
                    0,
                    "test_num: {}, state: {:?}, pending: {:?}",
                    test_num,
                    state,
                    deletions
                );
            }
        }

        states.push(new_state);
    }

    let changes = params
        .client
        .email_changes(State::Initial.to_string(), 0.into())
        .await
        .unwrap();
    let mut created = changes
        .created()
        .iter()
        .map(|i| Id::from_bytes(i.as_bytes()).unwrap().into())
        .collect::<Vec<u64>>();
    created.sort_unstable();

    assert_eq!(created, vec![2, 3, 11, 12]);
    assert_eq!(changes.updated(), Vec::<String>::new());
    assert_eq!(changes.destroyed(), Vec::<String>::new());
    assert_is_empty(server).await;
}

#[derive(Debug, Clone, Copy)]
pub enum LogAction {
    Insert(u64),
    Update(u64),
    Delete(u64),
    UpdateChild(u64),
    Move(u64, u64),
}

pub trait ParseState: Sized {
    fn parse_str(state: &str) -> Option<Self>;
}

impl ParseState for State {
    fn parse_str(state: &str) -> Option<Self> {
        let state = format!("{state}\"");
        let mut parser = Parser::new(state.as_bytes());
        State::parse(&mut parser).ok()
    }
}
