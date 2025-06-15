/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};

use common::{
    Inner,
    core::BuildServer,
    ipc::{BroadcastEvent, PushSubscription, StateEvent, UpdateSubscription},
};
use jmap_proto::types::{id::Id, state::StateChange, type_state::DataType};
use store::{ahash::AHashMap, rand};
use tokio::sync::mpsc;
use trc::ServerEvent;
use utils::map::bitmap::Bitmap;

use super::{
    Event, PURGE_EVERY, PushUpdate, SEND_TIMEOUT, Subscriber, SubscriberId, SubscriberType,
    push::spawn_push_manager,
};

#[allow(clippy::unwrap_or_default)]
pub fn spawn_state_manager(inner: Arc<Inner>, mut change_rx: mpsc::Receiver<StateEvent>) {
    let push_tx = spawn_push_manager(inner.clone());

    tokio::spawn(async move {
        let mut subscribers: AHashMap<u32, AHashMap<SubscriberId, Subscriber>> =
            AHashMap::default();
        let mut shared_accounts: AHashMap<u32, Vec<u32>> = AHashMap::default();
        let mut shared_accounts_map: AHashMap<u32, AHashMap<u32, Bitmap<DataType>>> =
            AHashMap::default();

        let mut last_purge = Instant::now();

        while let Some(event) = change_rx.recv().await {
            let mut purge_needed = last_purge.elapsed() >= PURGE_EVERY;

            match event {
                StateEvent::Stop => {
                    if push_tx.send(Event::Reset).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push reset.",
                            CausedBy = trc::location!()
                        );
                    }
                    break;
                }
                StateEvent::UpdateSharedAccounts { account_id } => {
                    // Obtain account membership and shared mailboxes
                    let acl = match inner.build_server().get_access_token(account_id).await {
                        Ok(result) => result,
                        Err(err) => {
                            trc::error!(
                                err.account_id(account_id)
                                    .details("Failed to obtain access token.")
                            );

                            continue;
                        }
                    };

                    // Delete any removed sharings
                    if let Some(shared_account_ids) = shared_accounts.get(&account_id) {
                        for shared_account_id in shared_account_ids {
                            if *shared_account_id != acl.primary_id
                                && !acl.member_of.contains(shared_account_id)
                                && !acl
                                    .access_to
                                    .iter()
                                    .any(|(id, _)| *id == *shared_account_id)
                            {
                                if let Some(shared_list) =
                                    shared_accounts_map.get_mut(shared_account_id)
                                {
                                    shared_list.remove(&account_id);
                                    if shared_list.is_empty() {
                                        shared_accounts_map.remove(shared_account_id);
                                    }
                                }
                            }
                        }
                    }

                    // Update lists
                    let mut shared_account_ids =
                        Vec::with_capacity(acl.member_of.len() + 1 + acl.access_to.len());
                    for member_id in [acl.primary_id].iter().chain(acl.member_of.iter()) {
                        shared_account_ids.push(*member_id);
                        shared_accounts_map
                            .entry(*member_id)
                            .or_insert_with(AHashMap::new)
                            .insert(account_id, Bitmap::all());
                    }
                    for (shared_account_id, shared_collections) in acl.access_to.iter() {
                        let mut types: Bitmap<DataType> = Bitmap::new();
                        for collection in *shared_collections {
                            if let Ok(type_state) = DataType::try_from(collection) {
                                types.insert(type_state);
                                if type_state == DataType::Email {
                                    types.insert(DataType::EmailDelivery);
                                    types.insert(DataType::Thread);
                                }
                            }
                        }
                        if !types.is_empty() {
                            shared_account_ids.push(*shared_account_id);
                            shared_accounts_map
                                .entry(*shared_account_id)
                                .or_insert_with(AHashMap::new)
                                .insert(account_id, types);
                        }
                    }
                    shared_accounts.insert(account_id, shared_account_ids);
                }
                StateEvent::Subscribe {
                    account_id,
                    types,
                    tx,
                } => {
                    subscribers
                        .entry(account_id)
                        .or_insert_with(AHashMap::default)
                        .insert(
                            SubscriberId::Ipc(rand::random()),
                            Subscriber {
                                types,
                                subscription: SubscriberType::Ipc { tx },
                            },
                        );
                }
                StateEvent::Publish {
                    state_change,
                    broadcast,
                } => {
                    // Publish event to cluster
                    if broadcast {
                        if let Some(broadcast_tx) = &inner.ipc.broadcast_tx.clone() {
                            if broadcast_tx
                                .send(BroadcastEvent::StateChange(state_change))
                                .await
                                .is_err()
                            {
                                trc::event!(
                                    Server(trc::ServerEvent::ThreadError),
                                    Details = "Error sending broadcast event.",
                                    CausedBy = trc::location!()
                                );
                            }
                        }
                    }

                    if let Some(shared_accounts) = shared_accounts_map.get(&state_change.account_id)
                    {
                        let current_time = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let mut push_ids = Vec::new();

                        for (owner_account_id, allowed_types) in shared_accounts {
                            if let Some(subscribers) = subscribers.get(owner_account_id) {
                                for (subscriber_id, subscriber) in subscribers {
                                    let mut types = Bitmap::new();
                                    for state_type in state_change.types {
                                        if subscriber.types.contains(state_type)
                                            && allowed_types.contains(state_type)
                                        {
                                            types.insert(state_type);
                                        }
                                    }
                                    if !types.is_empty() {
                                        match &subscriber.subscription {
                                            SubscriberType::Ipc { tx } if !tx.is_closed() => {
                                                let subscriber_tx = tx.clone();

                                                tokio::spawn(async move {
                                                    // Timeout after 500ms in case there is a blocked client
                                                    if subscriber_tx
                                                        .send_timeout(
                                                            StateChange {
                                                                account_id: state_change.account_id,
                                                                change_id: state_change.change_id,
                                                                types,
                                                            },
                                                            SEND_TIMEOUT,
                                                        )
                                                        .await
                                                        .is_err()
                                                    {
                                                        trc::event!(
                                                            Server(ServerEvent::ThreadError),
                                                            Details = "Error sending state change to subscriber.",
                                                            CausedBy = trc::location!()
                                                        );
                                                    }
                                                });
                                            }
                                            SubscriberType::Push { expires }
                                                if expires > &current_time =>
                                            {
                                                push_ids.push(Id::from_parts(
                                                    *owner_account_id,
                                                    (*subscriber_id).into(),
                                                ));
                                            }
                                            _ => {
                                                purge_needed = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !push_ids.is_empty()
                            && push_tx
                                .send(Event::Push {
                                    ids: push_ids,
                                    state_change,
                                })
                                .await
                                .is_err()
                        {
                            trc::event!(
                                Server(ServerEvent::ThreadError),
                                Details = "Error sending push updates.",
                                CausedBy = trc::location!()
                            );
                        }
                    }
                }
                StateEvent::UpdateSubscriptions {
                    account_id,
                    subscriptions,
                } => {
                    let mut updated_ids = Vec::with_capacity(subscriptions.len());
                    let mut push_updates = Vec::with_capacity(subscriptions.len());

                    if let Some(subscribers) = subscribers.get_mut(&account_id) {
                        let mut remove_ids = Vec::new();

                        for subscriber_id in subscribers.keys() {
                            if let SubscriberId::Push(push_id) = subscriber_id {
                                if !subscriptions.iter().any(|s| {
                                    matches!(s, UpdateSubscription::Verified(
                                        PushSubscription { id, .. }
                                    ) if id == push_id)
                                }) {
                                    remove_ids.push(*subscriber_id);
                                }
                            }
                        }

                        for remove_id in remove_ids {
                            push_updates.push(PushUpdate::Unregister {
                                id: Id::from_parts(account_id, remove_id.into()),
                            });
                            subscribers.remove(&remove_id);
                        }
                    }

                    for subscription in subscriptions {
                        match subscription {
                            UpdateSubscription::Unverified {
                                id,
                                url,
                                code,
                                keys,
                            } => {
                                push_updates.push(PushUpdate::Verify {
                                    id,
                                    account_id,
                                    url,
                                    code,
                                    keys,
                                });
                            }
                            UpdateSubscription::Verified(verified) => {
                                updated_ids.push(verified.id);
                                subscribers
                                    .entry(account_id)
                                    .or_insert_with(AHashMap::default)
                                    .insert(
                                        SubscriberId::Push(verified.id),
                                        Subscriber {
                                            types: verified.types,
                                            subscription: SubscriberType::Push {
                                                expires: verified.expires,
                                            },
                                        },
                                    );

                                push_updates.push(PushUpdate::Register {
                                    id: Id::from_parts(account_id, verified.id),
                                    url: verified.url,
                                    keys: verified.keys,
                                });
                            }
                        }
                    }

                    if !push_updates.is_empty()
                        && push_tx
                            .send(Event::Update {
                                updates: push_updates,
                            })
                            .await
                            .is_err()
                    {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push updates.",
                            CausedBy = trc::location!()
                        );
                    }
                }
            }

            if purge_needed {
                let mut remove_account_ids = Vec::new();
                let current_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for (account_id, subscriber_map) in &mut subscribers {
                    let mut remove_subscription_ids = Vec::new();
                    for (id, subscriber) in subscriber_map.iter() {
                        if !subscriber.is_valid(current_time) {
                            remove_subscription_ids.push(*id);
                        }
                    }
                    if !remove_subscription_ids.is_empty() {
                        if remove_subscription_ids.len() < subscriber_map.len() {
                            for remove_subscription_id in remove_subscription_ids {
                                subscriber_map.remove(&remove_subscription_id);
                            }
                        } else {
                            remove_account_ids.push(*account_id);
                        }
                    }
                }

                for remove_account_id in remove_account_ids {
                    subscribers.remove(&remove_account_id);
                }

                last_purge = Instant::now();
            }
        }
    });
}
