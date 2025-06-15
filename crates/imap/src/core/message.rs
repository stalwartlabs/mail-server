/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use common::listener::SessionStream;
use email::cache::MessageCacheFetch;
use imap_proto::protocol::{Sequence, expunge, select::Exists};
use jmap_proto::types::{collection::Collection, property::Property};
use std::collections::BTreeMap;
use store::{ValueKey, write::ValueClass};
use trc::AddContext;

use crate::core::ImapId;

use super::{
    ImapUidToId, Mailbox, MailboxId, MailboxState, NextMailboxState, SelectedMailbox, SessionData,
};

impl<T: SessionStream> SessionData<T> {
    pub async fn fetch_messages(
        &self,
        mailbox: &MailboxId,
        current_state: Option<u64>,
    ) -> trc::Result<Option<MailboxState>> {
        let cached_messages = self
            .server
            .get_cached_messages(mailbox.account_id)
            .await
            .caused_by(trc::location!())?;

        if current_state.is_some_and(|state| state == cached_messages.emails.change_id) {
            return Ok(None);
        }

        // Obtain UID next and assign UIDs
        let uid_map = cached_messages
            .emails
            .items
            .iter()
            .filter_map(|item| {
                item.mailboxes.iter().find_map(|m| {
                    if m.mailbox_id == mailbox.mailbox_id {
                        Some((m.uid, item.document_id))
                    } else {
                        None
                    }
                })
            })
            .collect::<BTreeMap<u32, u32>>();
        let mut uid_max = 0;
        let mut id_to_imap = AHashMap::with_capacity(uid_map.len());
        let mut uid_to_id = AHashMap::with_capacity(uid_map.len());

        for (seqnum, (uid, message_id)) in uid_map.into_iter().enumerate() {
            if uid > uid_max {
                uid_max = uid;
            }
            id_to_imap.insert(
                message_id,
                ImapId {
                    uid,
                    seqnum: seqnum as u32 + 1,
                },
            );
            uid_to_id.insert(uid, message_id);
        }

        Ok(Some(MailboxState {
            total_messages: id_to_imap.len(),
            id_to_imap,
            uid_to_id,
            uid_max,
            modseq: cached_messages.emails.change_id,
            next_state: None,
        }))
    }

    pub async fn synchronize_messages(&self, mailbox: &SelectedMailbox) -> trc::Result<u64> {
        // Obtain current modseq
        let mut current_modseq = mailbox.state.lock().modseq;
        if let Some(new_state) = self
            .fetch_messages(&mailbox.id, current_modseq.into())
            .await?
        {
            // Synchronize messages
            let mut current_state = mailbox.state.lock();
            current_modseq = new_state.modseq;

            // Add missing uids
            let mut deletions = current_state
                .next_state
                .take()
                .map(|state| state.deletions)
                .unwrap_or_default();
            let mut id_to_imap = AHashMap::with_capacity(current_state.id_to_imap.len());
            for (id, imap_id) in std::mem::take(&mut current_state.id_to_imap) {
                if !new_state.uid_to_id.contains_key(&imap_id.uid) {
                    // Add to deletions
                    deletions.push(imap_id);

                    // Invalidate entries
                    current_state.uid_to_id.remove(&imap_id.uid);
                } else {
                    id_to_imap.insert(id, imap_id);
                }
            }
            current_state.id_to_imap = id_to_imap;

            // Update state
            current_state.modseq = new_state.modseq;
            current_state.next_state = Some(Box::new(NextMailboxState {
                next_state: new_state,
                deletions,
            }));
        }

        Ok(current_modseq)
    }

    pub async fn write_mailbox_changes(
        &self,
        mailbox: &SelectedMailbox,
        is_qresync: bool,
    ) -> trc::Result<u64> {
        // Resync mailbox
        let modseq = self.synchronize_messages(mailbox).await?;
        let mut buf = Vec::new();
        {
            let mut current_state = mailbox.state.lock();
            if let Some(next_state) = current_state.next_state.take() {
                if !next_state.deletions.is_empty() {
                    let mut ids = next_state
                        .deletions
                        .into_iter()
                        .map(|id| if is_qresync { id.uid } else { id.seqnum })
                        .collect::<Vec<u32>>();
                    ids.sort_unstable();
                    expunge::Response { is_qresync, ids }.serialize_to(&mut buf);
                }
                if !buf.is_empty()
                    || next_state
                        .next_state
                        .uid_max
                        .saturating_sub(current_state.uid_max)
                        > 0
                {
                    Exists {
                        total_messages: next_state.next_state.total_messages,
                    }
                    .serialize(&mut buf);
                }
                *current_state = next_state.next_state;
            }
        }
        if !buf.is_empty() {
            self.write_bytes(buf).await?;
        }

        Ok(modseq)
    }

    pub async fn get_uid_next(&self, mailbox: &MailboxId) -> trc::Result<u32> {
        self.server
            .core
            .storage
            .data
            .get_counter(ValueKey {
                account_id: mailbox.account_id,
                collection: Collection::Mailbox.into(),
                document_id: mailbox.mailbox_id,
                class: ValueClass::Property(Property::EmailIds.into()),
            })
            .await
            .map(|v| (v + 1) as u32)
    }

    pub fn mailbox_state(&self, mailbox: &MailboxId) -> Option<Mailbox> {
        self.mailboxes
            .lock()
            .iter()
            .find(|m| m.account_id == mailbox.account_id)
            .and_then(|m| m.mailbox_state.get(&mailbox.mailbox_id))
            .cloned()
    }
}

impl SelectedMailbox {
    pub async fn sequence_to_ids(
        &self,
        sequence: &Sequence,
        is_uid: bool,
    ) -> trc::Result<AHashMap<u32, ImapId>> {
        if !sequence.is_saved_search() {
            let mut ids = AHashMap::new();
            let state = self.state.lock();

            if is_uid {
                let id_to_imap = state
                    .next_state
                    .as_ref()
                    .map(|s| &s.next_state.id_to_imap)
                    .unwrap_or(&state.id_to_imap);
                if !state.id_to_imap.is_empty() {
                    for (id, imap_id) in id_to_imap {
                        if sequence.contains(imap_id.uid, state.uid_max) {
                            ids.insert(*id, *imap_id);
                        }
                    }
                }
            } else if !state.id_to_imap.is_empty() {
                for (id, imap_id) in &state.id_to_imap {
                    if sequence.contains(imap_id.seqnum, state.total_messages as u32) {
                        ids.insert(*id, *imap_id);
                    }
                }
            }

            Ok(ids)
        } else {
            let saved_ids = self.get_saved_search().await.ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details("No saved search found.")
            })?;
            let mut ids = AHashMap::with_capacity(saved_ids.len());
            let state = self.state.lock();

            for imap_id in saved_ids.iter() {
                if let Some(id) = state.uid_to_id.get(&imap_id.uid) {
                    ids.insert(*id, *imap_id);
                }
            }

            Ok(ids)
        }
    }

    pub async fn sequence_expand_missing(&self, sequence: &Sequence, is_uid: bool) -> Vec<u32> {
        let mut deleted_ids = Vec::new();
        if !sequence.is_saved_search() {
            let state = self.state.lock();
            if is_uid {
                for uid in sequence.expand(state.uid_max) {
                    if !state.uid_to_id.contains_key(&uid) {
                        deleted_ids.push(uid);
                    }
                }
            } else {
                for seqnum in sequence.expand(state.total_messages as u32) {
                    if seqnum > state.total_messages as u32 {
                        deleted_ids.push(seqnum);
                    }
                }
            }
        } else if let Some(saved_ids) = self.get_saved_search().await {
            let state = self.state.lock();
            for id in saved_ids.iter() {
                if !state.uid_to_id.contains_key(&id.uid) {
                    deleted_ids.push(if is_uid { id.uid } else { id.seqnum });
                }
            }
        }
        deleted_ids.sort_unstable();
        deleted_ids
    }

    pub fn append_messages(&self, ids: Vec<ImapUidToId>, modseq: Option<u64>) {
        let mut mailbox = self.state.lock();
        if modseq.unwrap_or(0) > mailbox.modseq {
            let mut uid_max = 0;
            for id in ids {
                mailbox.total_messages += 1;
                let seqnum = mailbox.total_messages as u32;
                mailbox.uid_to_id.insert(id.uid, id.uid);
                mailbox.id_to_imap.insert(
                    id.id,
                    ImapId {
                        uid: id.uid,
                        seqnum,
                    },
                );
                uid_max = id.uid;
            }
            mailbox.uid_max = uid_max;
        }
    }
}
