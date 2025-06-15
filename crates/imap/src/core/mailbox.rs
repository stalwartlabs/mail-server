/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Account, MailboxId, MailboxSync, Session, SessionData};
use crate::core::Mailbox;
use ahash::AHashMap;
use common::{
    auth::AccessToken,
    config::jmap::settings::SpecialUse,
    listener::{SessionStream, limiter::InFlight},
    sharing::EffectiveAcl,
};

use directory::backend::internal::manage::ManageDirectory;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    mailbox::INBOX_ID,
};
use imap_proto::protocol::list::Attribute;
use jmap_proto::types::{acl::Acl, collection::Collection, id::Id, keyword::Keyword};
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
};
use trc::AddContext;

impl<T: SessionStream> SessionData<T> {
    pub async fn new(
        session: &Session<T>,
        access_token: Arc<AccessToken>,
        in_flight: Option<InFlight>,
    ) -> trc::Result<Self> {
        let mut session = SessionData {
            stream_tx: session.stream_tx.clone(),
            server: session.server.clone(),
            account_id: access_token.primary_id(),
            session_id: session.session_id,
            mailboxes: Mutex::new(vec![]),
            state: access_token.state().into(),
            access_token,
            in_flight,
        };
        let access_token = session.access_token.clone();

        // Fetch mailboxes for the main account
        let mut mailboxes = vec![
            session
                .fetch_account_mailboxes(session.account_id, None, &access_token, None)
                .await
                .caused_by(trc::location!())?
                .unwrap(),
        ];

        // Fetch shared mailboxes
        for &account_id in access_token.shared_accounts(Collection::Mailbox) {
            let prefix: String = format!(
                "{}/{}",
                session.server.core.jmap.shared_folder,
                session
                    .server
                    .store()
                    .get_principal_name(account_id)
                    .await
                    .caused_by(trc::location!())?
                    .unwrap_or_else(|| Id::from(account_id).to_string())
            );
            mailboxes.push(
                session
                    .fetch_account_mailboxes(account_id, prefix.into(), &access_token, None)
                    .await
                    .caused_by(trc::location!())?
                    .unwrap(),
            );
        }

        session.mailboxes = Mutex::new(mailboxes);

        Ok(session)
    }

    async fn fetch_account_mailboxes(
        &self,
        account_id: u32,
        mailbox_prefix: Option<String>,
        access_token: &AccessToken,
        current_state: Option<u64>,
    ) -> trc::Result<Option<Account>> {
        let cache = self
            .server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        if current_state.is_some_and(|state| state == cache.last_change_id) {
            return Ok(None);
        }

        let shared_mailbox_ids = if access_token.is_primary_id(account_id)
            || access_token.member_of.contains(&account_id)
        {
            None
        } else {
            cache.shared_mailboxes(access_token, Acl::Read).into()
        };

        // Build special uses
        let mut special_uses = AHashMap::new();
        for mailbox in &cache.mailboxes.items {
            if shared_mailbox_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(mailbox.document_id))
                && !matches!(mailbox.role, SpecialUse::None)
            {
                special_uses.insert(mailbox.role, mailbox.document_id);
            }
        }

        // Build account
        let mut account = Account {
            account_id,
            prefix: mailbox_prefix,
            mailbox_names: BTreeMap::new(),
            mailbox_state: AHashMap::with_capacity(cache.mailboxes.items.len()),
            last_change_id: cache.last_change_id,
        };

        for mailbox in &cache.mailboxes.items {
            if shared_mailbox_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(mailbox.document_id))
            {
                continue;
            }

            // Build mailbox path and map it to its effective id
            let mailbox_name = if let Some(prefix) = &account.prefix {
                let mut name = String::with_capacity(prefix.len() + mailbox.path.len() + 1);
                name.push_str(prefix.as_str());
                name.push('/');
                name.push_str(mailbox.path.as_str());
                name
            } else {
                mailbox.path.clone()
            };
            let effective_mailbox_id = self
                .server
                .core
                .jmap
                .default_folders
                .iter()
                .find(|f| f.name == mailbox_name || f.aliases.iter().any(|a| a == &mailbox_name))
                .and_then(|f| special_uses.get(&f.special_use))
                .copied()
                .unwrap_or(mailbox.document_id);
            account
                .mailbox_names
                .insert(mailbox_name, effective_mailbox_id);
            account.mailbox_state.insert(
                mailbox.document_id,
                Mailbox {
                    has_children: cache
                        .mailboxes
                        .items
                        .iter()
                        .any(|child| child.parent_id == mailbox.document_id),
                    is_subscribed: mailbox.subscribers.contains(&access_token.primary_id()),
                    special_use: match mailbox.role {
                        SpecialUse::Trash => Some(Attribute::Trash),
                        SpecialUse::Junk => Some(Attribute::Junk),
                        SpecialUse::Drafts => Some(Attribute::Drafts),
                        SpecialUse::Archive => Some(Attribute::Archive),
                        SpecialUse::Sent => Some(Attribute::Sent),
                        SpecialUse::Important => Some(Attribute::Important),
                        _ => None,
                    },
                    total_messages: cache.in_mailbox(mailbox.document_id).count() as u64,
                    total_unseen: cache
                        .in_mailbox_without_keyword(mailbox.document_id, &Keyword::Seen)
                        .count() as u64,
                    total_deleted: cache
                        .in_mailbox_with_keyword(mailbox.document_id, &Keyword::Deleted)
                        .count() as u64,
                    uid_validity: mailbox.uid_validity as u64,
                    uid_next: self
                        .get_uid_next(&MailboxId {
                            account_id,
                            mailbox_id: mailbox.document_id,
                        })
                        .await
                        .caused_by(trc::location!())? as u64,
                    total_deleted_storage: None,
                    size: None,
                },
            );
        }

        Ok(account.into())
    }

    pub async fn synchronize_mailboxes(
        &self,
        return_changes: bool,
    ) -> trc::Result<Option<MailboxSync>> {
        let mut changes = if return_changes {
            MailboxSync::default().into()
        } else {
            None
        };

        // Obtain access token
        let access_token = self
            .server
            .get_access_token(self.account_id)
            .await
            .caused_by(trc::location!())?;
        let state = access_token.state();

        // Shared mailboxes might have changed
        let mut added_accounts = Vec::new();
        if self.state.load(Ordering::Relaxed) != state {
            // Remove unlinked shared accounts
            let mut added_account_ids = Vec::new();
            {
                let mut mailboxes = self.mailboxes.lock();
                let mut new_accounts = Vec::with_capacity(mailboxes.len());
                let has_access_to = access_token
                    .shared_accounts(Collection::Mailbox)
                    .copied()
                    .collect::<Vec<_>>();
                for account in mailboxes.drain(..) {
                    if access_token.is_primary_id(account.account_id)
                        || has_access_to.contains(&account.account_id)
                    {
                        new_accounts.push(account);
                    } else {
                        // Add unshared mailboxes to deleted list
                        if let Some(changes) = &mut changes {
                            for (mailbox_name, _) in account.mailbox_names {
                                changes.deleted.push(mailbox_name);
                            }
                        }
                    }
                }

                // Add new shared account ids
                for account_id in has_access_to {
                    if !new_accounts
                        .iter()
                        .skip(1)
                        .any(|m| m.account_id == account_id)
                    {
                        added_account_ids.push(account_id);
                    }
                }
                *mailboxes = new_accounts;
            }

            // Fetch mailboxes for each new shared account
            for account_id in added_account_ids {
                let prefix: String = format!(
                    "{}/{}",
                    self.server.core.jmap.shared_folder,
                    self.server
                        .store()
                        .get_principal_name(account_id)
                        .await
                        .caused_by(trc::location!())?
                        .unwrap_or_else(|| Id::from(account_id).to_string())
                );
                added_accounts.push(
                    self.fetch_account_mailboxes(account_id, prefix.into(), &access_token, None)
                        .await?
                        .unwrap(),
                );
            }

            // Update state
            self.state.store(state, Ordering::Relaxed);
        }

        // Fetch mailbox changes for all accounts
        let mut changed_accounts = Vec::new();
        let account_states = self
            .mailboxes
            .lock()
            .iter()
            .map(|m| (m.account_id, m.prefix.clone(), m.last_change_id))
            .collect::<Vec<_>>();
        for (account_id, prefix, last_state) in account_states {
            if let Some(changed_account) = self
                .fetch_account_mailboxes(account_id, prefix, &access_token, last_state.into())
                .await
                .caused_by(trc::location!())?
            {
                changed_accounts.push(changed_account);
            }
        }

        // Update mailboxes
        if !changed_accounts.is_empty() || !added_accounts.is_empty() {
            let mut mailboxes = self.mailboxes.lock();

            for changed_account in changed_accounts {
                if let Some(pos) = mailboxes
                    .iter()
                    .position(|a| a.account_id == changed_account.account_id)
                {
                    // Add changes and deletions
                    if let Some(changes) = &mut changes {
                        let old_account = &mailboxes[pos];
                        let new_account = &changed_account;

                        // Add new mailboxes
                        for (mailbox_name, mailbox_id) in new_account.mailbox_names.iter() {
                            if let Some(old_mailbox) = old_account.mailbox_state.get(mailbox_id) {
                                if let Some(mailbox) = new_account.mailbox_state.get(mailbox_id) {
                                    if mailbox.total_messages != old_mailbox.total_messages
                                        || mailbox.total_unseen != old_mailbox.total_unseen
                                    {
                                        changes.changed.push(mailbox_name.clone());
                                    }
                                }
                            } else {
                                changes.added.push(mailbox_name.clone());
                            }
                        }

                        // Add deleted mailboxes
                        for (mailbox_name, mailbox_id) in &old_account.mailbox_names {
                            if !new_account.mailbox_state.contains_key(mailbox_id) {
                                changes.deleted.push(mailbox_name.clone());
                            }
                        }
                    }

                    mailboxes[pos] = changed_account;
                } else {
                    // Add newly shared accounts
                    if let Some(changes) = &mut changes {
                        changes
                            .added
                            .extend(changed_account.mailbox_names.keys().cloned());
                    }

                    mailboxes.push(changed_account);
                }
            }

            if !added_accounts.is_empty() {
                // Add newly shared accounts
                if let Some(changes) = &mut changes {
                    for added_account in &added_accounts {
                        changes
                            .added
                            .extend(added_account.mailbox_names.keys().cloned());
                    }
                }
                mailboxes.extend(added_accounts);
            }
        }

        Ok(changes)
    }

    pub fn get_mailbox_by_name(&self, mailbox_name: &str) -> Option<MailboxId> {
        let is_inbox = mailbox_name.eq_ignore_ascii_case("inbox");
        for account in self.mailboxes.lock().iter() {
            if account
                .prefix
                .as_ref()
                .is_none_or(|p| mailbox_name.starts_with(p.as_str()))
            {
                for (mailbox_name_, mailbox_id_) in account.mailbox_names.iter() {
                    if (!is_inbox && mailbox_name_ == mailbox_name)
                        || (is_inbox && *mailbox_id_ == INBOX_ID)
                    {
                        return MailboxId {
                            account_id: account.account_id,
                            mailbox_id: *mailbox_id_,
                        }
                        .into();
                    }
                }
            }
        }
        None
    }

    pub async fn check_mailbox_acl(
        &self,
        account_id: u32,
        document_id: u32,
        item: Acl,
    ) -> trc::Result<bool> {
        let access_token = self.get_access_token().await?;
        Ok(access_token.is_member(account_id)
            || self
                .server
                .get_archive(account_id, Collection::Mailbox, document_id)
                .await
                .and_then(|mailbox| {
                    if let Some(mailbox) = mailbox {
                        Ok(Some(
                            mailbox
                                .unarchive::<email::mailbox::Mailbox>()?
                                .acls
                                .effective_acl(&access_token)
                                .contains(item),
                        ))
                    } else {
                        Ok(None)
                    }
                })?
                .ok_or_else(|| {
                    trc::ImapEvent::Error
                        .caused_by(trc::location!())
                        .details("Mailbox no longer exists.")
                })?)
    }
}
