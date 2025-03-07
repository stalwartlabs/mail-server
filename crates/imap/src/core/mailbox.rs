/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use common::{
    AccountId, Mailbox,
    auth::AccessToken,
    config::jmap::settings::{ArchivedSpecialUse, SpecialUse},
    listener::{SessionStream, limiter::InFlight},
    sharing::EffectiveAcl,
};
use directory::{QueryBy, backend::internal::PrincipalField};
use email::mailbox::{INBOX_ID, manage::MailboxFnc};
use imap_proto::protocol::list::Attribute;
use indexmap::IndexMap;
use jmap_proto::types::{acl::Acl, collection::Collection, id::Id, property::Property};
use parking_lot::Mutex;
use std::sync::{Arc, atomic::Ordering};
use store::{
    query::log::{Change, Query},
    write::Archive,
};
use trc::AddContext;
use utils::topological::TopologicalSort;

use super::{Account, MailboxId, MailboxSync, Session, SessionData};

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
                .fetch_account_mailboxes(session.account_id, None, &access_token)
                .await
                .caused_by(trc::location!())?,
        ];

        // Fetch shared mailboxes
        for &account_id in access_token.shared_accounts(Collection::Mailbox) {
            mailboxes.push(
                session
                    .fetch_account_mailboxes(
                        account_id,
                        format!(
                            "{}/{}",
                            session.server.core.jmap.shared_folder,
                            session
                                .server
                                .core
                                .storage
                                .directory
                                .query(QueryBy::Id(account_id), false)
                                .await
                                .unwrap_or_default()
                                .and_then(|mut p| p.take_str(PrincipalField::Name))
                                .unwrap_or_else(|| Id::from(account_id).to_string())
                        )
                        .into(),
                        &access_token,
                    )
                    .await
                    .caused_by(trc::location!())?,
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
    ) -> trc::Result<Account> {
        let state_mailbox = self
            .server
            .core
            .storage
            .data
            .get_last_change_id(account_id, Collection::Mailbox)
            .await
            .caused_by(trc::location!())?;
        let state_email = self
            .server
            .core
            .storage
            .data
            .get_last_change_id(account_id, Collection::Email)
            .await
            .caused_by(trc::location!())?;
        let cached_account_id = AccountId {
            account_id,
            primary_id: access_token.primary_id(),
        };
        if let Some(cached_account) = self
            .server
            .inner
            .cache
            .account
            .get(&cached_account_id)
            .and_then(|cached_account| {
                if cached_account.state_mailbox == state_mailbox
                    && cached_account.state_email == state_email
                {
                    Some(cached_account)
                } else {
                    None
                }
            })
        {
            return Ok(cached_account.as_ref().clone());
        }

        let mailbox_ids = if access_token.is_primary_id(account_id)
            || access_token.member_of.contains(&account_id)
        {
            self.server
                .mailbox_get_or_create(account_id)
                .await
                .caused_by(trc::location!())?
        } else {
            self.server
                .shared_containers(access_token, account_id, Collection::Mailbox, Acl::Read)
                .await
                .caused_by(trc::location!())?
        };

        // Fetch mailboxes
        struct MailboxData {
            mailbox_id: u32,
            parent_id: u32,
            role: SpecialUse,
            name: String,
            is_subscribed: bool,
        }

        let mut mailboxes = AHashMap::with_capacity(10);
        let mut special_uses = AHashMap::new();
        let mut mailbox_topology = TopologicalSort::with_capacity(10);

        for (mailbox_id, mailbox_) in self
            .server
            .get_properties::<Archive, _>(
                account_id,
                Collection::Mailbox,
                &mailbox_ids,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
        {
            let mailbox = mailbox_
                .unarchive::<email::mailbox::Mailbox>()
                .caused_by(trc::location!())?;
            // Map special uses
            let role = SpecialUse::from(&mailbox.role);
            if !matches!(mailbox.role, ArchivedSpecialUse::None) {
                special_uses.insert(role, mailbox_id);
            }

            // Build mailbox data
            let mailbox = MailboxData {
                mailbox_id,
                parent_id: u32::from(mailbox.parent_id),
                role,
                name: mailbox.name.to_string(),
                is_subscribed: mailbox.is_subscribed(access_token.primary_id()),
            };
            mailbox_topology.insert(mailbox.parent_id, mailbox.mailbox_id + 1);

            // Add mailbox id
            mailboxes.insert(mailbox.mailbox_id, mailbox);
        }

        // Build account
        let message_ids = self
            .server
            .get_document_ids(account_id, Collection::Email)
            .await
            .caused_by(trc::location!())?;
        let mut account = Account {
            account_id,
            prefix: mailbox_prefix,
            mailbox_names: IndexMap::with_capacity(mailboxes.len()),
            mailbox_state: AHashMap::with_capacity(mailboxes.len()),
            state_mailbox,
            state_email,
            obj_size: 0,
        };
        account.obj_size = (std::mem::size_of::<Account>()
            + account.prefix.as_ref().map_or(0, |p| p.len())
            + account
                .mailbox_names
                .keys()
                .map(|k| k.len() + std::mem::size_of::<u32>())
                .sum::<usize>()
            + (account.mailbox_state.len()
                * (std::mem::size_of::<email::mailbox::Mailbox>() + std::mem::size_of::<u32>())))
            as u64;

        // Build mailbox state
        for mailbox in mailboxes.values() {
            account.mailbox_state.insert(
                mailbox.mailbox_id,
                Mailbox {
                    has_children: mailboxes
                        .values()
                        .any(|child| child.parent_id == mailbox.mailbox_id + 1),
                    is_subscribed: mailbox.is_subscribed,
                    special_use: match mailbox.role {
                        SpecialUse::Trash => Some(Attribute::Trash),
                        SpecialUse::Junk => Some(Attribute::Junk),
                        SpecialUse::Drafts => Some(Attribute::Drafts),
                        SpecialUse::Archive => Some(Attribute::Archive),
                        SpecialUse::Sent => Some(Attribute::Sent),
                        SpecialUse::Important => Some(Attribute::Important),
                        _ => None,
                    },
                    total_messages: self
                        .server
                        .get_tag(
                            account_id,
                            Collection::Email,
                            Property::MailboxIds,
                            mailbox.mailbox_id,
                        )
                        .await
                        .caused_by(trc::location!())?
                        .map(|v| v.len())
                        .unwrap_or(0)
                        .into(),
                    total_unseen: self
                        .server
                        .mailbox_unread_tags(account_id, mailbox.mailbox_id, &message_ids)
                        .await
                        .caused_by(trc::location!())?
                        .map(|v| v.len())
                        .unwrap_or(0)
                        .into(),
                    ..Default::default()
                },
            );
        }

        // Build mailbox tree
        for mailbox_id in mailbox_topology.into_iterator() {
            if mailbox_id == 0 {
                continue;
            }
            let mailbox_id = mailbox_id - 1;
            let (mailbox_name, parent_id) = mailboxes
                .get(&mailbox_id)
                .map(|m| {
                    (
                        m.name.as_str(),
                        if m.parent_id == 0 {
                            None
                        } else {
                            Some(m.parent_id - 1)
                        },
                    )
                })
                .unwrap();

            // Obtain folder name
            let (mailbox_name, did_rename) = if mailbox_id != INBOX_ID || account.prefix.is_some() {
                // If there is another mailbox called Inbox, rename it to avoid conflicts
                if parent_id.is_none() || !mailbox_name.eq_ignore_ascii_case("inbox") {
                    (mailbox_name, false)
                } else {
                    ("INBOX 2", true)
                }
            } else {
                ("INBOX", true)
            };

            // Map special use folder aliases to their internal ids
            let effective_mailbox_id = self
                .server
                .core
                .jmap
                .default_folders
                .iter()
                .find(|f| f.name == mailbox_name || f.aliases.iter().any(|a| a == mailbox_name))
                .and_then(|f| special_uses.get(&f.special_use))
                .copied()
                .unwrap_or(mailbox_id);

            // Update mailbox name
            let full_name = if let Some(parent_id) = parent_id {
                let full_name = format!(
                    "{}/{}",
                    mailboxes
                        .get(&parent_id)
                        .map(|m| m.name.as_str())
                        .unwrap_or_default(),
                    mailbox_name
                );
                mailboxes.get_mut(&mailbox_id).unwrap().name = full_name.clone();
                full_name
            } else if let Some(prefix) = &account.prefix {
                let full_name = format!("{prefix}/{mailbox_name}");
                mailboxes.get_mut(&mailbox_id).unwrap().name = full_name.clone();
                full_name
            } else if did_rename {
                let full_name = mailbox_name.to_string();
                mailboxes.get_mut(&mailbox_id).unwrap().name = full_name.clone();
                full_name
            } else {
                mailbox_name.to_string()
            };

            // Insert mailbox
            account
                .mailbox_names
                .insert(full_name, effective_mailbox_id);
        }

        // Update cache
        self.server
            .inner
            .cache
            .account
            .insert(cached_account_id, Arc::new(account.clone()));

        Ok(account)
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
                let prefix = format!(
                    "{}/{}",
                    self.server.core.jmap.shared_folder,
                    self.server
                        .core
                        .storage
                        .directory
                        .query(QueryBy::Id(account_id), false)
                        .await
                        .caused_by(trc::location!())?
                        .and_then(|mut p| p.take_str(PrincipalField::Name))
                        .unwrap_or_else(|| Id::from(account_id).to_string())
                );
                added_accounts.push(
                    self.fetch_account_mailboxes(account_id, prefix.into(), &access_token)
                        .await?,
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
            .map(|m| (m.account_id, m.state_mailbox))
            .collect::<Vec<_>>();
        for (account_id, last_state) in account_states {
            let changelog = self
                .server
                .store()
                .changes(
                    account_id,
                    Collection::Mailbox,
                    last_state.map(Query::Since).unwrap_or(Query::All),
                )
                .await?;
            if !changelog.changes.is_empty() {
                let mut has_changes = false;
                let mut has_child_changes = false;

                for change in changelog.changes {
                    match change {
                        Change::Insert(_) | Change::Update(_) | Change::Delete(_) => {
                            has_changes = true
                        }
                        Change::ChildUpdate(_) => has_child_changes = true,
                    }
                }

                if has_child_changes && !has_changes && changes.is_none() {
                    // Only child changes, no need to re-fetch mailboxes
                    let state_email = self
                        .server
                        .core
                        .storage
                        .data
                        .get_last_change_id(account_id, Collection::Email)
                        .await
                        .caused_by(trc::location!())?;
                    let state_mailbox = Some(changelog.to_change_id);
                    for account in self.mailboxes.lock().iter_mut() {
                        if account.account_id == account_id {
                            account.mailbox_state.values_mut().for_each(|v| {
                                v.total_deleted = None;
                                v.total_unseen = None;
                                v.total_messages = None;
                                v.size = None;
                                v.uid_next = None;
                            });
                            account.state_mailbox = state_mailbox;
                            account.state_email = state_email;
                            break;
                        }
                    }

                    // Update cache
                    let ac_id = AccountId {
                        account_id,
                        primary_id: access_token.primary_id(),
                    };
                    if let Some(cached_account_) = self.server.inner.cache.account.get(&ac_id) {
                        if cached_account_.state_mailbox != state_mailbox
                            || cached_account_.state_email != state_email
                        {
                            let mut cached_account = cached_account_.as_ref().clone();
                            cached_account.mailbox_state.values_mut().for_each(|v| {
                                v.total_deleted = None;
                                v.total_unseen = None;
                                v.total_messages = None;
                                v.size = None;
                                v.uid_next = None;
                            });
                            cached_account.state_mailbox = state_mailbox;
                            cached_account.state_email = state_email;
                            self.server
                                .inner
                                .cache
                                .account
                                .insert(ac_id, Arc::new(cached_account));
                        }
                    }
                } else {
                    // Refresh mailboxes for changed account
                    let mailbox_prefix = if !access_token.is_primary_id(account_id) {
                        format!(
                            "{}/{}",
                            self.server.core.jmap.shared_folder,
                            self.server
                                .core
                                .storage
                                .directory
                                .query(QueryBy::Id(account_id), false)
                                .await
                                .caused_by(trc::location!())?
                                .and_then(|mut p| p.take_str(PrincipalField::Name))
                                .unwrap_or_else(|| Id::from(account_id).to_string())
                        )
                        .into()
                    } else {
                        None
                    };

                    changed_accounts.push(
                        self.fetch_account_mailboxes(account_id, mailbox_prefix, &access_token)
                            .await?,
                    );
                }
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
                                    if mailbox.total_messages.unwrap_or(0)
                                        != old_mailbox.total_messages.unwrap_or(0)
                                        || mailbox.total_unseen.unwrap_or(0)
                                            != old_mailbox.total_unseen.unwrap_or(0)
                                    {
                                        changes.changed.push(mailbox_name.to_string());
                                    }
                                }
                            } else {
                                changes.added.push(mailbox_name.to_string());
                            }
                        }

                        // Add deleted mailboxes
                        for (mailbox_name, mailbox_id) in &old_account.mailbox_names {
                            if !new_account.mailbox_state.contains_key(mailbox_id) {
                                changes.deleted.push(mailbox_name.to_string());
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
                .is_none_or(|p| mailbox_name.starts_with(p))
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
                .get_property::<Archive>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
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
