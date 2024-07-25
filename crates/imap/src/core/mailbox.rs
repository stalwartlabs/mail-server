use std::{
    collections::BTreeMap,
    sync::{atomic::Ordering, Arc},
};

use ahash::AHashMap;
use common::{
    config::jmap::settings::SpecialUse,
    listener::{limiter::InFlight, SessionStream},
};
use directory::QueryBy;
use imap_proto::protocol::list::Attribute;
use jmap::{
    auth::{acl::EffectiveAcl, AccessToken},
    mailbox::INBOX_ID,
};
use jmap_proto::{
    object::Object,
    types::{acl::Acl, collection::Collection, id::Id, property::Property, value::Value},
};
use parking_lot::Mutex;
use store::query::log::{Change, Query};
use trc::AddContext;
use utils::lru_cache::LruCached;

use super::{Account, AccountId, Mailbox, MailboxId, MailboxSync, Session, SessionData};

impl<T: SessionStream> SessionData<T> {
    pub async fn new(
        session: &Session<T>,
        access_token: &AccessToken,
        in_flight: Option<InFlight>,
    ) -> trc::Result<Self> {
        let mut session = SessionData {
            stream_tx: session.stream_tx.clone(),
            jmap: session.jmap.clone(),
            imap: session.imap.clone(),
            account_id: access_token.primary_id(),
            session_id: session.session_id,
            mailboxes: Mutex::new(vec![]),
            state: access_token.state().into(),
            in_flight,
        };

        // Fetch mailboxes for the main account
        let mut mailboxes = vec![session
            .fetch_account_mailboxes(session.account_id, None, access_token)
            .await
            .caused_by(trc::location!())?];

        // Fetch shared mailboxes
        for &account_id in access_token.shared_accounts(Collection::Mailbox) {
            mailboxes.push(
                session
                    .fetch_account_mailboxes(
                        account_id,
                        format!(
                            "{}/{}",
                            session.jmap.core.jmap.shared_folder,
                            session
                                .jmap
                                .core
                                .storage
                                .directory
                                .query(QueryBy::Id(account_id), false)
                                .await
                                .unwrap_or_default()
                                .map(|p| p.name)
                                .unwrap_or_else(|| Id::from(account_id).to_string())
                        )
                        .into(),
                        access_token,
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
            .jmap
            .core
            .storage
            .data
            .get_last_change_id(account_id, Collection::Mailbox)
            .await
            .caused_by(trc::location!())?;
        let state_email = self
            .jmap
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
        if let Some(cached_account) =
            self.imap
                .cache_account
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
            self.jmap
                .mailbox_get_or_create(account_id)
                .await
                .caused_by(trc::location!())?
        } else {
            self.jmap
                .shared_documents(access_token, account_id, Collection::Mailbox, Acl::Read)
                .await
                .caused_by(trc::location!())?
        };

        // Fetch mailboxes
        let mut mailboxes = Vec::with_capacity(10);
        let mut special_uses = AHashMap::new();
        for (mailbox_id, values) in self
            .jmap
            .get_properties::<Object<Value>, _, _>(
                account_id,
                Collection::Mailbox,
                &mailbox_ids,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
        {
            // Map special uses
            if let Some(Value::Text(role)) = values.properties.get(&Property::Role) {
                let special_use = match role.as_str() {
                    "archive" => SpecialUse::Archive,
                    "drafts" => SpecialUse::Drafts,
                    "junk" => SpecialUse::Junk,
                    "sent" => SpecialUse::Sent,
                    "trash" => SpecialUse::Trash,
                    "inbox" => SpecialUse::Inbox,
                    _ => SpecialUse::None,
                };
                if special_use != SpecialUse::None {
                    special_uses.insert(special_use, mailbox_id);
                }
            }

            // Add mailbox id
            mailboxes.push((
                mailbox_id,
                values
                    .properties
                    .get(&Property::ParentId)
                    .map(|parent_id| match parent_id {
                        Value::Id(value) => value.document_id(),
                        _ => 0,
                    })
                    .unwrap_or(0),
                values,
            ));
        }

        // Build tree
        let mut iter = mailboxes.iter();
        let mut parent_id = 0;
        let mut path = Vec::new();
        let mut iter_stack = Vec::new();
        let message_ids = self
            .jmap
            .get_document_ids(account_id, Collection::Email)
            .await
            .caused_by(trc::location!())?;

        if let Some(mailbox_prefix) = &mailbox_prefix {
            path.push(mailbox_prefix.to_string());
        };

        let mut account = Account {
            account_id,
            prefix: mailbox_prefix,
            mailbox_names: BTreeMap::new(),
            mailbox_state: AHashMap::with_capacity(mailboxes.len()),
            state_mailbox,
            state_email,
        };

        loop {
            while let Some((mailbox_id, mailbox_parent_id, mailbox)) = iter.next() {
                if *mailbox_parent_id == parent_id {
                    let mut mailbox_path = path.clone();
                    if *mailbox_id != INBOX_ID || account.prefix.is_some() {
                        mailbox_path.push(
                            mailbox
                                .get(&Property::Name)
                                .as_string()
                                .unwrap_or_default()
                                .to_string(),
                        );
                    } else {
                        mailbox_path.push("INBOX".to_string());
                    }
                    let has_children = mailboxes
                        .iter()
                        .any(|(_, child_parent_id, _)| *child_parent_id == *mailbox_id + 1);

                    account.mailbox_state.insert(
                        *mailbox_id,
                        Mailbox {
                            has_children,
                            is_subscribed: mailbox
                                .properties
                                .get(&Property::IsSubscribed)
                                .map(|parent_id| match parent_id {
                                    Value::List(values) => values
                                        .contains(&Value::Id(access_token.primary_id().into())),
                                    _ => false,
                                })
                                .unwrap_or(false),
                            special_use: mailbox.properties.get(&Property::Role).and_then(
                                |parent_id| match parent_id {
                                    Value::Text(role) => Attribute::try_from(role.as_str()).ok(),
                                    _ => None,
                                },
                            ),
                            total_messages: self
                                .jmap
                                .get_tag(
                                    account_id,
                                    Collection::Email,
                                    Property::MailboxIds,
                                    *mailbox_id,
                                )
                                .await
                                .caused_by(trc::location!())?
                                .map(|v| v.len() as u32)
                                .unwrap_or(0)
                                .into(),
                            total_unseen: self
                                .jmap
                                .mailbox_unread_tags(account_id, *mailbox_id, &message_ids)
                                .await
                                .caused_by(trc::location!())?
                                .map(|v| v.len() as u32)
                                .unwrap_or(0)
                                .into(),
                            ..Default::default()
                        },
                    );

                    let mut mailbox_name = mailbox_path.join("/");
                    if mailbox_name.eq_ignore_ascii_case("inbox") && *mailbox_id != INBOX_ID {
                        // If there is another mailbox called Inbox, rename it to avoid conflicts
                        mailbox_name = format!("{mailbox_name} 2");
                    }

                    // Map special use folder aliases to their internal ids
                    let effective_mailbox_id = self
                        .jmap
                        .core
                        .jmap
                        .default_folders
                        .iter()
                        .find(|f| {
                            f.name == mailbox_name || f.aliases.iter().any(|a| a == &mailbox_name)
                        })
                        .and_then(|f| special_uses.get(&f.special_use))
                        .copied()
                        .unwrap_or(*mailbox_id);

                    account
                        .mailbox_names
                        .insert(mailbox_name, effective_mailbox_id);

                    if has_children && iter_stack.len() < 100 {
                        iter_stack.push((iter, parent_id, path));
                        parent_id = *mailbox_id + 1;
                        path = mailbox_path;
                        iter = mailboxes.iter();
                    }
                }
            }

            if let Some((prev_iter, prev_parent_id, prev_path)) = iter_stack.pop() {
                iter = prev_iter;
                parent_id = prev_parent_id;
                path = prev_path;
            } else {
                break;
            }
        }

        // Update cache
        self.imap
            .cache_account
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
            .jmap
            .get_cached_access_token(self.account_id)
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
                    self.jmap.core.jmap.shared_folder,
                    self.jmap
                        .core
                        .storage
                        .directory
                        .query(QueryBy::Id(account_id), false)
                        .await
                        .unwrap_or_default()
                        .map(|p| p.name)
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
                .jmap
                .changes_(
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
                        .jmap
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
                    if let Some(cached_account_) =
                        self.imap.cache_account.lock().get_mut(&AccountId {
                            account_id,
                            primary_id: access_token.primary_id(),
                        })
                    {
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
                            *cached_account_ = Arc::new(cached_account);
                        }
                    }
                } else {
                    // Refresh mailboxes for changed account
                    let mailbox_prefix = if !access_token.is_primary_id(account_id) {
                        format!(
                            "{}/{}",
                            self.jmap.core.jmap.shared_folder,
                            self.jmap
                                .core
                                .storage
                                .directory
                                .query(QueryBy::Id(account_id), false)
                                .await
                                .caused_by(trc::location!())?
                                .map(|p| p.name)
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
                .map_or(true, |p| mailbox_name.starts_with(p))
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
                .jmap
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
                .await?
                .map(|mailbox| mailbox.effective_acl(&access_token).contains(item))
                .ok_or_else(|| {
                    trc::ImapEvent::Error
                        .caused_by(trc::location!())
                        .details("Mailbox no longer exists.")
                })?)
    }
}
