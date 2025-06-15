/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::MessageCacheState};
use common::{
    Server, auth::AccessToken, config::jmap::settings::SpecialUse, sharing::EffectiveAcl,
    storage::index::ObjectIndexBuilder,
};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::{Mailbox, destroy::MailboxDestroy},
};
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::mailbox::SetArguments,
    response::references::EvalObjectReferences,
    types::{
        acl::Acl,
        collection::Collection,
        id::Id,
        property::Property,
        state::State,
        value::{MaybePatchValue, Object, SetValue, Value},
    },
};
use store::{
    roaring::RoaringBitmap,
    write::{Archive, BatchBuilder, assert::AssertValue},
};
use trc::AddContext;
use utils::config::utils::ParseValue;

#[allow(unused_imports)]
use email::mailbox::{INBOX_ID, JUNK_ID, TRASH_ID, UidMailbox};
use std::future::Future;

pub struct SetContext<'x> {
    account_id: u32,
    access_token: &'x AccessToken,
    is_shared: bool,
    response: SetResponse,
    mailbox_ids: RoaringBitmap,
    will_destroy: Vec<Id>,
}

pub trait MailboxSet: Sync + Send {
    fn mailbox_set(
        &self,
        request: SetRequest<SetArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;

    fn mailbox_set_item(
        &self,
        changes_: Object<SetValue>,
        update: Option<(u32, Archive<Mailbox>)>,
        ctx: &SetContext,
    ) -> impl Future<Output = trc::Result<Result<ObjectIndexBuilder<Mailbox, Mailbox>, SetError>>> + Send;
}

impl MailboxSet for Server {
    #[allow(clippy::blocks_in_conditions)]
    async fn mailbox_set(
        &self,
        mut request: SetRequest<SetArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let on_destroy_remove_emails = request.arguments.on_destroy_remove_emails.unwrap_or(false);
        let cache = self.get_cached_messages(account_id).await?;
        let mut ctx = SetContext {
            account_id,
            is_shared: access_token.is_shared(account_id),
            access_token,
            response: self
                .prepare_set_response(&request, cache.assert_state(true, &request.if_in_state)?)
                .await?,
            mailbox_ids: RoaringBitmap::from_iter(cache.mailboxes.index.keys()),
            will_destroy: request.unwrap_destroy(),
        };
        let mut change_id = None;

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            match self.mailbox_set_item(object, None, &ctx).await? {
                Ok(builder) => {
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Mailbox);

                    let parent_id = builder.changes().unwrap().parent_id;
                    if parent_id > 0 {
                        batch
                            .update_document(parent_id - 1)
                            .assert_value(Property::Value, AssertValue::Some);
                    }

                    let document_id = self
                        .store()
                        .assign_document_ids(account_id, Collection::Mailbox, 1)
                        .await
                        .caused_by(trc::location!())?;

                    batch
                        .create_document(document_id)
                        .custom(builder)
                        .caused_by(trc::location!())?
                        .commit_point();

                    ctx.mailbox_ids.insert(document_id);
                    ctx.response.created(id, document_id);
                }
                Err(err) => {
                    ctx.response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        if !batch.is_empty() {
            change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?
                .into();
        }

        // Process updates
        let mut will_update = Vec::with_capacity(request.update.as_ref().map_or(0, |u| u.len()));
        let mut batch = BatchBuilder::new();
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if ctx.will_destroy.contains(&id) {
                ctx.response
                    .not_updated
                    .append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain mailbox
            let document_id = id.document_id();
            if let Some(mailbox) = self
                .get_archive(account_id, Collection::Mailbox, document_id)
                .await?
            {
                // Validate ACL
                let mailbox = mailbox
                    .into_deserialized::<email::mailbox::Mailbox>()
                    .caused_by(trc::location!())?;
                if ctx.is_shared {
                    let acl = mailbox.inner.acls.effective_acl(access_token);
                    if !acl.contains(Acl::Modify) {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden()
                                .with_description("You are not allowed to modify this mailbox."),
                        );
                        continue 'update;
                    } else if object.0.contains_key(&Property::Acl)
                        && !acl.contains(Acl::Administer)
                    {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "You are not allowed to change the permissions of this mailbox.",
                            ),
                        );
                        continue 'update;
                    }
                }

                match self
                    .mailbox_set_item(object, (document_id, mailbox).into(), &ctx)
                    .await?
                {
                    Ok(builder) => {
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::Mailbox);

                        let parent_id = builder.changes().unwrap().parent_id;
                        if parent_id > 0 {
                            batch
                                .update_document(parent_id - 1)
                                .assert_value(Property::Value, AssertValue::Some);
                        }

                        batch
                            .update_document(document_id)
                            .custom(builder)
                            .caused_by(trc::location!())?
                            .commit_point();
                        will_update.push(id);
                    }
                    Err(err) => {
                        ctx.response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
            } else {
                ctx.response.not_updated.append(id, SetError::not_found());
            }
        }

        if !batch.is_empty() {
            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id_) => {
                    change_id = Some(change_id_);
                    for id in will_update {
                        ctx.response.updated.append(id, None);
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    for id in will_update {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this mailbox, please try again.",
                            ),
                        );
                    }
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        // Process deletions
        for id in ctx.will_destroy {
            match self
                .mailbox_destroy(
                    account_id,
                    id.document_id(),
                    ctx.access_token,
                    on_destroy_remove_emails,
                )
                .await?
            {
                Ok(change_id_) => {
                    if change_id_.is_some() {
                        change_id = change_id_;
                    }
                    ctx.response.destroyed.push(id);
                }
                Err(err) => {
                    ctx.response.not_destroyed.append(id, err);
                }
            }
        }

        // Write changes
        if let Some(change_id) = change_id {
            ctx.response.new_state = State::Exact(change_id).into();
        }

        Ok(ctx.response)
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn mailbox_set_item(
        &self,
        changes_: Object<SetValue>,
        update: Option<(u32, Archive<Mailbox>)>,
        ctx: &SetContext<'_>,
    ) -> trc::Result<Result<ObjectIndexBuilder<Mailbox, Mailbox>, SetError>> {
        // Parse properties
        let mut changes = update
            .as_ref()
            .map(|(_, obj)| obj.inner.clone())
            .unwrap_or_else(|| Mailbox::new(String::new()));
        let mut has_acl_changes = false;
        for (property, value) in changes_.0 {
            let value = match ctx.response.eval_object_references(value) {
                Ok(value) => value,
                Err(err) => {
                    return Ok(Err(err));
                }
            };
            match (&property, value) {
                (Property::Name, MaybePatchValue::Value(Value::Text(value))) => {
                    let value = value.trim();
                    if !value.is_empty() && value.len() < self.core.jmap.mailbox_name_max_len {
                        changes.name = value.into();
                    } else {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(Property::Name)
                            .with_description(
                                if !value.is_empty() {
                                    "Mailbox name is too long."
                                } else {
                                    "Mailbox name cannot be empty."
                                }
                                .to_string(),
                            )));
                    }
                }
                (Property::ParentId, MaybePatchValue::Value(Value::Id(value))) => {
                    let parent_id = value.document_id();
                    if ctx.will_destroy.contains(&value) {
                        return Ok(Err(SetError::will_destroy()
                            .with_description("Parent ID will be destroyed.")));
                    } else if !ctx.mailbox_ids.contains(parent_id) {
                        return Ok(Err(SetError::invalid_properties()
                            .with_description("Parent ID does not exist.")));
                    }
                    changes.parent_id = parent_id + 1;
                }
                (Property::ParentId, MaybePatchValue::Value(Value::Null)) => {
                    changes.parent_id = 0;
                }
                (Property::IsSubscribed, MaybePatchValue::Value(Value::Bool(subscribe))) => {
                    let account_id = ctx.access_token.primary_id();
                    if subscribe {
                        if !changes.subscribers.contains(&account_id) {
                            changes.subscribers.push(account_id);
                        }
                    } else {
                        changes.subscribers.retain(|id| *id != account_id);
                    }
                }
                (Property::Role, MaybePatchValue::Value(Value::Text(value))) => {
                    let role = value.trim();
                    if let Ok(role) = SpecialUse::parse_value(role) {
                        changes.role = role;
                    } else {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(Property::Role)
                            .with_description(format!("Invalid role {role:?}."))));
                    }
                }
                (Property::Role, MaybePatchValue::Value(Value::Null)) => {
                    changes.role = SpecialUse::None;
                }
                (Property::SortOrder, MaybePatchValue::Value(Value::UnsignedInt(value))) => {
                    changes.sort_order = Some(value as u32);
                }
                (Property::Acl, value) => {
                    has_acl_changes = true;
                    match self
                        .acl_set(
                            &mut changes.acls,
                            update.as_ref().map(|(_, obj)| obj.inner.acls.as_slice()),
                            value,
                        )
                        .await
                    {
                        Ok(_) => continue,
                        Err(err) => {
                            return Ok(Err(err));
                        }
                    }
                }

                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property)
                        .with_description("Invalid property or value.".to_string())));
                }
            }
        }

        // Validate depth and circular parent-child relationship
        if update
            .as_ref()
            .is_none_or(|(_, m)| m.inner.parent_id != changes.parent_id)
        {
            let mut mailbox_parent_id = changes.parent_id;
            let current_mailbox_id = update
                .as_ref()
                .map_or(u32::MAX, |(mailbox_id, _)| *mailbox_id + 1);
            let mut success = false;
            for depth in 0..self.core.jmap.mailbox_max_depth {
                if mailbox_parent_id == current_mailbox_id {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::ParentId)
                        .with_description("Mailbox cannot be a parent of itself.")));
                } else if mailbox_parent_id == 0 {
                    if depth == 0 && ctx.is_shared {
                        return Ok(Err(SetError::forbidden()
                            .with_description("You are not allowed to create root folders.")));
                    }
                    success = true;
                    break;
                }
                let parent_document_id = mailbox_parent_id - 1;

                if let Some(mailbox_) = self
                    .get_archive(ctx.account_id, Collection::Mailbox, parent_document_id)
                    .await?
                {
                    let mailbox = mailbox_
                        .unarchive::<email::mailbox::Mailbox>()
                        .caused_by(trc::location!())?;
                    if depth == 0
                        && ctx.is_shared
                        && !mailbox
                            .acls
                            .effective_acl(ctx.access_token)
                            .contains_any([Acl::CreateChild, Acl::Administer].into_iter())
                    {
                        return Ok(Err(SetError::forbidden().with_description(
                            "You are not allowed to create sub mailboxes under this mailbox.",
                        )));
                    }

                    mailbox_parent_id = mailbox.parent_id.into();
                } else if ctx.mailbox_ids.contains(parent_document_id) {
                    // Parent mailbox is probably created within the same request
                    success = true;
                    break;
                } else {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::ParentId)
                        .with_description("Mailbox parent does not exist.")));
                }
            }

            if !success {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::ParentId)
                    .with_description(
                        "Mailbox parent-child relationship is too deep.",
                    )));
            }
        }

        let cached_mailboxes = self.get_cached_messages(ctx.account_id).await?;

        // Verify that the mailbox role is unique.
        if !matches!(changes.role, SpecialUse::None)
            && update
                .as_ref()
                .is_none_or(|(_, m)| m.inner.role != changes.role)
        {
            if cached_mailboxes.mailbox_by_role(&changes.role).is_some() {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Role)
                    .with_description(format!(
                        "A mailbox with role '{}' already exists.",
                        changes.role.as_str().unwrap_or_default()
                    ))));
            }

            // Role of internal folders cannot be modified
            if update.as_ref().is_some_and(|(document_id, _)| {
                *document_id == INBOX_ID || *document_id == TRASH_ID
            }) {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Role)
                    .with_description(
                        "You are not allowed to change the role of Inbox or Trash folders.",
                    )));
            }
        }

        // Verify that the mailbox name is unique.
        if !changes.name.is_empty() {
            // Obtain parent mailbox id
            let lower_name = changes.name.to_lowercase();
            if update
                .as_ref()
                .is_none_or(|(_, m)| m.inner.name != changes.name)
                && cached_mailboxes.mailboxes.items.iter().any(|m| {
                    m.name.to_lowercase() == lower_name
                        && m.parent_id().map_or(0, |id| id + 1) == changes.parent_id
                })
            {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Name)
                    .with_description(format!(
                        "A mailbox with name '{}' already exists.",
                        changes.name
                    ))));
            }
        } else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::Name)
                .with_description("Mailbox name cannot be empty.")));
        }

        // Refresh ACLs
        let current = update.map(|(_, current)| current);
        if has_acl_changes {
            self.refresh_acls(
                &changes.acls,
                current.as_ref().map(|m| m.inner.acls.as_slice()),
            )
            .await;
        }

        // Validate
        Ok(Ok(ObjectIndexBuilder::new()
            .with_changes(changes)
            .with_current_opt(current)))
    }
}
