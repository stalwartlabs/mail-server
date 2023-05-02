use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::set::{SetRequest, SetResponse},
    object::{
        index::{IndexAs, IndexProperty, ObjectIndexBuilder},
        mailbox::SetArguments,
        Object,
    },
    response::Response,
    types::{
        collection::Collection,
        id::Id,
        property::Property,
        value::{MaybePatchValue, SetValue, Value},
    },
};
use store::{
    query::Filter,
    roaring::RoaringBitmap,
    write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, F_BITMAP, F_CLEAR, F_VALUE},
};

use crate::JMAP;

use super::{INBOX_ID, TRASH_ID};

struct SetContext<'x> {
    account_id: u32,
    primary_id: u32,
    response: &'x Response,
    mailbox_ids: RoaringBitmap,
    will_destroy: Vec<Id>,
}

static SCHEMA: &[IndexProperty] = &[
    IndexProperty::new(Property::Name)
        .index_as(IndexAs::Text {
            tokenize: true,
            index: true,
        })
        .required(),
    IndexProperty::new(Property::Role)
        .index_as(IndexAs::Text {
            tokenize: false,
            index: true,
        })
        .required(),
    IndexProperty::new(Property::Role).index_as(IndexAs::HasProperty),
    IndexProperty::new(Property::ParentId).index_as(IndexAs::Integer),
    IndexProperty::new(Property::SortOrder).index_as(IndexAs::Integer),
    IndexProperty::new(Property::IsSubscribed).index_as(IndexAs::IntegerList),
];

impl JMAP {
    #[allow(clippy::blocks_in_if_conditions)]
    pub async fn mailbox_set(
        &self,
        mut request: SetRequest<SetArguments>,
        response: &Response,
    ) -> Result<SetResponse, MethodError> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let mut set_response = self
            .prepare_set_response(&request, Collection::Mailbox)
            .await?;
        let on_destroy_remove_emails = request.arguments.on_destroy_remove_emails.unwrap_or(false);
        let mut ctx = SetContext {
            account_id,
            primary_id: account_id,
            response,
            mailbox_ids: self
                .get_document_ids(account_id, Collection::Mailbox)
                .await?
                .unwrap_or_default(),
            will_destroy: request.unwrap_destroy(),
        };

        // Process creates
        let mut changes = ChangeLogBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            match self.mailbox_set_item(object, None, &ctx).await? {
                Ok(builder) => {
                    let mut batch = BatchBuilder::new();
                    let document_id = self
                        .assign_document_id(account_id, Collection::Mailbox)
                        .await?;
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Mailbox)
                        .create_document(document_id)
                        .custom(builder);
                    changes.log_insert(Collection::Mailbox, document_id);
                    ctx.mailbox_ids.insert(document_id);
                    self.store.write(batch.build()).await.map_err(|err| {
                        tracing::error!(
                        event = "error",
                        context = "mailbox_set",
                        account_id = account_id,
                        error = ?err,
                        "Failed to create mailbox(es).");
                        MethodError::ServerPartialFail
                    })?;

                    set_response.created(id, document_id);
                }
                Err(err) => {
                    set_response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            // Obtain mailbox
            let document_id = id.document_id();
            if let Some(mut mailbox) = self
                .get_property::<HashedValue<Object<Value>>>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                match self
                    .mailbox_set_item(object, (document_id, mailbox.take()).into(), &ctx)
                    .await?
                {
                    Ok(builder) => {
                        let mut batch = BatchBuilder::new();
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::Mailbox)
                            .create_document(document_id)
                            .assert_value(Property::Value, &mailbox)
                            .custom(builder);
                        if !batch.is_empty() {
                            changes.log_update(Collection::Mailbox, document_id);
                            match self.store.write(batch.build()).await {
                                Ok(_) => (),
                                Err(store::Error::AssertValueFailed) => {
                                    set_response.not_updated.append(id, SetError::forbidden().with_description(
                                        "Another process modified this mailbox, please try again.",
                                    ));
                                    continue 'update;
                                }
                                Err(err) => {
                                    tracing::error!(
                                        event = "error",
                                        context = "mailbox_set",
                                        account_id = account_id,
                                        error = ?err,
                                        "Failed to update mailbox(es).");
                                    return Err(MethodError::ServerPartialFail);
                                }
                            }
                        }
                        set_response.updated.append(id, None);
                    }
                    Err(err) => {
                        set_response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
            } else {
                set_response.not_updated.append(id, SetError::not_found());
            }
        }

        // Process deletions
        'destroy: for id in ctx.will_destroy {
            let document_id = id.document_id();
            // Internal folders cannot be deleted
            if document_id == INBOX_ID || document_id == TRASH_ID {
                set_response.not_destroyed.append(
                    id,
                    SetError::forbidden()
                        .with_description("You are not allowed to delete Inbox or Trash folders."),
                );
                continue;
            }

            // Verify that this mailbox does not have sub-mailboxes
            if !self
                .filter(
                    account_id,
                    Collection::Mailbox,
                    vec![Filter::eq(Property::ParentId, document_id + 1)],
                )
                .await?
                .results
                .is_empty()
            {
                set_response.not_destroyed.append(
                    id,
                    SetError::new(SetErrorType::MailboxHasChild)
                        .with_description("Mailbox has at least one children."),
                );
                continue;
            }

            // Verify that the mailbox is empty
            if let Some(message_ids) = self
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::MailboxIds,
                    document_id,
                )
                .await?
            {
                if on_destroy_remove_emails {
                    // If the message is in multiple mailboxes, untag it from the current mailbox,
                    // otherwise delete it.
                    for message_id in message_ids {
                        // Obtain mailboxIds
                        if let Some(mailbox_ids) = self
                            .get_property::<HashedValue<Vec<u32>>>(
                                account_id,
                                Collection::Email,
                                message_id,
                                Property::MailboxIds,
                            )
                            .await?
                            .and_then(|mut ids| {
                                let idx = ids.inner.iter().position(|&id| id == document_id)?;
                                ids.inner.swap_remove(idx);
                                Some(ids)
                            })
                        {
                            if !mailbox_ids.inner.is_empty() {
                                // Obtain threadId
                                if let Some(thread_id) = self
                                    .get_property::<u32>(
                                        account_id,
                                        Collection::Email,
                                        message_id,
                                        Property::ThreadId,
                                    )
                                    .await?
                                {
                                    // Untag message from mailbox
                                    let mut batch = BatchBuilder::new();
                                    batch
                                        .with_account_id(account_id)
                                        .with_collection(Collection::Email)
                                        .update_document(message_id)
                                        .assert_value(Property::MailboxIds, &mailbox_ids)
                                        .value(Property::MailboxIds, mailbox_ids.inner, F_VALUE)
                                        .value(
                                            Property::MailboxIds,
                                            document_id,
                                            F_BITMAP | F_CLEAR,
                                        );
                                    match self.store.write(batch.build()).await {
                                        Ok(_) => changes.log_update(
                                            Collection::Email,
                                            Id::from_parts(thread_id, message_id),
                                        ),
                                        Err(store::Error::AssertValueFailed) => {
                                            set_response.not_destroyed.append(
                                                id,
                                                SetError::forbidden().with_description(
                                                    concat!("Another process modified a message in this mailbox ",
                                                    "while deleting it, please try again.")
                                                ),
                                            );
                                            continue 'destroy;
                                        }
                                        Err(err) => {
                                            tracing::error!(
                                                    event = "error",
                                                    context = "mailbox_set",
                                                    account_id = account_id,
                                                    mailbox_id = document_id,
                                                    message_id = message_id,
                                                    error = ?err,
                                                    "Failed to update message while deleting mailbox.");
                                            return Err(MethodError::ServerPartialFail);
                                        }
                                    }
                                } else {
                                    tracing::debug!(
                                        event = "error",
                                        context = "mailbox_set",
                                        account_id = account_id,
                                        mailbox_id = document_id,
                                        message_id = message_id,
                                        "Message does not have a threadId, skipping."
                                    );
                                }
                            } else {
                                // Delete message
                                if let Ok(mut change) =
                                    self.email_delete(account_id, document_id).await?
                                {
                                    change.changes.remove(&(Collection::Mailbox as u8));
                                    changes.merge(change);
                                }
                            }
                        } else {
                            tracing::debug!(
                                event = "error",
                                context = "mailbox_set",
                                account_id = account_id,
                                mailbox_id = document_id,
                                message_id = message_id,
                                "Message is not in the mailbox, skipping."
                            );
                        }
                    }
                } else {
                    set_response.not_destroyed.append(
                        id,
                        SetError::new(SetErrorType::MailboxHasEmail)
                            .with_description("Mailbox is not empty."),
                    );
                    continue;
                }
            }

            // Obtain mailbox
            if let Some(mailbox) = self
                .get_property::<HashedValue<Object<Value>>>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Mailbox)
                    .delete_document(document_id)
                    .assert_value(Property::Value, &mailbox)
                    .custom(ObjectIndexBuilder::new(SCHEMA).with_current(mailbox.inner));

                match self.store.write(batch.build()).await {
                    Ok(_) => changes.log_delete(Collection::Mailbox, document_id),
                    Err(store::Error::AssertValueFailed) => {
                        set_response.not_destroyed.append(
                            id,
                            SetError::forbidden().with_description(concat!(
                                "Another process modified this mailbox ",
                                "while deleting it, please try again."
                            )),
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                                    event = "error",
                                    context = "mailbox_set",
                                    account_id = account_id,
                                    document_id = document_id,
                                    error = ?err,
                                    "Failed to delete mailbox.");
                        return Err(MethodError::ServerPartialFail);
                    }
                }
            } else {
                set_response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !changes.is_empty() {
            set_response.new_state = self.commit_changes(account_id, changes).await?.into();
        }

        Ok(set_response)
    }

    #[allow(clippy::blocks_in_if_conditions)]
    async fn mailbox_set_item(
        &self,
        changes_: Object<SetValue>,
        update: Option<(u32, Object<Value>)>,
        ctx: &SetContext<'_>,
    ) -> Result<Result<ObjectIndexBuilder, SetError>, MethodError> {
        // Parse properties
        let mut changes = Object::with_capacity(changes_.properties.len());
        for item in changes_.iterate_and_eval_references(ctx.response) {
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    return Ok(Err(err));
                }
            };
            match item {
                (Property::Name, MaybePatchValue::Value(Value::Text(value))) => {
                    let value = value.trim();
                    if !value.is_empty() && value.len() < self.config.mailbox_name_max_len {
                        changes.append(Property::Name, Value::Text(value.to_string()));
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

                    changes.append(Property::ParentId, Value::Id((parent_id + 1).into()));
                }
                (Property::ParentId, MaybePatchValue::Value(Value::Null)) => {
                    changes.append(Property::ParentId, Value::Id(0u64.into()))
                }
                (Property::IsSubscribed, MaybePatchValue::Value(Value::Bool(subscribe))) => {
                    let fixme = "true";
                    let account_id = Value::Id(ctx.primary_id.into());
                    let mut new_value = None;
                    if let Some((_, current_fields)) = update.as_ref() {
                        if let Value::List(subscriptions) =
                            current_fields.get(&Property::IsSubscribed)
                        {
                            if subscribe {
                                if !subscriptions.contains(&account_id) {
                                    let mut current_subscriptions = subscriptions.clone();
                                    current_subscriptions.push(account_id.clone());
                                    new_value = Value::List(current_subscriptions).into();
                                } else {
                                    continue;
                                }
                            } else if subscriptions.contains(&account_id) {
                                if subscriptions.len() > 1 {
                                    new_value = Value::List(
                                        subscriptions
                                            .iter()
                                            .filter(|id| *id != &account_id)
                                            .cloned()
                                            .collect(),
                                    )
                                    .into();
                                } else {
                                    new_value = Value::Null.into();
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                    changes.append(
                        Property::IsSubscribed,
                        if let Some(new_value) = new_value {
                            new_value
                        } else if subscribe {
                            Value::List(vec![account_id])
                        } else {
                            continue;
                        },
                    );
                }
                (Property::Role, MaybePatchValue::Value(Value::Text(value))) => {
                    let role = value.trim().to_lowercase();
                    if [
                        "inbox", "trash", "spam", "junk", "drafts", "archive", "sent",
                    ]
                    .contains(&role.as_str())
                    {
                        changes.append(Property::Role, Value::Text(role));
                    } else {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(Property::Role)
                            .with_description(format!("Invalid role {role:?}."))));
                    }
                }
                (Property::Role, MaybePatchValue::Value(Value::Null)) => {
                    changes.append(Property::Role, Value::Null)
                }
                (Property::SortOrder, MaybePatchValue::Value(Value::UnsignedInt(value))) => {
                    changes.append(Property::SortOrder, Value::UnsignedInt(value));
                }
                (Property::Acl, _) => {
                    todo!()
                }
                (property, _) => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property)
                        .with_description("Invalid property or value.".to_string())))
                }
            };
        }

        // Validate depth and circular parent-child relationship
        if let Value::Id(mailbox_parent_id) = changes.get(&Property::ParentId) {
            let current_mailbox_id = update
                .as_ref()
                .map_or(u32::MAX, |(mailbox_id, _)| *mailbox_id + 1);
            let mut mailbox_parent_id = mailbox_parent_id.document_id();
            let mut success = false;
            for _ in 0..self.config.mailbox_max_depth {
                if mailbox_parent_id == current_mailbox_id {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::ParentId)
                        .with_description("Mailbox cannot be a parent of itself.")));
                } else if mailbox_parent_id == 0 {
                    success = true;
                    break;
                }
                let parent_document_id = mailbox_parent_id - 1;

                if let Some(mut fields) = self
                    .get_property::<Object<Value>>(
                        ctx.account_id,
                        Collection::Mailbox,
                        parent_document_id,
                        Property::Value,
                    )
                    .await?
                {
                    mailbox_parent_id = fields
                        .properties
                        .remove(&Property::ParentId)
                        .and_then(|v| v.try_unwrap_id().map(|id| id.document_id()))
                        .unwrap_or(0);
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
        } else if update.is_none() {
            // Set parentId if the field is missing
            changes.append(Property::ParentId, Value::Id(0u64.into()));
        }

        // Verify that the mailbox role is unique.
        if let Value::Text(mailbox_role) = changes.get(&Property::Role) {
            if update
                .as_ref()
                .map(|(_, update)| update.get(&Property::Role))
                .and_then(|v| v.as_string())
                .unwrap_or_default()
                != mailbox_role
            {
                if !self
                    .filter(
                        ctx.account_id,
                        Collection::Mailbox,
                        vec![Filter::eq(Property::Role, mailbox_role.as_str())],
                    )
                    .await?
                    .results
                    .is_empty()
                {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::Role)
                        .with_description(format!(
                            "A mailbox with role '{}' already exists.",
                            mailbox_role
                        ))));
                }

                // Role of internal folders cannot be modified
                if update.as_ref().map_or(false, |(document_id, _)| {
                    *document_id == INBOX_ID || *document_id == TRASH_ID
                }) {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::Role)
                        .with_description(
                            "You are not allowed to change the role of Inbox or Trash folders.",
                        )));
                }
            }
        }

        // Verify that the mailbox name is unique.
        if let Value::Text(mailbox_name) = changes.get(&Property::Name) {
            // Obtain parent mailbox id
            if let Some(parent_mailbox_id) = if let Some(mailbox_parent_id) = &changes
                .properties
                .get(&Property::ParentId)
                .and_then(|id| id.as_id().map(|id| id.document_id()))
            {
                (*mailbox_parent_id).into()
            } else if let Some((_, current_fields)) = &update {
                if current_fields
                    .properties
                    .get(&Property::Name)
                    .and_then(|n| n.as_string())
                    != Some(mailbox_name)
                {
                    current_fields
                        .properties
                        .get(&Property::ParentId)
                        .and_then(|id| id.as_id().map(|id| id.document_id()))
                        .unwrap_or_default()
                        .into()
                } else {
                    None
                }
            } else {
                0.into()
            } {
                if !self
                    .filter(
                        ctx.account_id,
                        Collection::Mailbox,
                        vec![
                            Filter::eq(Property::Name, mailbox_name.as_str()),
                            Filter::eq(Property::ParentId, parent_mailbox_id),
                        ],
                    )
                    .await?
                    .results
                    .is_empty()
                {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::Name)
                        .with_description(format!(
                            "A mailbox with name '{}' already exists.",
                            mailbox_name
                        ))));
                }
            }
        }

        // Validate
        Ok(ObjectIndexBuilder::new(SCHEMA)
            .with_changes(changes)
            .with_current_opt(update.map(|(_, current)| current))
            .validate())
    }
}
