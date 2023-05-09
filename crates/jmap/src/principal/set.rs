use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::set::{RequestArguments, SetRequest, SetResponse},
    object::{
        index::{IndexAs, IndexProperty, ObjectIndexBuilder},
        Object,
    },
    types::{
        collection::Collection,
        id::Id,
        keyword::Keyword,
        property::Property,
        value::{MaybePatchValue, SetValue, Value},
    },
};
use store::{
    roaring::RoaringBitmap,
    write::{
        assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, DeserializeFrom, SerializeInto,
        ToBitmaps, F_BITMAP, F_CLEAR, F_VALUE,
    },
    BlobKind, Serialize, ValueKey,
};

use crate::{mailbox, JMAP, SUPERUSER_ID};

struct SetContext {
    set_response: SetResponse,
    principal_ids: RoaringBitmap,
    will_destroy: Vec<Id>,
}

pub static SCHEMA: &[IndexProperty] = &[
    IndexProperty::new(Property::Name)
        .index_as(IndexAs::Text {
            tokenize: true,
            index: true,
        })
        .required(),
    IndexProperty::new(Property::Role).index_as(IndexAs::Text {
        tokenize: false,
        index: true,
    }),
    IndexProperty::new(Property::Role).index_as(IndexAs::HasProperty),
    IndexProperty::new(Property::ParentId).index_as(IndexAs::Integer),
    IndexProperty::new(Property::SortOrder).index_as(IndexAs::Integer),
    IndexProperty::new(Property::IsSubscribed).index_as(IndexAs::IntegerList),
];

impl JMAP {
    pub async fn principal_set(
        &self,
        mut request: SetRequest<RequestArguments>,
    ) -> Result<SetResponse, MethodError> {
        // Prepare response
        let mut ctx = SetContext {
            set_response: self
                .prepare_set_response(&request, Collection::Principal)
                .await?,
            principal_ids: self
                .get_document_ids(SUPERUSER_ID, Collection::Principal)
                .await?
                .unwrap_or_default(),
            will_destroy: request.unwrap_destroy(),
        };

        // Process creates
        let mut changes = ChangeLogBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            match self.principal_set_item(object, None, &ctx).await? {
                Ok(builder) => {
                    let mut batch = BatchBuilder::new();
                    let principal_id = self
                        .assign_document_id(SUPERUSER_ID, Collection::Principal)
                        .await?;
                    let create_mailboxes = matches!(
                        builder.get(&Property::Type),
                        Value::Text(t) if ["individual", "group"].contains(&t.as_str())
                    );
                    batch
                        .with_account_id(SUPERUSER_ID)
                        .with_collection(Collection::Principal)
                        .create_document(principal_id)
                        .custom(builder);

                    // Create mailboxes
                    if create_mailboxes {
                        batch
                            .with_account_id(principal_id)
                            .with_collection(Collection::Mailbox);
                        for (name, role) in [
                            ("Inbox", "inbox"),
                            ("Deleted Items", "trash"),
                            ("Drafts", "drafts"),
                            ("Sent Items", "sent"),
                            ("Junk Mail", "junk"),
                        ] {
                            batch
                                .create_document(
                                    self.assign_document_id(principal_id, Collection::Mailbox)
                                        .await?,
                                )
                                .custom(
                                    ObjectIndexBuilder::new(mailbox::set::SCHEMA).with_changes(
                                        Object::with_capacity(3)
                                            .with_property(Property::Name, name)
                                            .with_property(Property::Role, role)
                                            .with_property(Property::ParentId, 0u32),
                                    ),
                                );
                        }
                    }

                    changes.log_insert(Collection::Principal, principal_id);
                    ctx.principal_ids.insert(principal_id);
                    self.store.write(batch.build()).await.map_err(|err| {
                        tracing::error!(
                        event = "error",
                        context = "principal_set",
                        error = ?err,
                        "Failed to create mailbox(es).");
                        MethodError::ServerPartialFail
                    })?;

                    ctx.set_response.created(id, principal_id);
                }
                Err(err) => {
                    ctx.set_response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            // Obtain mailbox
            let principal_id = id.document_id();
            if let Some(mut principal) = self
                .get_property::<HashedValue<Object<Value>>>(
                    SUPERUSER_ID,
                    Collection::Principal,
                    principal_id,
                    Property::Value,
                )
                .await?
            {
                match self
                    .principal_set_item(object, (principal_id, principal.take()).into(), &ctx)
                    .await?
                {
                    Ok(builder) => {
                        let mut batch = BatchBuilder::new();
                        batch
                            .with_account_id(SUPERUSER_ID)
                            .with_collection(Collection::Principal)
                            .create_document(principal_id)
                            .assert_value(Property::Value, &principal)
                            .custom(builder);
                        if !batch.is_empty() {
                            changes.log_update(Collection::Principal, principal_id);
                            match self.store.write(batch.build()).await {
                                Ok(_) => (),
                                Err(store::Error::AssertValueFailed) => {
                                    ctx.set_response.not_updated.append(id, SetError::forbidden().with_description(
                                                "Another process modified this principal, please try again.",
                                            ));
                                    continue 'update;
                                }
                                Err(err) => {
                                    tracing::error!(
                                                event = "error",
                                                context = "principal_set",
                                                error = ?err,
                                                "Failed to update principal(s).");
                                    return Err(MethodError::ServerPartialFail);
                                }
                            }
                        }
                        ctx.set_response.updated.append(id, None);
                    }
                    Err(err) => {
                        ctx.set_response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
            } else {
                ctx.set_response
                    .not_updated
                    .append(id, SetError::not_found());
            }
        }

        // Process deletions
        'destroy: for id in ctx.will_destroy {
            let principal_id = id.document_id();
            // Obtain mailbox
            if let Some(mailbox) = self
                .get_property::<HashedValue<Object<Value>>>(
                    SUPERUSER_ID,
                    Collection::Principal,
                    principal_id,
                    Property::Value,
                )
                .await?
            {
                let delete_account_data = "todo";
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(SUPERUSER_ID)
                    .with_collection(Collection::Principal)
                    .delete_document(principal_id)
                    .assert_value(Property::Value, &mailbox)
                    .custom(ObjectIndexBuilder::new(SCHEMA).with_current(mailbox.inner));

                match self.store.write(batch.build()).await {
                    Ok(_) => {
                        changes.log_delete(Collection::Principal, principal_id);
                        ctx.set_response.destroyed.push(id);
                    }
                    Err(store::Error::AssertValueFailed) => {
                        ctx.set_response.not_destroyed.append(
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
                                    document_id = principal_id,
                                    error = ?err,
                                    "Failed to delete principal.");
                        return Err(MethodError::ServerPartialFail);
                    }
                }
            } else {
                ctx.set_response
                    .not_destroyed
                    .append(id, SetError::not_found());
            }
        }

        // Write changes
        if !changes.is_empty() {
            ctx.set_response.new_state = self.commit_changes(SUPERUSER_ID, changes).await?.into();
        }

        Ok(ctx.set_response)
    }

    #[allow(clippy::blocks_in_if_conditions)]
    async fn principal_set_item(
        &self,
        changes_: Object<SetValue>,
        update: Option<(u32, Object<Value>)>,
        ctx: &SetContext,
    ) -> Result<Result<ObjectIndexBuilder, SetError>, MethodError> {
        todo!()
    }
}
