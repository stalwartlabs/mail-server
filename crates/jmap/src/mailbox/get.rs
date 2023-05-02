use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, keyword::Keyword, property::Property, value::Value},
};
use store::{ahash::AHashSet, roaring::RoaringBitmap};

use crate::JMAP;

impl JMAP {
    pub async fn mailbox_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
        let ids = request.unwrap_ids(self.config.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::Name,
            Property::ParentId,
            Property::Role,
            Property::SortOrder,
            Property::IsSubscribed,
            Property::TotalEmails,
            Property::UnreadEmails,
            Property::TotalThreads,
            Property::UnreadThreads,
            Property::MyRights,
        ]);
        let account_id = request.account_id.document_id();
        let mailbox_ids = self
            .get_document_ids(account_id, Collection::Mailbox)
            .await?
            .unwrap_or_default();
        let message_ids = self.get_document_ids(account_id, Collection::Email).await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            mailbox_ids
                .iter()
                .take(self.config.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let fetch_properties = properties.iter().any(|p| {
            matches!(
                p,
                Property::Name
                    | Property::ParentId
                    | Property::Role
                    | Property::SortOrder
                    | Property::Acl
            )
        });
        let mut response = GetResponse {
            account_id: Some(request.account_id),
            state: self.get_state(account_id, Collection::Mailbox).await?,
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the mailbox object
            let document_id = id.document_id();
            if !mailbox_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }

            let mut values = if fetch_properties {
                match self
                    .get_property::<Object<Value>>(
                        account_id,
                        Collection::Mailbox,
                        document_id,
                        &Property::Value,
                    )
                    .await?
                {
                    Some(values) => values,
                    None => {
                        response.not_found.push(id);
                        continue;
                    }
                }
            } else {
                Object::with_capacity(0)
            };

            let mut mailbox = Object::with_capacity(properties.len());

            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::Name | Property::Role => values.remove(property),
                    Property::SortOrder => values
                        .properties
                        .remove(property)
                        .unwrap_or(Value::UnsignedInt(0)),
                    Property::ParentId => values
                        .properties
                        .remove(property)
                        .map(|parent_id| match parent_id {
                            Value::Id(value) if value.document_id() > 0 => {
                                Value::Id((value.document_id() - 1).into())
                            }
                            _ => Value::Null,
                        })
                        .unwrap_or_default(),
                    Property::TotalEmails => Value::UnsignedInt(
                        self.get_tag(
                            account_id,
                            Collection::Email,
                            Property::MailboxIds,
                            document_id,
                        )
                        .await?
                        .map(|v| v.len())
                        .unwrap_or(0),
                    ),
                    Property::UnreadEmails => Value::UnsignedInt(
                        self.mailbox_unread_tags(account_id, document_id, &message_ids)
                            .await?
                            .map(|v| v.len())
                            .unwrap_or(0),
                    ),
                    Property::TotalThreads => Value::UnsignedInt(
                        self.mailbox_count_threads(
                            account_id,
                            self.get_tag(
                                account_id,
                                Collection::Email,
                                Property::MailboxIds,
                                document_id,
                            )
                            .await?,
                        )
                        .await? as u64,
                    ),
                    Property::UnreadThreads => Value::UnsignedInt(
                        self.mailbox_count_threads(
                            account_id,
                            self.mailbox_unread_tags(account_id, document_id, &message_ids)
                                .await?,
                        )
                        .await? as u64,
                    ),
                    Property::MyRights => {
                        let todo = "add shared";
                        mailbox_rights_owner()
                    }
                    Property::IsSubscribed => values
                        .properties
                        .remove(property)
                        .map(|parent_id| match parent_id {
                            Value::List(values)
                                if values.contains(&Value::Id(account_id.into())) =>
                            {
                                let todo = "use acl id";
                                Value::Bool(true)
                            }
                            _ => Value::Bool(false),
                        })
                        .unwrap_or(Value::Bool(false)),
                    /*Property::ACL
                        if acl.is_member(account_id)
                            || self
                                .mail_shared_folders(account_id, &acl.member_of, Acl::Administer)?
                                .has_access(document_id) =>
                    {
                        let mut acl_get = VecMap::new();
                        for (account_id, acls) in fields.as_ref().unwrap().get_acls() {
                            if let Some(email) = self.principal_to_email(account_id)? {
                                acl_get.append(email, acls);
                            }
                        }
                        Value::ACLGet(acl_get)
                    }*/
                    _ => Value::Null,
                };

                mailbox.append(property.clone(), value);
            }
        }
        Ok(response)
    }

    async fn mailbox_count_threads(
        &self,
        account_id: u32,
        document_ids: Option<RoaringBitmap>,
    ) -> Result<usize, MethodError> {
        if let Some(document_ids) = document_ids {
            let mut thread_ids = AHashSet::default();
            self.get_properties::<u32>(
                account_id,
                Collection::Email,
                document_ids.into_iter(),
                Property::ThreadId,
            )
            .await?
            .into_iter()
            .flatten()
            .for_each(|thread_id| {
                thread_ids.insert(thread_id);
            });
            Ok(thread_ids.len())
        } else {
            Ok(0)
        }
    }

    async fn mailbox_unread_tags(
        &self,
        account_id: u32,
        document_id: u32,
        message_ids: &Option<RoaringBitmap>,
    ) -> Result<Option<RoaringBitmap>, MethodError> {
        if let (Some(message_ids), Some(mailbox_message_ids)) = (
            message_ids,
            self.get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                document_id,
            )
            .await?,
        ) {
            if let Some(mut seen) = self
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::Keywords,
                    Keyword::Seen,
                )
                .await?
            {
                seen ^= message_ids;
                seen &= &mailbox_message_ids;
                if !seen.is_empty() {
                    Ok(Some(seen))
                } else {
                    Ok(None)
                }
            } else {
                Ok(mailbox_message_ids.into())
            }
        } else {
            Ok(None)
        }
    }
}

fn mailbox_rights_owner() -> Value {
    Object::with_capacity(9)
        .with_property(Property::MayReadItems, true)
        .with_property(Property::MayAddItems, true)
        .with_property(Property::MayRemoveItems, true)
        .with_property(Property::MaySetSeen, true)
        .with_property(Property::MaySetKeywords, true)
        .with_property(Property::MayCreateChild, true)
        .with_property(Property::MayRename, true)
        .with_property(Property::MayDelete, true)
        .with_property(Property::MaySubmit, true)
        .into()
}

/*fn mailbox_rights_shared(acl: Bitmap<Acl>) -> Value {
    Object::with_capacity(9)
        .with_property(Property::MayReadItems, acl.contains(Acl::ReadItems))
        .with_property(Property::MayAddItems, acl.contains(Acl::AddItems))
        .with_property(Property::MayRemoveItems, acl.contains(Acl::RemoveItems))
        .with_property(Property::MaySetSeen, acl.contains(Acl::ModifyItems))
        .with_property(Property::MaySetKeywords, acl.contains(Acl::ModifyItems))
        .with_property(Property::MayCreateChild, acl.contains(Acl::CreateChild))
        .with_property(Property::MayRename, acl.contains(Acl::Modify))
        .with_property(Property::MayDelete, acl.contains(Acl::Delete))
        .with_property(Property::MaySubmit, acl.contains(Acl::Submit))
        .into()
}*/
