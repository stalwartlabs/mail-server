/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{acl::Acl, collection::Collection, keyword::Keyword, property::Property, value::Value},
};
use store::{ahash::AHashSet, query::Filter, roaring::RoaringBitmap};
use trc::AddContext;

use crate::{
    auth::{acl::EffectiveAcl, AccessToken},
    JMAP,
};

impl JMAP {
    pub async fn mailbox_get(
        &self,
        mut request: GetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
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
        let mut mailbox_ids = self.mailbox_get_or_create(account_id).await?;
        if access_token.is_shared(account_id) {
            mailbox_ids &= self
                .shared_documents(access_token, account_id, Collection::Mailbox, Acl::Read)
                .await?;
        }
        let message_ids = self.get_document_ids(account_id, Collection::Email).await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            mailbox_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
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
                    | Property::MyRights
            )
        });
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, Collection::Mailbox)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the mailbox object
            let document_id = id.document_id();
            if !mailbox_ids.contains(document_id) {
                response.not_found.push(id.into());
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
                        response.not_found.push(id.into());
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
                        if access_token.is_shared(account_id) {
                            let acl = values.effective_acl(access_token);
                            Object::with_capacity(9)
                                .with_property(Property::MayReadItems, acl.contains(Acl::ReadItems))
                                .with_property(Property::MayAddItems, acl.contains(Acl::AddItems))
                                .with_property(
                                    Property::MayRemoveItems,
                                    acl.contains(Acl::RemoveItems),
                                )
                                .with_property(Property::MaySetSeen, acl.contains(Acl::ModifyItems))
                                .with_property(
                                    Property::MaySetKeywords,
                                    acl.contains(Acl::ModifyItems),
                                )
                                .with_property(
                                    Property::MayCreateChild,
                                    acl.contains(Acl::CreateChild),
                                )
                                .with_property(Property::MayRename, acl.contains(Acl::Modify))
                                .with_property(Property::MayDelete, acl.contains(Acl::Delete))
                                .with_property(Property::MaySubmit, acl.contains(Acl::Submit))
                                .into()
                        } else {
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
                    }
                    Property::IsSubscribed => values
                        .properties
                        .remove(property)
                        .map(|parent_id| match parent_id {
                            Value::List(values)
                                if values
                                    .contains(&Value::Id(access_token.primary_id().into())) =>
                            {
                                Value::Bool(true)
                            }
                            _ => Value::Bool(false),
                        })
                        .unwrap_or(Value::Bool(false)),
                    Property::Acl => {
                        self.acl_get(
                            values
                                .properties
                                .get(&Property::Acl)
                                .and_then(|v| v.as_acl())
                                .map(|v| &v[..])
                                .unwrap_or_else(|| &[]),
                            access_token,
                            account_id,
                        )
                        .await
                    }

                    _ => Value::Null,
                };

                mailbox.append(property.clone(), value);
            }

            // Add result to response
            response.list.push(mailbox);
        }
        Ok(response)
    }

    async fn mailbox_count_threads(
        &self,
        account_id: u32,
        document_ids: Option<RoaringBitmap>,
    ) -> trc::Result<usize> {
        if let Some(document_ids) = document_ids {
            let mut thread_ids = AHashSet::default();
            self.get_cached_thread_ids(account_id, document_ids.into_iter())
                .await
                .caused_by(trc::location!())?
                .into_iter()
                .for_each(|(_, thread_id)| {
                    thread_ids.insert(thread_id);
                });
            Ok(thread_ids.len())
        } else {
            Ok(0)
        }
    }

    pub async fn mailbox_unread_tags(
        &self,
        account_id: u32,
        document_id: u32,
        message_ids: &Option<RoaringBitmap>,
    ) -> trc::Result<Option<RoaringBitmap>> {
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

    pub async fn mailbox_expand_path<'x>(
        &self,
        account_id: u32,
        path: &'x str,
        exact_match: bool,
    ) -> trc::Result<Option<ExpandPath<'x>>> {
        let path = path
            .split('/')
            .filter_map(|p| {
                let p = p.trim();
                if !p.is_empty() {
                    p.into()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if path.is_empty() || path.len() > self.core.jmap.mailbox_max_depth {
            return Ok(None);
        }

        let mut filter = Vec::with_capacity(path.len() + 2);
        filter.push(Filter::Or);
        for &item in &path {
            filter.push(Filter::eq(Property::Name, item));
        }
        filter.push(Filter::End);

        let document_ids = self
            .filter(account_id, Collection::Mailbox, filter)
            .await?
            .results;
        if exact_match && (document_ids.len() as usize) < path.len() {
            return Ok(None);
        }

        let mut found_names = Vec::new();
        for document_id in document_ids {
            if let Some(mut obj) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                if let Some(Value::Text(value)) = obj.properties.remove(&Property::Name) {
                    found_names.push((
                        value,
                        if let Some(Value::Id(value)) = obj.properties.remove(&Property::ParentId) {
                            value.document_id()
                        } else {
                            0
                        },
                        document_id + 1,
                    ));
                } else {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }

        Ok(Some(ExpandPath { path, found_names }))
    }

    pub async fn mailbox_get_by_name(
        &self,
        account_id: u32,
        path: &str,
    ) -> trc::Result<Option<u32>> {
        Ok(self
            .mailbox_expand_path(account_id, path, true)
            .await?
            .and_then(|ep| {
                let mut next_parent_id = 0;
                'outer: for name in ep.path {
                    for (part, parent_id, document_id) in &ep.found_names {
                        if part.eq(name) && *parent_id == next_parent_id {
                            next_parent_id = *document_id;
                            continue 'outer;
                        }
                    }
                    return None;
                }
                Some(next_parent_id - 1)
            }))
    }

    pub async fn mailbox_get_by_role(
        &self,
        account_id: u32,
        role: &str,
    ) -> trc::Result<Option<u32>> {
        self.filter(
            account_id,
            Collection::Mailbox,
            vec![Filter::eq(Property::Role, role)],
        )
        .await
        .map(|r| r.results.min())
    }
}

#[derive(Debug)]
pub struct ExpandPath<'x> {
    pub path: Vec<&'x str>,
    pub found_names: Vec<(String, u32, u32)>,
}
