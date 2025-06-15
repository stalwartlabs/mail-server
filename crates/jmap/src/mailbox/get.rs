/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    types::{
        acl::Acl,
        keyword::Keyword,
        property::Property,
        value::{Object, Value},
    },
};
use std::future::Future;
use store::ahash::AHashSet;

pub trait MailboxGet: Sync + Send {
    fn mailbox_get(
        &self,
        request: GetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;
}

impl MailboxGet for Server {
    async fn mailbox_get(
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
        let cache = self.get_cached_messages(account_id).await?;
        let shared_ids = if access_token.is_shared(account_id) {
            cache.shared_mailboxes(access_token, Acl::Read).into()
        } else {
            None
        };
        let ids = if let Some(ids) = ids {
            ids
        } else {
            cache
                .mailboxes
                .index
                .keys()
                .filter(|id| shared_ids.as_ref().is_none_or(|ids| ids.contains(**id)))
                .copied()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: Some(cache.mailboxes.change_id.into()),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the mailbox object
            let document_id = id.document_id();
            let cached_mailbox = if let Some(mailbox) =
                cache.mailbox_by_id(&document_id).filter(|_| {
                    shared_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(document_id))
                }) {
                mailbox
            } else {
                response.not_found.push(id.into());
                continue;
            };

            let mut mailbox = Object::with_capacity(properties.len());

            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::Name => Value::Text(cached_mailbox.name.to_string()),
                    Property::Role => {
                        if let Some(role) = cached_mailbox.role.as_str() {
                            Value::Text(role.to_string())
                        } else {
                            Value::Null
                        }
                    }
                    Property::SortOrder => Value::from(cached_mailbox.sort_order()),
                    Property::ParentId => {
                        if let Some(parent_id) = cached_mailbox.parent_id() {
                            Value::Id((parent_id).into())
                        } else {
                            Value::Null
                        }
                    }
                    Property::TotalEmails => {
                        Value::UnsignedInt(cache.in_mailbox(document_id).count() as u64)
                    }
                    Property::UnreadEmails => Value::UnsignedInt(
                        cache
                            .in_mailbox_without_keyword(document_id, &Keyword::Seen)
                            .count() as u64,
                    ),
                    Property::TotalThreads => Value::UnsignedInt(
                        cache
                            .in_mailbox(document_id)
                            .map(|m| m.thread_id)
                            .collect::<AHashSet<_>>()
                            .len() as u64,
                    ),
                    Property::UnreadThreads => Value::UnsignedInt(
                        cache
                            .in_mailbox_without_keyword(document_id, &Keyword::Seen)
                            .map(|m| m.thread_id)
                            .collect::<AHashSet<_>>()
                            .len() as u64,
                    ),
                    Property::MyRights => {
                        if access_token.is_shared(account_id) {
                            let acl = cached_mailbox.acls.as_slice().effective_acl(access_token);
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
                    Property::IsSubscribed => Value::Bool(
                        cached_mailbox
                            .subscribers
                            .contains(&access_token.primary_id()),
                    ),
                    Property::Acl => {
                        self.acl_get(&cached_mailbox.acls, access_token, account_id)
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
}
