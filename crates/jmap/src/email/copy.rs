/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};

use email::{mailbox::manage::MailboxFnc, message::copy::EmailCopy};
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse, RequestArguments},
        set::{self, SetRequest},
    },
    request::{
        Call, RequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeReference,
    },
    response::references::EvalObjectReferences,
    types::{
        acl::Acl,
        collection::Collection,
        property::Property,
        state::{State, StateChange},
        type_state::DataType,
        value::{MaybePatchValue, Value},
    },
};

use crate::{api::http::HttpSessionData, changes::state::StateManager};
use std::future::Future;
use utils::map::vec_map::VecMap;

pub trait JmapEmailCopy: Sync + Send {
    fn email_copy(
        &self,
        request: CopyRequest<RequestArguments>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse>> + Send;
}

impl JmapEmailCopy for Server {
    async fn email_copy(
        &self,
        request: CopyRequest<RequestArguments>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod>>,
        session: &HttpSessionData,
    ) -> trc::Result<CopyResponse> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let old_state = self
            .assert_state(account_id, Collection::Email, &request.if_in_state)
            .await?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
            state_change: None,
        };

        let from_message_ids = self
            .owned_or_shared_items(
                access_token,
                from_account_id,
                Collection::Mailbox,
                Collection::Email,
                Property::MailboxIds,
                Acl::ReadItems,
            )
            .await?;
        let mailbox_ids = self.mailbox_get_or_create(account_id).await?;
        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            self.shared_containers(access_token, account_id, Collection::Mailbox, Acl::AddItems)
                .await?
                .into()
        } else {
            None
        };
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();

        // Obtain quota
        let resource_token = self.get_resource_token(access_token, account_id).await?;

        'create: for (id, create) in request.create {
            let id = id.unwrap();
            let from_message_id = id.document_id();
            if !from_message_ids.contains(from_message_id) {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            }

            let mut mailboxes = Vec::new();
            let mut keywords = Vec::new();
            let mut received_at = None;

            for (property, value) in create.0 {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };

                match (property, value) {
                    (Property::MailboxIds, MaybePatchValue::Value(Value::List(ids))) => {
                        mailboxes = ids
                            .into_iter()
                            .filter_map(|id| id.try_unwrap_id()?.document_id().into())
                            .collect();
                    }

                    (Property::MailboxIds, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(id) = patch.next().unwrap().try_unwrap_id() {
                            let document_id = id.document_id();
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                if !mailboxes.contains(&document_id) {
                                    mailboxes.push(document_id);
                                }
                            } else {
                                mailboxes.retain(|id| id != &document_id);
                            }
                        }
                    }

                    (Property::Keywords, MaybePatchValue::Value(Value::List(keywords_))) => {
                        keywords = keywords_
                            .into_iter()
                            .filter_map(|keyword| keyword.try_unwrap_keyword())
                            .collect();
                    }

                    (Property::Keywords, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(keyword) = patch.next().unwrap().try_unwrap_keyword() {
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                if !keywords.contains(&keyword) {
                                    keywords.push(keyword);
                                }
                            } else {
                                keywords.retain(|k| k != &keyword);
                            }
                        }
                    }
                    (Property::ReceivedAt, MaybePatchValue::Value(Value::Date(value))) => {
                        received_at = value.into();
                    }
                    (property, _) => {
                        response.not_created.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(property)
                                .with_description("Invalid property or value.".to_string()),
                        );
                        continue 'create;
                    }
                }
            }

            // Make sure message belongs to at least one mailbox
            if mailboxes.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::MailboxIds)
                        .with_description("Message has to belong to at least one mailbox."),
                );
                continue 'create;
            }

            // Verify that the mailboxIds are valid
            for mailbox_id in &mailboxes {
                if !mailbox_ids.contains(*mailbox_id) {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description(format!("mailboxId {mailbox_id} does not exist.")),
                    );
                    continue 'create;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {mailbox_id}."
                        )),
                    );
                    continue 'create;
                }
            }

            // Add response
            match self
                .copy_message(
                    from_account_id,
                    from_message_id,
                    &resource_token,
                    mailboxes,
                    keywords,
                    received_at,
                    session.session_id,
                )
                .await?
            {
                Ok(email) => {
                    response.created.append(id, email.into());
                }
                Err(err) => {
                    response.not_created.append(id, err);
                }
            }

            // Add to destroy list
            if on_success_delete {
                destroy_ids.push(id);
            }
        }

        // Update state
        if !response.created.is_empty() {
            response.new_state = self.get_state(account_id, Collection::Email).await?;
            if let State::Exact(change_id) = &response.new_state {
                response.state_change = StateChange::new(account_id)
                    .with_change(DataType::Email, *change_id)
                    .with_change(DataType::Mailbox, *change_id)
                    .with_change(DataType::Thread, *change_id)
                    .into()
            }
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::Email, MethodFunction::Set),
                method: RequestMethod::Set(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeReference::Value(destroy_ids).into(),
                    arguments: set::RequestArguments::Email,
                }),
            }
            .into();
        }

        Ok(response)
    }
}
