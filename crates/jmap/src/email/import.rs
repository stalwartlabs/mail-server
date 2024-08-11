/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::import::{ImportEmailRequest, ImportEmailResponse},
    types::{
        acl::Acl,
        collection::Collection,
        id::Id,
        property::Property,
        state::{State, StateChange},
        type_state::DataType,
    },
};
use mail_parser::MessageParser;
use utils::map::vec_map::VecMap;

use crate::{api::http::HttpSessionData, auth::AccessToken, JMAP};

use super::ingest::{IngestEmail, IngestSource};

impl JMAP {
    pub async fn email_import(
        &self,
        request: ImportEmailRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<ImportEmailResponse> {
        // Validate state
        let account_id = request.account_id.document_id();
        let old_state: State = self
            .assert_state(account_id, Collection::Email, &request.if_in_state)
            .await?;

        let valid_mailbox_ids = self.mailbox_get_or_create(account_id).await?;
        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            self.shared_documents(access_token, account_id, Collection::Mailbox, Acl::AddItems)
                .await?
                .into()
        } else {
            None
        };

        // Obtain quota
        let account_quota = self.get_quota(access_token, account_id).await?;

        let mut response = ImportEmailResponse {
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state: old_state.into(),
            created: VecMap::with_capacity(request.emails.len()),
            not_created: VecMap::new(),
            state_change: None,
        };

        'outer: for (id, email) in request.emails {
            // Validate mailboxIds
            let mailbox_ids = email
                .mailbox_ids
                .unwrap()
                .into_iter()
                .map(|m| m.unwrap().document_id())
                .collect::<Vec<_>>();
            if mailbox_ids.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::MailboxIds)
                        .with_description("Message must belong to at least one mailbox."),
                );
                continue;
            }
            for mailbox_id in &mailbox_ids {
                if !valid_mailbox_ids.contains(*mailbox_id) {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description(format!(
                                "Mailbox {} does not exist.",
                                Id::from(*mailbox_id)
                            )),
                    );
                    continue 'outer;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {}.",
                            Id::from(*mailbox_id)
                        )),
                    );
                    continue 'outer;
                }
            }

            // Fetch raw message to import
            let raw_message = match self.blob_download(&email.blob_id, access_token).await? {
                Some(raw_message) => raw_message,
                None => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::BlobNotFound)
                            .with_description(format!("BlobId {} not found.", email.blob_id)),
                    );
                    continue;
                }
            };

            // Import message
            match self
                .email_ingest(IngestEmail {
                    raw_message: &raw_message,
                    message: MessageParser::new().parse(&raw_message),
                    account_id,
                    account_quota,
                    mailbox_ids,
                    keywords: email.keywords,
                    received_at: email.received_at.map(|r| r.into()),
                    source: IngestSource::Jmap,
                    encrypt: self.core.jmap.encrypt && self.core.jmap.encrypt_append,
                    session_id: session.session_id,
                })
                .await
            {
                Ok(email) => {
                    response.created.append(id, email.into());
                }
                Err(mut err) => match err.as_ref() {
                    trc::EventType::Limit(trc::LimitEvent::Quota) => {
                        response.not_created.append(
                            id,
                            SetError::new(SetErrorType::OverQuota)
                                .with_description("You have exceeded your disk quota."),
                        );
                    }
                    trc::EventType::MessageIngest(trc::MessageIngestEvent::Error) => {
                        response.not_created.append(
                            id,
                            SetError::new(SetErrorType::InvalidEmail).with_description(
                                err.take_value(trc::Key::Reason)
                                    .and_then(|v| v.into_string())
                                    .unwrap(),
                            ),
                        );
                    }
                    _ => {
                        return Err(err);
                    }
                },
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

        Ok(response)
    }
}
