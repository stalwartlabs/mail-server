use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::import::{ImportEmailRequest, ImportEmailResponse},
    types::{acl::Acl, collection::Collection, property::Property, state::State},
};
use utils::map::vec_map::VecMap;

use crate::{auth::AclToken, MaybeError, JMAP};

impl JMAP {
    pub async fn email_import(
        &self,
        request: ImportEmailRequest,
        acl_token: &AclToken,
    ) -> Result<ImportEmailResponse, MethodError> {
        // Validate state
        let account_id = request.account_id.document_id();
        let old_state: State = self
            .assert_state(account_id, Collection::Email, &request.if_in_state)
            .await?;

        let valid_mailbox_ids = self.mailbox_get_or_create(account_id).await?;
        let can_add_mailbox_ids = if acl_token.is_shared(account_id) {
            self.shared_documents(acl_token, account_id, Collection::Mailbox, Acl::AddItems)
                .await?
                .into()
        } else {
            None
        };

        let mut created = VecMap::with_capacity(request.emails.len());
        let mut not_created = VecMap::with_capacity(request.emails.len());

        'outer: for (id, email) in request.emails {
            // Validate mailboxIds
            let mailbox_ids = email
                .mailbox_ids
                .unwrap()
                .into_iter()
                .map(|m| m.unwrap().document_id())
                .collect::<Vec<_>>();
            if mailbox_ids.is_empty() {
                not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::MailboxIds)
                        .with_description("Message must belong to at least one mailbox."),
                );
                continue;
            }
            for mailbox_id in &mailbox_ids {
                if !valid_mailbox_ids.contains(*mailbox_id) {
                    not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description(format!("Mailbox {} does not exist.", mailbox_id)),
                    );
                    continue 'outer;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {mailbox_id}."
                        )),
                    );
                    continue 'outer;
                }
            }

            // Fetch raw message to import
            let raw_message = match self.blob_download(&email.blob_id, acl_token).await {
                Ok(Some(raw_message)) => raw_message,
                Ok(None) => {
                    not_created.append(
                        id,
                        SetError::new(SetErrorType::BlobNotFound)
                            .with_description(format!("BlobId {} not found.", email.blob_id)),
                    );
                    continue;
                }
                Err(err) => {
                    tracing::error!(event = "error",
                    context = "store",
                    account_id = account_id,
                    blob_id = ?email.blob_id,
                    error = ?err,
                    "Failed to retrieve blob");
                    return Err(MethodError::ServerPartialFail);
                }
            };

            // Import message
            match self
                .email_ingest(
                    &raw_message,
                    account_id,
                    mailbox_ids,
                    email.keywords,
                    email.received_at.map(|r| r.into()),
                )
                .await
            {
                Ok(email) => {
                    created.append(id, email.into());
                }
                Err(MaybeError::Permanent(reason)) => {
                    not_created.append(
                        id,
                        SetError::new(SetErrorType::InvalidEmail).with_description(reason),
                    );
                }
                Err(MaybeError::Temporary) => {
                    return Err(MethodError::ServerPartialFail);
                }
            }
        }

        Ok(ImportEmailResponse {
            account_id: request.account_id,
            new_state: if !created.is_empty() {
                self.get_state(account_id, Collection::Email).await?
            } else {
                old_state.clone()
            },
            old_state: old_state.into(),
            created: if !created.is_empty() {
                created.into()
            } else {
                None
            },
            not_created: if !not_created.is_empty() {
                not_created.into()
            } else {
                None
            },
        })
    }
}
