/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fs, path::PathBuf};

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes};
use ahash::AHashSet;
use jmap::mailbox::INBOX_ID;
use jmap_client::{
    client::Client,
    core::set::{SetError, SetErrorType},
    email::{self, Email},
    mailbox::Role,
    Error, Set,
};
use jmap_proto::types::id::Id;

use super::{find_values, replace_blob_ids, replace_boundaries, replace_values, JMAPTest};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Set tests...");
    let server = params.server.clone();

    let mailbox_id = Id::from(INBOX_ID).to_string();
    params.client.set_default_account_id(Id::from(1u64));

    create(&mut params.client, &mailbox_id).await;
    update(&mut params.client, &mailbox_id).await;

    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}

async fn create(client: &mut Client, mailbox_id: &str) {
    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("jmap");
    test_dir.push("email_set");

    for file_name in fs::read_dir(&test_dir).unwrap() {
        let mut file_name = file_name.as_ref().unwrap().path();
        if file_name.extension().map_or(true, |e| e != "json") {
            continue;
        }
        println!("Creating email from {:?}", file_name);

        // Upload blobs
        let mut json_request = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
        let blob_values = find_values(&json_request, "\"blobId\"");
        if !blob_values.is_empty() {
            let mut blob_ids = Vec::with_capacity(blob_values.len());
            for blob_value in &blob_values {
                let blob_value = blob_value.replace("\\r", "\r").replace("\\n", "\n");
                blob_ids.push(
                    client
                        .upload(None, blob_value.into_bytes(), None)
                        .await
                        .unwrap()
                        .take_blob_id(),
                );
            }
            json_request = replace_values(json_request, &blob_values, &blob_ids);
        }

        // Create message and obtain its blobId
        let mut request = client.build();
        let mut create_item =
            serde_json::from_slice::<Email<Set>>(json_request.as_bytes()).unwrap();
        create_item.mailbox_ids([mailbox_id]);
        let create_id = request.set_email().create_item(create_item);
        let created_email = request
            .send_set_email()
            .await
            .unwrap()
            .created(&create_id)
            .unwrap();

        // Download raw message
        let raw_message = client
            .download(created_email.blob_id().unwrap())
            .await
            .unwrap();

        // Fetch message
        let mut request = client.build();
        request
            .get_email()
            .ids([created_email.id().unwrap()])
            .properties([
                email::Property::Id,
                email::Property::BlobId,
                email::Property::ThreadId,
                email::Property::MailboxIds,
                email::Property::Keywords,
                email::Property::ReceivedAt,
                email::Property::MessageId,
                email::Property::InReplyTo,
                email::Property::References,
                email::Property::Sender,
                email::Property::From,
                email::Property::To,
                email::Property::Cc,
                email::Property::Bcc,
                email::Property::ReplyTo,
                email::Property::Subject,
                email::Property::SentAt,
                email::Property::HasAttachment,
                email::Property::Preview,
                email::Property::BodyValues,
                email::Property::TextBody,
                email::Property::HtmlBody,
                email::Property::Attachments,
                email::Property::BodyStructure,
            ])
            .arguments()
            .body_properties([
                email::BodyProperty::PartId,
                email::BodyProperty::BlobId,
                email::BodyProperty::Size,
                email::BodyProperty::Name,
                email::BodyProperty::Type,
                email::BodyProperty::Charset,
                email::BodyProperty::Headers,
                email::BodyProperty::Disposition,
                email::BodyProperty::Cid,
                email::BodyProperty::Language,
                email::BodyProperty::Location,
            ])
            .fetch_all_body_values(true)
            .max_body_value_bytes(100);
        let email = request
            .send_get_email()
            .await
            .unwrap()
            .pop()
            .unwrap()
            .into_test();

        // Compare raw message
        file_name.set_extension("eml");
        let result = replace_boundaries(String::from_utf8(raw_message).unwrap());

        if fs::read(&file_name).unwrap() != result.as_bytes() {
            file_name.set_extension("eml_failed");
            fs::write(&file_name, result.as_bytes()).unwrap();
            panic!("Test failed, output saved to {}", file_name.display());
        }

        // Compare response
        file_name.set_extension("jmap");
        let result = replace_blob_ids(replace_boundaries(
            serde_json::to_string_pretty(&email).unwrap(),
        ));
        if fs::read(&file_name).unwrap() != result.as_bytes() {
            file_name.set_extension("jmap_failed");
            fs::write(&file_name, result.as_bytes()).unwrap();
            panic!("Test failed, output saved to {}", file_name.display());
        }
    }
}

async fn update(client: &mut Client, root_mailbox_id: &str) {
    // Obtain all messageIds previously created
    let mailbox = client
        .email_query(
            email::query::Filter::in_mailbox(root_mailbox_id).into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap();

    // Create two test mailboxes
    let test_mailbox1_id = client
        .set_default_account_id(Id::new(1).to_string())
        .mailbox_create("Test 1", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let test_mailbox2_id = client
        .set_default_account_id(Id::new(1).to_string())
        .mailbox_create("Test 2", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    // Set keywords and mailboxes
    let mut request = client.build();
    request
        .set_email()
        .update(mailbox.id(0))
        .mailbox_ids([&test_mailbox1_id, &test_mailbox2_id])
        .keywords(["test1", "test2"]);
    request
        .send_set_email()
        .await
        .unwrap()
        .updated(mailbox.id(0))
        .unwrap();
    assert_email_properties(
        client,
        mailbox.id(0),
        &[&test_mailbox1_id, &test_mailbox2_id],
        &["test1", "test2"],
    )
    .await;

    // Patch keywords and mailboxes
    let mut request = client.build();
    request
        .set_email()
        .update(mailbox.id(0))
        .mailbox_id(&test_mailbox1_id, false)
        .keyword("test1", true)
        .keyword("test2", false)
        .keyword("test3", true);
    request
        .send_set_email()
        .await
        .unwrap()
        .updated(mailbox.id(0))
        .unwrap();
    assert_email_properties(
        client,
        mailbox.id(0),
        &[&test_mailbox2_id],
        &["test1", "test3"],
    )
    .await;

    // Orphan messages should not be permitted
    let mut request = client.build();
    request
        .set_email()
        .update(mailbox.id(0))
        .mailbox_id(&test_mailbox2_id, false);
    assert!(matches!(
        request
            .send_set_email()
            .await
            .unwrap()
            .updated(mailbox.id(0)),
        Err(Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));

    // Updating and destroying the same item should not be allowed
    let mut request = client.build();
    let set_email_request = request.set_email();
    set_email_request
        .update(mailbox.id(0))
        .mailbox_id(&test_mailbox2_id, false);
    set_email_request.destroy([mailbox.id(0)]);
    assert!(matches!(
        request
            .send_set_email()
            .await
            .unwrap()
            .updated(mailbox.id(0)),
        Err(Error::Set(SetError {
            type_: SetErrorType::WillDestroy,
            ..
        }))
    ));

    // Delete some messages
    let mut request = client.build();
    request.set_email().destroy([mailbox.id(1), mailbox.id(2)]);
    assert_eq!(
        request
            .send_set_email()
            .await
            .unwrap()
            .destroyed_ids()
            .unwrap()
            .count(),
        2
    );
    let mut request = client.build();
    request.get_email().ids([mailbox.id(1), mailbox.id(2)]);
    assert_eq!(request.send_get_email().await.unwrap().not_found().len(), 2);

    // Destroy test mailboxes
    client
        .mailbox_destroy(&test_mailbox1_id, true)
        .await
        .unwrap();
    client
        .mailbox_destroy(&test_mailbox2_id, true)
        .await
        .unwrap();
}

pub async fn assert_email_properties(
    client: &mut Client,
    message_id: &str,
    mailbox_ids: &[&str],
    keywords: &[&str],
) {
    let result = client
        .email_get(
            message_id,
            [email::Property::MailboxIds, email::Property::Keywords].into(),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        mailbox_ids.iter().copied().collect::<AHashSet<_>>(),
        result
            .mailbox_ids()
            .iter()
            .copied()
            .collect::<AHashSet<_>>()
    );

    assert_eq!(
        keywords.iter().copied().collect::<AHashSet<_>>(),
        result.keywords().iter().copied().collect::<AHashSet<_>>()
    );
}
