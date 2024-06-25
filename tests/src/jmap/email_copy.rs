/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_client::mailbox::Role;
use jmap_proto::types::id::Id;

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Copy tests...");
    let server = params.server.clone();

    // Create a mailbox on account 1
    let ac1_mailbox_id = params
        .client
        .set_default_account_id(Id::new(1).to_string())
        .mailbox_create("Copy Test Ac# 1", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    // Insert a message on account 1
    let ac1_email_id = params
        .client
        .email_import(
            concat!(
                "From: bill@example.com\r\n",
                "To: jdoe@example.com\r\n",
                "Subject: TPS Report\r\n",
                "\r\n",
                "I'm going to need those TPS reports ASAP. ",
                "So, if you could do that, that'd be great."
            )
            .as_bytes()
            .to_vec(),
            [&ac1_mailbox_id],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();

    // Create a mailbox on account 2
    let ac2_mailbox_id = params
        .client
        .set_default_account_id(Id::new(2).to_string())
        .mailbox_create("Copy Test Ac# 2", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    // Copy the email and delete it from the first account
    let mut request = params.client.build();
    request
        .copy_email(Id::new(1).to_string())
        .on_success_destroy_original(true)
        .create(&ac1_email_id)
        .mailbox_id(&ac2_mailbox_id, true)
        .keyword("$draft", true)
        .received_at(311923920);
    let ac2_email_id = request
        .send()
        .await
        .unwrap()
        .method_response_by_pos(0)
        .unwrap_copy_email()
        .unwrap()
        .created(&ac1_email_id)
        .unwrap()
        .take_id();

    // Check that the email was copied
    let email = params
        .client
        .email_get(&ac2_email_id, None::<Vec<_>>)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        email.preview().unwrap(),
        "I'm going to need those TPS reports ASAP. So, if you could do that, that'd be great."
    );
    assert_eq!(email.subject().unwrap(), "TPS Report");
    assert_eq!(email.mailbox_ids(), &[&ac2_mailbox_id]);
    assert_eq!(email.keywords(), &["$draft"]);
    assert_eq!(email.received_at().unwrap(), 311923920);

    // Check that the email was deleted
    assert!(params
        .client
        .set_default_account_id(Id::new(1).to_string())
        .email_get(&ac1_email_id, None::<Vec<_>>)
        .await
        .unwrap()
        .is_none());

    // Empty store
    destroy_all_mailboxes(params).await;
    params.client.set_default_account_id(Id::new(2).to_string());
    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}
