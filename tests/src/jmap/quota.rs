/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use crate::jmap::{
    assert_is_empty, delivery::SmtpConnection, jmap_raw_request, mailbox::destroy_all_mailboxes,
    test_account_login,
};
use jmap::{blob::upload::DISABLE_UPLOAD_QUOTA, mailbox::INBOX_ID};
use jmap_client::{
    core::set::{SetErrorType, SetObject},
    email::EmailBodyPart,
};
use jmap_proto::types::{collection::Collection, id::Id};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running quota tests...");
    let server = params.server.clone();
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    params
        .directory
        .create_test_user_with_email("robert@example.com", "aabbcc", "Robert Foobar")
        .await;
    let other_account_id = Id::from(server.get_account_id("jdoe@example.com").await.unwrap());
    let account_id = Id::from(server.get_account_id("robert@example.com").await.unwrap());
    params
        .directory
        .set_test_quota("robert@example.com", 1024)
        .await;
    params
        .directory
        .add_to_group("robert@example.com", "jdoe@example.com")
        .await;

    // Delete temporary blobs from previous tests
    server.store.blob_hash_expire_all().await;

    // Test temporary blob quota (3 files)
    DISABLE_UPLOAD_QUOTA.store(false, std::sync::atomic::Ordering::Relaxed);
    let client = test_account_login("robert@example.com", "aabbcc").await;
    for i in 0..3 {
        assert_eq!(
            client
                .upload(None, vec![b'A' + i; 1024], None)
                .await
                .unwrap()
                .size(),
            1024
        );
    }
    match client
        .upload(None, vec![b'Z'; 1024], None)
        .await
        .unwrap_err()
    {
        jmap_client::Error::Problem(err) if err.detail().unwrap().contains("quota") => (),
        other => panic!("Unexpected error: {:?}", other),
    }
    server.store.blob_hash_expire_all().await;

    // Test temporary blob quota (50000 bytes)
    for i in 0..2 {
        assert_eq!(
            client
                .upload(None, vec![b'a' + i; 25000], None)
                .await
                .unwrap()
                .size(),
            25000
        );
    }
    match client
        .upload(None, vec![b'z'; 1024], None)
        .await
        .unwrap_err()
    {
        jmap_client::Error::Problem(err) if err.detail().unwrap().contains("quota") => (),
        other => panic!("Unexpected error: {:?}", other),
    }
    server.store.blob_hash_expire_all().await;

    // Test JMAP Quotas extension
    let response = jmap_raw_request(
        r#"[[ "Quota/get", {
            "accountId": "$$",
            "ids": null
          }, "0" ]]"#
            .replace("$$", &account_id.to_string()),
        "robert@example.com",
        "aabbcc",
    )
    .await;
    assert!(response.contains("\"used\":0"), "{}", response);
    assert!(response.contains("\"hardLimit\":1024"), "{}", response);
    assert!(response.contains("\"scope\":\"account\""), "{}", response);
    assert!(
        response.contains("\"name\":\"robert@example.com\""),
        "{}",
        response
    );

    // Test Email/import quota
    let inbox_id = Id::new(INBOX_ID as u64).to_string();
    let mut message_ids = Vec::new();
    for i in 0..2 {
        message_ids.push(
            client
                .email_import(
                    create_message_with_size(
                        "jdoe@example.com",
                        "robert@example.com",
                        &format!("Test {i}"),
                        512,
                    ),
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    assert_over_quota(
        client
            .email_import(
                create_message_with_size("test@example.com", "jdoe@example.com", "Test 3", 100),
                vec![&inbox_id],
                None::<Vec<String>>,
                None,
            )
            .await,
    );

    // Test JMAP Quotas extension
    let response = jmap_raw_request(
        r#"[[ "Quota/get", {
            "accountId": "$$",
            "ids": null
          }, "0" ]]"#
            .replace("$$", &account_id.to_string()),
        "robert@example.com",
        "aabbcc",
    )
    .await;
    assert!(response.contains("\"used\":1024"), "{}", response);
    assert!(response.contains("\"hardLimit\":1024"), "{}", response);

    // Delete messages and check available quota
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    assert_eq!(
        server
            .get_used_quota(account_id.document_id())
            .await
            .unwrap(),
        0
    );

    // Test Email/set quota
    let mut message_ids = Vec::new();
    for i in 0..2 {
        let mut request = client.build();
        let create_item = request.set_email().create();
        create_item
            .mailbox_ids([&inbox_id])
            .subject(format!("Test {i}"))
            .from(["jdoe@example.com"])
            .to(["robert@example.com"])
            .body_value("a".to_string(), String::from_utf8(vec![b'A'; 200]).unwrap())
            .text_body(EmailBodyPart::new().part_id("a"));
        let create_id = create_item.create_id().unwrap();
        message_ids.push(
            request
                .send_set_email()
                .await
                .unwrap()
                .created(&create_id)
                .unwrap()
                .take_id(),
        );
    }
    let mut request = client.build();
    let create_item = request.set_email().create();
    create_item
        .mailbox_ids([&inbox_id])
        .subject("Test 3")
        .from(["jdoe@example.com"])
        .to(["robert@example.com"])
        .body_value("a".to_string(), String::from_utf8(vec![b'A'; 400]).unwrap())
        .text_body(EmailBodyPart::new().part_id("a"));
    let create_id = create_item.create_id().unwrap();
    assert_over_quota(request.send_set_email().await.unwrap().created(&create_id));

    // Delete messages and check available quota
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    assert_eq!(
        server
            .get_used_quota(account_id.document_id())
            .await
            .unwrap(),
        0
    );

    // Test Email/copy quota
    let other_client = test_account_login("jdoe@example.com", "12345").await;
    let mut other_message_ids = Vec::new();
    let mut message_ids = Vec::new();
    for i in 0..3 {
        other_message_ids.push(
            other_client
                .email_import(
                    create_message_with_size(
                        "jane@example.com",
                        "jdoe@example.com",
                        &format!("Other Test {i}"),
                        512,
                    ),
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    for id in other_message_ids.iter().take(2) {
        message_ids.push(
            client
                .email_copy(
                    other_account_id.to_string(),
                    id,
                    vec![&inbox_id],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }
    assert_over_quota(
        client
            .email_copy(
                other_account_id.to_string(),
                &other_message_ids[2],
                vec![&inbox_id],
                None::<Vec<String>>,
                None,
            )
            .await,
    );

    // Delete messages and check available quota
    for message_id in message_ids {
        client.email_destroy(&message_id).await.unwrap();
    }
    assert_eq!(
        server
            .get_used_quota(account_id.document_id())
            .await
            .unwrap(),
        0
    );

    // Test delivery quota
    let mut lmtp = SmtpConnection::connect().await;
    for i in 0..2 {
        lmtp.ingest(
            "jane@example.com",
            &["robert@example.com"],
            &String::from_utf8(create_message_with_size(
                "jane@example.com",
                "robert@example.com",
                &format!("Ingest test {i}"),
                100,
            ))
            .unwrap(),
        )
        .await;
    }
    let quota = server
        .get_used_quota(account_id.document_id())
        .await
        .unwrap();
    assert!(quota > 0 && quota <= 1024, "Quota is {}", quota);
    assert_eq!(
        server
            .get_document_ids(account_id.document_id(), Collection::Email)
            .await
            .unwrap()
            .unwrap()
            .len(),
        1,
    );
    DISABLE_UPLOAD_QUOTA.store(true, std::sync::atomic::Ordering::Relaxed);

    // Remove test data
    for account_id in [&account_id, &other_account_id] {
        params.client.set_default_account_id(account_id.to_string());
        destroy_all_mailboxes(&params.client).await;
    }
    assert_is_empty(server).await;
}

fn assert_over_quota<T: std::fmt::Debug>(result: Result<T, jmap_client::Error>) {
    match result {
        Ok(result) => panic!("Expected error, got {:?}", result),
        Err(jmap_client::Error::Set(err)) if err.error() == &SetErrorType::OverQuota => (),
        Err(err) => panic!("Expected OverQuota SetError, got {:?}", err),
    }
}

fn create_message_with_size(from: &str, to: &str, subject: &str, size: usize) -> Vec<u8> {
    let mut message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n",
        from, to, subject
    );
    for _ in 0..size - message.len() {
        message.push('A');
    }

    message.into_bytes()
}
