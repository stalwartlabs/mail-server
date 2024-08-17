/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::time::Duration;

use common::enterprise::{license::LicenseKey, undelete::DeletedBlob, Enterprise};
use imap_proto::ResponseType;
use jmap::api::management::enterprise::undelete::{UndeleteRequest, UndeleteResponse};
use store::write::now;

use crate::imap::{ImapConnection, Type};

use super::{delivery::AssertResult, JMAPTest, ManagementApi};

pub async fn test(params: &mut JMAPTest) {
    // Enable Enterprise
    let mut core = params.server.shared_core.load_full().as_ref().clone();
    core.enterprise = Enterprise {
        license: LicenseKey {
            valid_to: now() + 3600,
            valid_from: now() - 3600,
            hostname: String::new(),
            accounts: 100,
        },
        undelete_period: Duration::from_secs(2).into(),
        trace_hold_period: Duration::from_secs(1).into(),
        trace_store: core.storage.data.clone().into(),
    }
    .into();
    params.server.shared_core.store(core.into());
    assert!(params.server.shared_core.load().is_enterprise_edition());

    // Undelete
    undelete(params).await;

    // Disable Enterprise
    let mut core = params.server.shared_core.load_full().as_ref().clone();
    core.enterprise = None;
    params.server.shared_core.store(core.into());
}

const RAW_MESSAGE: &str = "From: john@example.com
To: john@example.com
Subject: undelete test

test
";

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
pub(super) struct List<T> {
    pub items: Vec<T>,
    pub total: usize,
}

async fn undelete(params: &mut JMAPTest) {
    // Create test account
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "secret", "John Doe")
        .await;

    // Authenticate
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.send("AUTHENTICATE PLAIN {32+}\r\nAGpkb2VAZXhhbXBsZS5jb20Ac2VjcmV0")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Insert test message
    imap.send("STATUS INBOX (MESSAGES)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 0");
    imap.send(&format!("APPEND INBOX {{{}}}", RAW_MESSAGE.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(RAW_MESSAGE).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Make sure the message is there
    imap.send("STATUS INBOX (MESSAGES)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 1");
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Fetch message body
    imap.send("FETCH 1 BODY[]").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("Subject: undelete test");

    // Delete and expunge message
    imap.send("STORE 1 +FLAGS (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Logout and reconnect
    imap.send("LOGOUT").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.send("AUTHENTICATE PLAIN {32+}\r\nAGpkb2VAZXhhbXBsZS5jb20Ac2VjcmV0")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Make sure the message is gone
    imap.send("STATUS INBOX (MESSAGES)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 0");

    // Query undelete API
    let api = ManagementApi::new(8899, "admin", "secret");
    api.get::<serde_json::Value>("/api/store/purge/account/jdoe@example.com")
        .await
        .unwrap();
    let deleted = api
        .get::<List<DeletedBlob<String, String, String>>>("/api/store/undelete/jdoe@example.com")
        .await
        .unwrap()
        .unwrap_data()
        .items;
    assert_eq!(deleted.len(), 1);
    let deleted = deleted.into_iter().next().unwrap();

    // Undelete
    let result = api
        .post::<Vec<UndeleteResponse>>(
            "/api/store/undelete/jdoe@example.com",
            &vec![UndeleteRequest {
                hash: deleted.hash,
                collection: deleted.collection,
                time: deleted.deleted_at,
                cancel_deletion: deleted.expires_at.into(),
            }],
        )
        .await
        .unwrap()
        .unwrap_data();
    assert_eq!(result, vec![UndeleteResponse::Success]);

    // Make sure the message is back
    imap.send("STATUS INBOX (MESSAGES)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 1");

    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Fetch message body
    imap.send("FETCH 1 BODY[]").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("Subject: undelete test");
}
