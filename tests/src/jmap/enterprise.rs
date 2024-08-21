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

use common::{
    config::telemetry::{StoreTracer, TelemetrySubscriberType},
    enterprise::{license::LicenseKey, undelete::DeletedBlob, Enterprise},
    telemetry::tracers::store::{TracingQuery, TracingStore},
};
use imap_proto::ResponseType;
use jmap::api::management::enterprise::undelete::{UndeleteRequest, UndeleteResponse};
use store::write::now;
use trc::{
    ipc::{bitset::Bitset, subscriber::SubscriberBuilder},
    DeliveryEvent, EventType, SmtpEvent,
};

use crate::{
    imap::{ImapConnection, Type},
    jmap::delivery::SmtpConnection,
};

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

    // Create test account
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "secret", "John Doe")
        .await;

    undelete(params).await;
    tracing(params).await;

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

async fn tracing(params: &mut JMAPTest) {
    // Enable tracing
    let store = params.server.core.storage.data.clone();
    TelemetrySubscriberType::StoreTracer(StoreTracer {
        store: store.clone(),
    })
    .spawn(
        SubscriberBuilder::new("store-tracer".to_string()).with_interests(Box::new(Bitset::all())),
        true,
    );

    // Make sure there are no span entries in the db
    assert_eq!(
        store
            .query_spans(
                &[TracingQuery::EventType(EventType::Smtp(
                    SmtpEvent::ConnectionStart
                ))],
                0,
                0
            )
            .await
            .unwrap(),
        Vec::<u64>::new()
    );

    // Send an email
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "X-Spam-Status: No\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    lmtp.quit().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Purge should not delete anything at this point
    store.purge_spans(Duration::from_secs(1)).await.unwrap();

    // There should be a span entry in the db
    for span_type in [
        EventType::Delivery(DeliveryEvent::AttemptStart),
        EventType::Smtp(SmtpEvent::ConnectionStart),
    ] {
        let spans = store
            .query_spans(&[TracingQuery::EventType(span_type)], 0, 0)
            .await
            .unwrap();
        assert_eq!(spans.len(), 1, "{span_type:?}");
        assert_eq!(
            store.get_span(spans[0]).await.unwrap()[0].inner.typ,
            span_type
        );
    }

    // Try searching
    for keyword in ["bill@example.com", "jdoe@example.com", "example.com"] {
        let spans = store
            .query_spans(&[TracingQuery::Keywords(keyword.to_string())], 0, 0)
            .await
            .unwrap();
        assert_eq!(spans.len(), 2, "keyword: {keyword}");
        assert!(spans[0] > spans[1], "keyword: {keyword}");
    }

    // Purge should delete the span entries
    tokio::time::sleep(Duration::from_millis(800)).await;
    store.purge_spans(Duration::from_secs(1)).await.unwrap();

    for query in [
        TracingQuery::EventType(EventType::Smtp(SmtpEvent::ConnectionStart)),
        TracingQuery::EventType(EventType::Delivery(DeliveryEvent::AttemptStart)),
        TracingQuery::Keywords("bill@example.com".to_string()),
        TracingQuery::Keywords("jdoe@example.com".to_string()),
        TracingQuery::Keywords("example.com".to_string()),
    ] {
        assert_eq!(
            store.query_spans(&[query], 0, 0).await.unwrap(),
            Vec::<u64>::new()
        );
    }
}

async fn undelete(_params: &mut JMAPTest) {
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

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
pub(super) struct List<T> {
    pub items: Vec<T>,
    pub total: usize,
}
