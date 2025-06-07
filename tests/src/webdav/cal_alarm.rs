/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use email::{cache::MessageCacheFetch, message::metadata::MessageMetadata};
use hyper::StatusCode;
use jmap_proto::types::{collection::Collection, property::Property};
use mail_parser::{DateTime, MessageParser};
use store::write::now;

pub async fn test(test: &WebDavTest) {
    println!("Running calendar e-mail alarms tests...");
    let client = test.client("john");
    client
        .request_with_headers(
            "PUT",
            "/dav/cal/john/default/its-alarming-how-charming-i-feel.ics",
            [("content-type", "text/calendar; charset=utf-8")],
            TEST_ALARM_1.replace(
                "$START",
                &DateTime::from_timestamp(now() as i64 + 5)
                    .to_rfc3339()
                    .replace(['-', ':'], ""),
            ),
        )
        .await
        .with_status(StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    // Check that the alarm was sent
    let messages = test
        .server
        .get_cached_messages(client.account_id)
        .await
        .unwrap();
    assert_eq!(messages.emails.items.len(), 2);

    for (idx, message) in messages.emails.items.iter().enumerate() {
        let metadata_ = test
            .server
            .get_archive_by_property(
                client.account_id,
                Collection::Email,
                message.document_id,
                Property::BodyStructure,
            )
            .await
            .unwrap()
            .unwrap();
        let contents = test
            .server
            .blob_store()
            .get_blob(
                metadata_
                    .unarchive::<MessageMetadata>()
                    .unwrap()
                    .blob_hash
                    .0
                    .as_slice(),
                0..usize::MAX,
            )
            .await
            .unwrap()
            .unwrap();

        //let t = std::fs::write(format!("message_{}.eml", message.document_id), &contents).unwrap();

        let message = MessageParser::new().parse(&contents).unwrap();
        let contents = message
            .html_bodies()
            .next()
            .unwrap()
            .text_contents()
            .unwrap();

        if idx == 0 {
            // First alarm does not have a summary or description
            assert!(
                contents.contains("See the pretty girl in that mirror there"),
                "failed for {contents}"
            );
            assert!(
                contents.contains("What mirror where?!"),
                "failed for {contents}"
            );
        } else {
            assert!(
                contents.contains("I feel pretty and witty and gay"),
                "failed for {contents}"
            );
            assert!(
                contents.contains("It&#39;s alarming how charming I feel."),
                "failed for {contents}"
            );
        }
        assert!(
            contents.contains(concat!(
                "/dav/cal/john/default/",
                "its-alarming-how-charming-i-feel.ics"
            )),
            "failed for {contents}"
        );
    }
}

const TEST_ALARM_1: &str = r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID: 2371c2d9-a136-43b0-bba3-f6ab249ad46e
SUMMARY:See the pretty girl in that mirror there
DESCRIPTION:What mirror where?!
DTSTART:$START
DTEND;TZID=America/New_York:21250221T180000
LOCATION:West Side
BEGIN:VALARM
TRIGGER:-P2S
ACTION:EMAIL
ATTENDEE:mailto:john_doe@unknown.com
SUMMARY:I feel pretty and witty and gay
DESCRIPTION:I feel charming, Oh, so charming, It's alarming how charming I feel.
END:VALARM
BEGIN:VALARM
TRIGGER:-P4S
ACTION:EMAIL
END:VALARM
END:VEVENT
END:VCALENDAR
"#;
