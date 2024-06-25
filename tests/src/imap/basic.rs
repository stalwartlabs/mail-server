/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap::op::authenticate::decode_challenge_oauth;
use imap_proto::ResponseType;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;

use super::{AssertResult, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection) {
    println!("Running basic tests...");

    // Test CAPABILITY
    imap.send("CAPABILITY").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Test NOOP
    imap.send("NOOP").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Test ID
    imap.send("ID").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* ID (\"name\" \"Stalwart IMAP\" \"version\" ");

    // Login should be disabled
    imap.send("LOGIN jdoe@example.com secret").await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;

    // Try logging in with wrong password
    imap.send("AUTHENTICATE PLAIN {24}").await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged("AGJvYXR5AG1jYm9hdGZhY2U=").await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;
}

#[test]
fn decode_challenge() {
    assert!(
        Credentials::OAuthBearer {
            token: "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==".to_string()
        } == decode_challenge_oauth(
            &base64_decode(
                concat!(
                    "bixhPXVzZXJAZXhhbXBsZS5jb20sAWhv",
                    "c3Q9c2VydmVyLmV4YW1wbGUuY29tAXBvcnQ9MTQzAWF1dGg9QmVhcmVyI",
                    "HZGOWRmdDRxbVRjMk52YjNSbGNrQmhiSFJoZG1semRHRXVZMjl0Q2c9PQ",
                    "EB"
                )
                .as_bytes(),
            )
            .unwrap(),
        )
        .unwrap()
    );
}
