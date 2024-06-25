/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::PathBuf;

use directory::backend::internal::manage::ManageDirectory;
use jmap::email::crypto::{
    try_parse_certs, Algorithm, EncryptMessage, EncryptionMethod, EncryptionParams, EncryptionType,
};
use jmap_proto::types::id::Id;
use mail_parser::{MessageParser, MimeHeaders};

use crate::jmap::{delivery::SmtpConnection, ManagementApi};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Encryption-at-rest tests...");

    // Create test account
    let server = params.server.clone();
    let client = &mut params.client;
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    let account_id = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jdoe@example.com")
            .await
            .unwrap(),
    )
    .to_string();

    // Build API
    let api = ManagementApi::new(8899, "jdoe@example.com", "12345");

    // Try importing using multiple methods and symmetric algos
    for (file_name, method, num_certs) in [
        ("cert_smime.pem", EncryptionMethod::SMIME, 3),
        ("cert_pgp.pem", EncryptionMethod::PGP, 1),
    ] {
        let certs = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("crypto")
                .join(file_name),
        )
        .unwrap();

        for algo in [Algorithm::Aes128, Algorithm::Aes256] {
            let request = match method {
                EncryptionMethod::PGP => EncryptionType::PGP {
                    algo,
                    certs: certs.clone(),
                },
                EncryptionMethod::SMIME => EncryptionType::SMIME {
                    algo,
                    certs: certs.clone(),
                },
            };

            assert_eq!(
                api.post::<u32>("/api/crypto", &request)
                    .await
                    .unwrap()
                    .unwrap_data(),
                num_certs
            );
        }
    }

    // Send a new message, which should be encrypted
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report (should be encrypted)\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    // Send an encrypted message
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report (already encrypted)\r\n",
            "Content-Type: application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data\r\n",
            "\r\n",
            "xjMEZMYfNhYJKwYBBAHaRw8BAQdAYyTN1HzqapLw8xwkCGwa0OjsgT/JqhcB/+Dy",
            "Ga1fsBrNG0pvaG4gRG9lIDxqb2huQGV4YW1wbGUub3JnPsKJBBMWCAAxFiEEg836",
            "pwbXpuQ/THMtpJwd4oBfIrUFAmTGHzYCGwMECwkIBwUVCAkKCwUWAgMBAAAKCRCk",
            "nB3igF8itYhyAQD2jEdeYa3gyQ47X9YWZTK1wEJkN8W9//V1fYl2XQwqlQEA0qBv",
            "Ai6nUh99oDw+/zQ8DFIKdeb5Ti4tu/X58PdpiQ7OOARkxh82EgorBgEEAZdVAQUB",
            "AQdAvXz2FbFN0DovQF/ACnZyczTsSIQp0mvmF1PE+aijbC8DAQgHwngEGBYIACAW",
            "IQSDzfqnBtem5D9Mcy2knB3igF8itQUCZMYfNgIbDAAKCRCknB3igF8itRnoAQC3",
            "GzPmgx7TnB+SexPuJV/DoKSMJ0/X+hbEFcZkulxaDQEAh+xiJCvf+ZNAKw6kFhsL",
            "UuZhEDktxnY6Ehz3aB7FawA=",
            "=KGrr",
        ),
    )
    .await;

    // Disable encryption
    assert_eq!(
        api.post::<Option<String>>("/api/crypto", &EncryptionType::Disabled)
            .await
            .unwrap()
            .unwrap_data(),
        None
    );

    // Send a new message, which should NOT be encrypted
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report (plain text)\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    // Check messages
    client.set_default_account_id(&account_id);
    let mut request = client.build();
    request.get_email();
    let emails = request.send_get_email().await.unwrap().take_list();
    assert_eq!(emails.len(), 3, "3 messages were expected: {:#?}.", emails);

    for email in emails {
        let message =
            String::from_utf8(client.download(email.blob_id().unwrap()).await.unwrap()).unwrap();
        if message.contains("should be encrypted") {
            assert!(
                message.contains("Content-Type: multipart/encrypted"),
                "got message {message}, expected encrypted message"
            );
        } else if message.contains("already encrypted") {
            assert!(
                message.contains("Content-Type: application/pkcs7-mime")
                    && message.contains("xjMEZMYfNhYJKwYBBAHaRw8BAQdAYy"),
                "got message {message}, expected message to be left intact"
            );
        } else if message.contains("plain text") {
            assert!(
                message.contains("I'm going to need those TPS reports ASAP."),
                "got message {message}, expected plain text message"
            );
        } else {
            panic!("Unexpected message: {:#?}", message)
        }
    }
}

#[tokio::test]
pub async fn import_certs_and_encrypt() {
    for (name, method, expected_certs) in [
        ("cert_pgp.pem", EncryptionMethod::PGP, 1),
        //("cert_pgp.der", EncryptionMethod::PGP, 1),
        ("cert_smime.pem", EncryptionMethod::SMIME, 3),
        ("cert_smime.der", EncryptionMethod::SMIME, 1),
    ] {
        let mut certs = try_parse_certs(
            method,
            std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("crypto")
                    .join(name),
            )
            .unwrap(),
        )
        .expect(name);

        assert_eq!(certs.len(), expected_certs);

        if method == EncryptionMethod::PGP && certs.len() == 2 {
            // PGP library won't encrypt using EC
            certs.pop();
        }

        let mut params = EncryptionParams {
            method,
            algo: Algorithm::Aes128,
            certs,
        };

        for algo in [Algorithm::Aes128, Algorithm::Aes256] {
            let message = MessageParser::new()
                .parse(b"Subject: test\r\ntest\r\n")
                .unwrap();
            assert!(!message.is_encrypted());
            params.algo = algo;
            message.encrypt(&params).await.unwrap();
        }
    }

    // S/MIME and PGP should not be allowed mixed
    assert!(try_parse_certs(
        EncryptionMethod::PGP,
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("crypto")
                .join("cert_mixed.pem"),
        )
        .unwrap(),
    )
    .is_err());
}

#[test]
pub fn check_is_encrypted() {
    let messages = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("crypto")
            .join("is_encrypted.txt"),
    )
    .unwrap();

    for raw_message in messages.split("---") {
        let is_encrypted = raw_message.contains("TRUE");
        let message = MessageParser::new()
            .parse(raw_message.trim().as_bytes())
            .unwrap();
        assert!(message.content_type().is_some());
        assert_eq!(
            message.is_encrypted(),
            is_encrypted,
            "failed for {raw_message}"
        );
    }
}
