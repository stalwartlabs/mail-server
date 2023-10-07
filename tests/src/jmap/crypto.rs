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

use std::{path::PathBuf, sync::Arc, time::Duration};

use ahash::AHashMap;
use jmap::{
    email::crypto::{
        try_parse_certs, Algorithm, EncryptMessage, EncryptionMethod, EncryptionParams,
    },
    JMAP,
};
use jmap_client::client::Client;
use jmap_proto::types::id::Id;
use mail_parser::{MessageParser, MimeHeaders};

use crate::{directory::sql::create_test_user_with_email, jmap::delivery::SmtpConnection};

pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running Encryption-at-rest tests...");

    // Create test account
    create_test_user_with_email(
        server.directory.as_ref(),
        "jdoe@example.com",
        "12345",
        "John Doe",
    )
    .await;
    let account_id = Id::from(server.get_account_id("jdoe@example.com").await.unwrap()).to_string();

    // Update
    let mut params = AHashMap::from_iter([
        ("email".to_string(), b"jdoe@example.com".to_vec()),
        ("password".to_string(), b"12345".to_vec()),
    ]);

    // Try importing using multiple methods and symmetric algos
    for (file_name, method, num_certs) in [
        ("cert_smime.pem", EncryptionMethod::SMIME, 3),
        ("cert_pgp.der", EncryptionMethod::PGP, 1),
    ] {
        params.insert(
            "certificate".to_string(),
            std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("crypto")
                    .join(file_name),
            )
            .unwrap(),
        );

        for algo in [Algorithm::Aes128, Algorithm::Aes256] {
            let encryption = format!(
                "{}-{}",
                match method {
                    EncryptionMethod::PGP => "pgp",
                    EncryptionMethod::SMIME => "smime",
                },
                match algo {
                    Algorithm::Aes128 => "128",
                    Algorithm::Aes256 => "256",
                }
            );
            params.insert("encryption".to_string(), encryption.as_bytes().to_vec());
            let response = post(&params).await;
            assert!(
                response.contains(&format!("{num_certs} certificate")),
                "got response {response}, expected {num_certs} certs"
            );
            assert!(
                response.contains(&format!("{method} ({algo})")),
                "got response {response}, expected {encryption} algo"
            );
            println!("response = {response}");
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
    params.remove("certificate");
    params.insert("encryption".to_string(), "disable".as_bytes().to_vec());
    let response = post(&params).await;
    assert!(
        response.contains("Encryption at rest disabled"),
        "got response {response}, expected 'Encryption at rest disabled'"
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
    for (name, expected_method, expected_certs) in [
        ("cert_pgp.pem", EncryptionMethod::PGP, 1),
        //("cert_pgp.der", EncryptionMethod::PGP, 1),
        ("cert_smime.pem", EncryptionMethod::SMIME, 3),
        ("cert_smime.der", EncryptionMethod::SMIME, 1),
    ] {
        let (method, mut certs) = try_parse_certs(
            std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("crypto")
                    .join(name),
            )
            .unwrap(),
        )
        .expect(name);

        assert_eq!(method, expected_method);
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

async fn post(params: &AHashMap<String, Vec<u8>>) -> String {
    let mut form = reqwest::multipart::Form::new();
    for (key, value) in params {
        form = if key != "certificate" {
            form.text(
                key.to_string(),
                std::str::from_utf8(value).unwrap().to_string(),
            )
        } else {
            form.part(
                key.to_string(),
                reqwest::multipart::Part::bytes(value.to_vec())
                    .file_name("certificate")
                    .mime_str("application/octet-stream")
                    .unwrap(),
            )
        }
    }

    String::from_utf8(
        reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default()
            .post("https://127.0.0.1:8899/crypto")
            .multipart(form)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
