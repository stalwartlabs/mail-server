/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fs, io};

use imap_proto::ResponseType;

use crate::jmap::wait_for_index;

use super::{resources_dir, AssertResult, IMAPTest, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection, handle: &IMAPTest) {
    println!("Running APPEND tests...");

    // Invalid APPEND commands
    imap.send("APPEND \"Does not exist\" {1+}\r\na").await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("TRYCREATE");

    // Import test messages
    let mut entries = fs::read_dir(resources_dir())
        .unwrap()
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .unwrap();

    entries.sort();

    let mut expected_uid = 1;
    for file_name in entries.into_iter().take(20) {
        if file_name.extension().map_or(true, |e| e != "txt") {
            continue;
        }
        let raw_message = fs::read(&file_name).unwrap();

        imap.send(&format!(
            "APPEND INBOX (Flag_{}) {{{}}}",
            file_name
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .split_once('.')
                .unwrap()
                .0,
            raw_message.len()
        ))
        .await;
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        imap.send_untagged(std::str::from_utf8(&raw_message).unwrap())
            .await;
        let result = imap
            .assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_response_code();
        let mut code = result.split(' ');
        assert_eq!(code.next(), Some("APPENDUID"));
        assert_ne!(code.next(), Some("0"));
        assert_eq!(code.next(), Some(expected_uid.to_string().as_str()));
        expected_uid += 1;
    }

    wait_for_index(&handle.jmap).await;
}

pub async fn assert_append_message(
    imap: &mut ImapConnection,
    folder: &str,
    message: &str,
    expected_response: ResponseType,
) -> Vec<String> {
    imap.send(&format!("APPEND \"{}\" {{{}}}", folder, message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, expected_response).await
}

fn build_message(message: usize, in_reply_to: Option<usize>, thread_num: usize) -> String {
    if let Some(in_reply_to) = in_reply_to {
        format!(
            "Message-ID: <{}@domain>\nReferences: <{}@domain>\nSubject: re: T{}\n\nreply\n",
            message, in_reply_to, thread_num
        )
    } else {
        format!(
            "Message-ID: <{}@domain>\nSubject: T{}\n\nmsg\n",
            message, thread_num
        )
    }
}

pub fn build_messages() -> Vec<String> {
    let mut messages = Vec::new();
    for parent in 0..3 {
        messages.push(build_message(parent, None, parent));
        for child in 0..3 {
            messages.push(build_message(
                ((parent + 1) * 10) + child,
                parent.into(),
                parent,
            ));
        }
    }
    messages
}
