/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use smtp_proto::{Response, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS};
use tokio::{fs::File, io::AsyncReadExt};

use crate::smtp::{
    inbound::{sign::TextConfigContext, TestQueueEvent},
    ParseTestConfig, TestConfig, TestCore,
};
use smtp::{
    config::ConfigContext,
    core::Core,
    queue::{
        DeliveryAttempt, Domain, Error, ErrorDetails, HostResponse, Message, Recipient, Schedule,
        Status,
    },
};

#[tokio::test]
async fn generate_dsn() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dsn");
    path.push("original.txt");
    let size = fs::metadata(&path).unwrap().len() as usize;

    let flags = RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_SUCCESS;
    let message = Box::new(Message {
        size,
        id: 0,
        path,
        created: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        return_path: "sender@foobar.org".to_string(),
        return_path_lcase: "".to_string(),
        return_path_domain: "foobar.org".to_string(),
        recipients: vec![Recipient {
            domain_idx: 0,
            address: "foobar@example.org".to_string(),
            address_lcase: "foobar@example.org".to_string(),
            status: Status::PermanentFailure(HostResponse {
                hostname: ErrorDetails {
                    entity: "mx.example.org".to_string(),
                    details: "RCPT TO:<foobar@example.org>".to_string(),
                },
                response: Response {
                    code: 550,
                    esc: [5, 1, 2],
                    message: "User does not exist".to_string(),
                },
            }),
            flags: 0,
            orcpt: None,
        }],
        domains: vec![Domain {
            domain: "example.org".to_string(),
            retry: Schedule::now(),
            notify: Schedule::now(),
            expires: Instant::now() + Duration::from_secs(10),
            status: Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
                entity: "mx.domain.org".to_string(),
                details: "Connection timeout".to_string(),
            })),
            changed: false,
        }],
        flags: 0,
        env_id: None,
        priority: 0,

        queue_refs: vec![],
    });
    let mut attempt = DeliveryAttempt {
        span: tracing::span!(tracing::Level::INFO, "hi"),
        message,
        in_flight: vec![],
    };

    // Load config
    let mut core = Core::test();
    let ctx = ConfigContext::default().parse_signatures();
    let mut config = &mut core.queue.config.dsn;
    config.sign = "['rsa']"
        .parse_if::<Vec<String>>(&ctx)
        .map_if_block(&ctx.signers, "", "")
        .unwrap();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_dsn_test");

    // Disabled DSN
    core.queue.send_dsn(&mut attempt).await;
    qr.assert_empty_queue();

    // Failure DSN
    attempt.message.recipients[0].flags = flags;
    core.queue.send_dsn(&mut attempt).await;
    compare_dsn(qr.read_event().await.unwrap_message(), "failure.eml").await;

    // Success DSN
    attempt.message.recipients.push(Recipient {
        domain_idx: 0,
        address: "jane@example.org".to_string(),
        address_lcase: "jane@example.org".to_string(),
        status: Status::Completed(HostResponse {
            hostname: "mx2.example.org".to_string(),
            response: Response {
                code: 250,
                esc: [2, 1, 5],
                message: "Message accepted for delivery".to_string(),
            },
        }),
        flags,
        orcpt: None,
    });
    core.queue.send_dsn(&mut attempt).await;
    compare_dsn(qr.read_event().await.unwrap_message(), "success.eml").await;

    // Delay DSN
    attempt.message.recipients.push(Recipient {
        domain_idx: 0,
        address: "john.doe@example.org".to_string(),
        address_lcase: "john.doe@example.org".to_string(),
        status: Status::Scheduled,
        flags,
        orcpt: "jdoe@example.org".to_string().into(),
    });
    core.queue.send_dsn(&mut attempt).await;
    compare_dsn(qr.read_event().await.unwrap_message(), "delay.eml").await;

    // Mixed DSN
    for rcpt in &mut attempt.message.recipients {
        rcpt.flags = flags;
    }
    attempt.message.domains[0].notify.due = Instant::now();
    core.queue.send_dsn(&mut attempt).await;
    compare_dsn(qr.read_event().await.unwrap_message(), "mixed.eml").await;

    // Load queue
    let queue = core.queue.read_queue().await;
    assert_eq!(queue.scheduled.len(), 4);
}

async fn compare_dsn(message: Box<Message>, test: &str) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dsn");
    path.push(test);

    let mut bytes = vec![0u8; message.size];
    File::open(&message.path)
        .await
        .unwrap()
        .read_exact(&mut bytes)
        .await
        .unwrap();

    let dsn = remove_ids(bytes);
    let dsn_expected = fs::read_to_string(&path).unwrap();

    //fs::write(&path, dsn.as_bytes()).unwrap();
    assert_eq!(dsn, dsn_expected, "Failed for {}", path.display());
}

fn remove_ids(message: Vec<u8>) -> String {
    let old_message = String::from_utf8(message).unwrap();
    let mut message = String::with_capacity(old_message.len());
    let mut found_dkim = false;
    let mut skip = false;

    let mut boundary = "";
    for line in old_message.split("\r\n") {
        if skip {
            if line.chars().next().unwrap().is_ascii_whitespace() {
                continue;
            } else {
                skip = false;
            }
        }
        if line.starts_with("Date:") || line.starts_with("Message-ID:") {
            continue;
        } else if !found_dkim && line.starts_with("DKIM-Signature:") {
            found_dkim = true;
            skip = true;
            continue;
        } else if line.starts_with("--") {
            message.push_str(&line.replace(boundary, "mime_boundary"));
        } else if let Some((_, boundary_)) = line.split_once("boundary=\"") {
            boundary = boundary_.split_once('"').unwrap().0;
            message.push_str(&line.replace(boundary, "mime_boundary"));
        } else if line.starts_with("Arrival-Date:") {
            message.push_str("Arrival-Date: <date goes here>");
        } else if line.starts_with("Will-Retry-Until:") {
            message.push_str("Will-Retry-Until: <date goes here>");
        } else {
            message.push_str(line);
        }
        message.push_str("\r\n");
    }

    if !found_dkim {
        panic!("No DKIM signature found in: {old_message}");
    }

    message
}
