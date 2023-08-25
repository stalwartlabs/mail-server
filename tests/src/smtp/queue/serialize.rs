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

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use smtp_proto::{Response, MAIL_REQUIRETLS, MAIL_SMTPUTF8, RCPT_CONNEG, RCPT_NOTIFY_FAILURE};

use smtp::{
    core::SMTP,
    queue::{
        Domain, Error, ErrorDetails, HostResponse, Message, Recipient, Schedule, Status,
        RCPT_STATUS_CHANGED,
    },
};

use crate::smtp::{inbound::TestQueueEvent, TestConfig, TestSMTP};

#[tokio::test]
async fn queue_serialize() {
    let mut core = SMTP::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_queue_serialize_test");

    // Create test message
    let message = Message {
        size: 0,
        id: 0,
        path: PathBuf::new(),
        created: 123456,
        return_path: "sender@FooBar.org".to_string(),
        return_path_lcase: "sender@foobar.org".to_string(),
        return_path_domain: "foobar.org".to_string(),
        recipients: vec![
            Recipient {
                domain_idx: 0,
                address: "FOOBAR@example.org".to_string(),
                address_lcase: "foobar@example.org".to_string(),
                status: Status::Scheduled,
                flags: RCPT_CONNEG,
                orcpt: None,
            },
            Recipient {
                domain_idx: 1,
                address: "FOOBAR@example.org".to_string(),
                address_lcase: "foobar@example.org".to_string(),
                status: Status::Scheduled,
                flags: RCPT_NOTIFY_FAILURE,
                orcpt: None,
            },
        ],
        domains: vec![
            Domain {
                domain: "example.org".to_string(),
                retry: Schedule::now(),
                notify: Schedule::now(),
                expires: Instant::now() + Duration::from_secs(10),
                status: Status::Scheduled,
                disable_tls: false,
                changed: false,
            },
            Domain {
                domain: "example.com".to_string(),
                retry: Schedule::now(),
                notify: Schedule::now(),
                expires: Instant::now() + Duration::from_secs(10),
                status: Status::Scheduled,
                disable_tls: false,
                changed: false,
            },
        ],
        flags: MAIL_REQUIRETLS | MAIL_SMTPUTF8,
        env_id: "hello".to_string().into(),
        priority: -1,

        queue_refs: vec![],
    };

    // Queue message
    assert!(
        core.queue
            .queue_message(
                Box::new(message),
                (&b"From: test@foobar.org\r\n"[..]).into(),
                b"Subject: test\r\n\n\ntest",
                &tracing::info_span!("hi")
            )
            .await
    );
    let mut message = qr.read_event().await.unwrap_message();

    // Deserialize
    assert_msg_eq(
        &message,
        &Message::from_path(message.path.clone()).await.unwrap(),
    );

    // Write update
    message.recipients[0].status = Status::PermanentFailure(HostResponse {
        hostname: ErrorDetails {
            entity: "mx.example.org".to_string(),
            details: "RCPT TO:<foobar@example.org>".to_string(),
        },
        response: Response {
            code: 550,
            esc: [5, 1, 2],
            message: "User does not exist\nplease contact support for details\n".to_string(),
        },
    });
    message.recipients[0].flags |= RCPT_STATUS_CHANGED;

    message.recipients[1].status = Status::Completed(HostResponse {
        hostname: "smtp.foo.bar".to_string(),
        response: Response {
            code: 250,
            esc: [2, 1, 5],
            message: "Great success!".to_string(),
        },
    });
    message.recipients[1].flags |= RCPT_STATUS_CHANGED;

    message.domains[0].status = Status::TemporaryFailure(Error::UnexpectedResponse(HostResponse {
        hostname: ErrorDetails {
            entity: "mx2.example.org".to_string(),
            details: "DATA".to_string(),
        },
        response: Response {
            code: 450,
            esc: [4, 3, 1],
            message: "Can't accept mail at this moment".to_string(),
        },
    }));
    message.domains[0].changed = true;

    message.domains[1].status = Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
        entity: "mx.domain.org".to_string(),
        details: "Connection timeout".to_string(),
    }));
    message.domains[1].changed = true;
    message.domains[1].notify = Schedule::later(Duration::from_secs(30));
    message.domains[1].notify.inner = 321;
    message.domains[1].retry = Schedule::later(Duration::from_secs(62));
    message.domains[1].retry.inner = 678;

    // Save changes
    message.save_changes().await;
    assert!(message.serialize_changes().is_empty());
    assert_msg_eq(
        &message,
        &Message::from_path(message.path.clone()).await.unwrap(),
    );

    // Remove
    message.remove().await;
    assert!(!message.path.exists());
}

fn assert_msg_eq(msg: &Message, other: &Message) {
    assert_eq!(msg.id, other.id);
    assert_eq!(msg.created, other.created);
    assert_eq!(msg.path, other.path);
    assert_eq!(msg.return_path, other.return_path);
    assert_eq!(msg.return_path_lcase, other.return_path_lcase);
    assert_eq!(msg.return_path_domain, other.return_path_domain);
    assert_eq!(msg.recipients, other.recipients);
    assert_eq!(msg.domains.len(), other.domains.len());
    for (domain, other) in msg.domains.iter().zip(other.domains.iter()) {
        assert_eq!(domain.domain, other.domain);
        assert_eq!(domain.retry.inner, other.retry.inner);
        assert_eq!(domain.notify.inner, other.notify.inner);
        assert_eq!(domain.status, other.status);
        assert_instant_eq(domain.expires, other.expires);
        assert_instant_eq(domain.retry.due, other.retry.due);
        assert_instant_eq(domain.notify.due, other.notify.due);
    }
    assert_eq!(msg.flags, other.flags);
    assert_eq!(msg.env_id, other.env_id);
    assert_eq!(msg.priority, other.priority);
    assert_eq!(msg.size, other.size);
}

fn assert_instant_eq(instant: Instant, other: Instant) {
    let dur = if instant > other {
        instant - other
    } else {
        other - instant
    }
    .as_secs();
    assert!(dur <= 1, "dur {dur}");
}
