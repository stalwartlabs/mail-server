/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use mail_auth::hickory_resolver::proto::op::ResponseCode;

use smtp::queue::{Domain, Message, Schedule, Status};
use store::write::now;

use crate::smtp::outbound::TestServer;

const CONFIG: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true
"#;

#[tokio::test]
async fn queue_due() {
    let local = TestServer::new("smtp_queue_due_test", CONFIG, true).await;
    let core = local.build_smtp();
    let qr = &local.qr;

    let mut message = new_message(0);
    message.domains.push(domain("c", 3, 8, 9));
    let due = message.next_delivery_event();
    message.save_changes(&core, 0.into(), due.into()).await;

    let mut message = new_message(1);
    message.domains.push(domain("b", 2, 6, 7));
    let due = message.next_delivery_event();
    message.save_changes(&core, 0.into(), due.into()).await;

    let mut message = new_message(2);
    message.domains.push(domain("a", 1, 4, 5));
    let due = message.next_delivery_event();
    message.save_changes(&core, 0.into(), due.into()).await;

    for domain in vec!["a", "b", "c"].into_iter() {
        let now = now();
        for queue_event in core.next_event().await {
            if queue_event.due > now {
                let wake_up = queue_event.due - now;
                assert_eq!(wake_up, 1);
                std::thread::sleep(Duration::from_secs(wake_up));
            }
            if let Some(message) = core.read_message(queue_event.queue_id).await {
                message.domain(domain);
                message.remove(&core, queue_event.due).await;
            } else {
                panic!("Message not found");
            }
        }
    }

    qr.assert_queue_is_empty().await;
}

#[test]
fn delivery_events() {
    let mut message = new_message(0);

    message.domains.push(domain("a", 1, 2, 3));
    message.domains.push(domain("b", 4, 5, 6));
    message.domains.push(domain("c", 7, 8, 9));

    for t in 0..2 {
        assert_eq!(message.next_event().unwrap(), message.domain("a").retry.due);
        assert_eq!(message.next_delivery_event(), message.domain("a").retry.due);
        assert_eq!(
            message
                .next_event_after(message.domain("a").expires)
                .unwrap(),
            message.domain("b").retry.due
        );
        assert_eq!(
            message
                .next_event_after(message.domain("b").expires)
                .unwrap(),
            message.domain("c").retry.due
        );
        assert_eq!(
            message
                .next_event_after(message.domain("c").notify.due)
                .unwrap(),
            message.domain("c").expires
        );
        assert!(message
            .next_event_after(message.domain("c").expires)
            .is_none());

        if t == 0 {
            message.domains.reverse();
        } else {
            message.domains.swap(0, 1);
        }
    }

    message.domain_mut("a").set_status(
        mail_auth::Error::DnsRecordNotFound(ResponseCode::BADCOOKIE),
        &[],
    );
    assert_eq!(message.next_event().unwrap(), message.domain("b").retry.due);
    assert_eq!(message.next_delivery_event(), message.domain("b").retry.due);

    message.domain_mut("b").set_status(
        mail_auth::Error::DnsRecordNotFound(ResponseCode::BADCOOKIE),
        &[],
    );
    assert_eq!(message.next_event().unwrap(), message.domain("c").retry.due);
    assert_eq!(message.next_delivery_event(), message.domain("c").retry.due);

    message.domain_mut("c").set_status(
        mail_auth::Error::DnsRecordNotFound(ResponseCode::BADCOOKIE),
        &[],
    );
    assert!(message.next_event().is_none());
}

pub fn new_message(id: u64) -> Message {
    Message {
        size: 0,
        id,
        created: 0,
        return_path: "sender@foobar.org".to_string(),
        return_path_lcase: "".to_string(),
        return_path_domain: "foobar.org".to_string(),
        recipients: vec![],
        domains: vec![],
        flags: 0,
        env_id: None,
        priority: 0,
        quota_keys: vec![],
        blob_hash: Default::default(),
    }
}

fn domain(domain: &str, retry: u64, notify: u64, expires: u64) -> Domain {
    Domain {
        domain: domain.to_string(),
        retry: Schedule::later(Duration::from_secs(retry)),
        notify: Schedule::later(Duration::from_secs(notify)),
        expires: now() + expires,
        status: Status::Scheduled,
    }
}

pub trait TestMessage {
    fn domain(&self, name: &str) -> &Domain;
    fn domain_mut(&mut self, name: &str) -> &mut Domain;
}

impl TestMessage for Message {
    fn domain(&self, name: &str) -> &Domain {
        self.domains
            .iter()
            .find(|d| d.domain == name)
            .unwrap_or_else(|| panic!("Expected domain {name} not found in {:?}", self.domains))
    }

    fn domain_mut(&mut self, name: &str) -> &mut Domain {
        self.domains.iter_mut().find(|d| d.domain == name).unwrap()
    }
}
