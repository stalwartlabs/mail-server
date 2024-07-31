/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use directory::backend::internal::manage::ManageDirectory;
use jmap::mailbox::{INBOX_ID, JUNK_ID};
use jmap_proto::types::{collection::Collection, id::Id, property::Property};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running message delivery tests...");

    // Create a domain name and a test account
    let server = params.server.clone();
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    params
        .directory
        .create_test_user_with_email("jane@example.com", "abcdef", "Jane Smith")
        .await;
    params
        .directory
        .create_test_user_with_email("bill@example.com", "098765", "Bill Foobar")
        .await;
    let account_id_1 = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jdoe@example.com")
            .await
            .unwrap(),
    )
    .to_string();
    let account_id_2 = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jane@example.com")
            .await
            .unwrap(),
    )
    .to_string();
    let account_id_3 = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("bill@example.com")
            .await
            .unwrap(),
    )
    .to_string();
    params
        .directory
        .link_test_address("jdoe@example.com", "john.doe@example.com", "alias")
        .await;

    // Create a mailing list
    params
        .directory
        .link_test_address("jdoe@example.com", "members@example.com", "list")
        .await;
    params
        .directory
        .link_test_address("jane@example.com", "members@example.com", "list")
        .await;
    params
        .directory
        .link_test_address("bill@example.com", "members@example.com", "list")
        .await;

    // Delivering to individuals
    let mut lmtp = SmtpConnection::connect().await;
    params.webhook.clear();

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

    let john_id = Id::from_bytes(account_id_1.as_bytes())
        .unwrap()
        .document_id();
    assert_eq!(
        server
            .get_document_ids(john_id, Collection::Email)
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server
            .get_tag(john_id, Collection::Email, Property::MailboxIds, INBOX_ID)
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server
            .get_tag(john_id, Collection::Email, Property::MailboxIds, JUNK_ID)
            .await
            .unwrap()
            .map_or(0, |bm| bm.len()),
        0
    );

    // Delivering to individuals' aliases
    lmtp.ingest(
        "bill@example.com",
        &["john.doe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: john.doe@example.com\r\n",
            "Subject: Fwd: TPS Report\r\n",
            "X-Spam-Status: Yes, score=13.9\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    assert_eq!(
        server
            .get_document_ids(john_id, Collection::Email)
            .await
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        server
            .get_tag(john_id, Collection::Email, Property::MailboxIds, INBOX_ID)
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server
            .get_tag(john_id, Collection::Email, Property::MailboxIds, JUNK_ID)
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );

    // EXPN and VRFY
    lmtp.expn("members@example.com", 2)
        .await
        .assert_contains("jdoe@example.com")
        .assert_contains("jane@example.com")
        .assert_contains("bill@example.com");
    lmtp.expn("non_existant@example.com", 5).await;
    lmtp.expn("jdoe@example.com", 5).await;
    lmtp.vrfy("jdoe@example.com", 2).await;
    lmtp.vrfy("members@example.com", 5).await;
    lmtp.vrfy("non_existant@example.com", 5).await;

    // Delivering to a mailing list
    lmtp.ingest(
        "bill@example.com",
        &["members@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: members@example.com\r\n",
            "Subject: WFH policy\r\n",
            "\r\n",
            "We need the entire staff back in the office, ",
            "TPS reports cannot be filed properly from home."
        ),
    )
    .await;

    for (account_id, num_messages) in [(&account_id_1, 3), (&account_id_2, 1), (&account_id_3, 1)] {
        assert_eq!(
            server
                .get_document_ids(
                    Id::from_bytes(account_id.as_bytes()).unwrap().document_id(),
                    Collection::Email
                )
                .await
                .unwrap()
                .unwrap()
                .len(),
            num_messages,
            "for {}",
            account_id
        );
    }

    // Removing members from the mailing list and chunked ingest
    params
        .directory
        .remove_test_alias("jdoe@example.com", "members@example.com")
        .await;
    lmtp.ingest_chunked(
        "bill@example.com",
        &["members@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: members@example.com\r\n",
            "Subject: WFH policy (reminder)\r\n",
            "\r\n",
            "This is a reminder that we need the entire staff back in the office, ",
            "TPS reports cannot be filed properly from home."
        ),
        10,
    )
    .await;

    for (account_id, num_messages) in [(&account_id_1, 3), (&account_id_2, 2), (&account_id_3, 2)] {
        assert_eq!(
            server
                .get_document_ids(
                    Id::from_bytes(account_id.as_bytes()).unwrap().document_id(),
                    Collection::Email
                )
                .await
                .unwrap()
                .unwrap()
                .len(),
            num_messages,
            "for {}",
            account_id
        );
    }

    // Deduplication of recipients
    lmtp.ingest(
        "bill@example.com",
        &[
            "members@example.com",
            "jdoe@example.com",
            "john.doe@example.com",
            "jane@example.com",
            "bill@example.com",
        ],
        concat!(
            "From: bill@example.com\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your TPS reports before ",
            "going on holidays."
        ),
    )
    .await;

    for (account_id, num_messages) in [(&account_id_1, 4), (&account_id_2, 3), (&account_id_3, 3)] {
        assert_eq!(
            server
                .get_document_ids(
                    Id::from_bytes(account_id.as_bytes()).unwrap().document_id(),
                    Collection::Email
                )
                .await
                .unwrap()
                .unwrap()
                .len(),
            num_messages,
            "for {}",
            account_id
        );
    }

    // Remove test data
    for account_id in [&account_id_1, &account_id_2, &account_id_3] {
        params.client.set_default_account_id(account_id);
        destroy_all_mailboxes(params).await;
    }
    assert_is_empty(server).await;

    // Check webhook events
    params.webhook.assert_contains(&[
        "store.ingest",
        "delivery.dsn",
        "\"from\": \"bill@example.com\"",
        "\"to\": \"john.doe@example.com\"",
    ]);
}

pub struct SmtpConnection {
    reader: Lines<BufReader<ReadHalf<TcpStream>>>,
    writer: WriteHalf<TcpStream>,
}

impl SmtpConnection {
    pub async fn ingest_with_code(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &str,
        code: u8,
    ) -> Vec<String> {
        self.mail_from(from, 2).await;
        for recipient in recipients {
            self.rcpt_to(recipient, 2).await;
        }
        self.data(3).await;
        let result = self.data_bytes(message, recipients.len(), code).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        result
    }

    pub async fn ingest(&mut self, from: &str, recipients: &[&str], message: &str) {
        self.ingest_with_code(from, recipients, message, 2).await;
    }

    async fn ingest_chunked(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &str,
        chunk_size: usize,
    ) {
        self.mail_from(from, 2).await;
        for recipient in recipients {
            self.rcpt_to(recipient, 2).await;
        }
        for chunk in message.as_bytes().chunks(chunk_size) {
            self.bdat(std::str::from_utf8(chunk).unwrap(), 2).await;
        }
        self.bdat_last("", recipients.len(), 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    pub async fn connect() -> Self {
        SmtpConnection::connect_port(11200).await
    }

    pub async fn connect_port(port: u16) -> Self {
        let (reader, writer) = tokio::io::split(
            TcpStream::connect(&format!("127.0.0.1:{port}"))
                .await
                .unwrap(),
        );
        let mut conn = SmtpConnection {
            reader: BufReader::new(reader).lines(),
            writer,
        };
        conn.read(1, 2).await;
        conn.lhlo().await;
        conn
    }

    pub async fn lhlo(&mut self) -> Vec<String> {
        self.send("LHLO localhost").await;
        self.read(1, 2).await
    }

    pub async fn mail_from(&mut self, sender: &str, code: u8) -> Vec<String> {
        self.send(&format!("MAIL FROM:<{}>", sender)).await;
        self.read(1, code).await
    }

    pub async fn rcpt_to(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("RCPT TO:<{}>", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn vrfy(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("VRFY {}", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn expn(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("EXPN {}", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn data(&mut self, code: u8) -> Vec<String> {
        self.send("DATA").await;
        self.read(1, code).await
    }

    pub async fn data_bytes(
        &mut self,
        message: &str,
        num_responses: usize,
        code: u8,
    ) -> Vec<String> {
        self.send_raw(message).await;
        self.send_raw("\r\n.\r\n").await;
        self.read(num_responses, code).await
    }

    pub async fn bdat(&mut self, chunk: &str, code: u8) -> Vec<String> {
        self.send_raw(&format!("BDAT {}\r\n{}", chunk.len(), chunk))
            .await;
        self.read(1, code).await
    }

    pub async fn bdat_last(&mut self, chunk: &str, num_responses: usize, code: u8) -> Vec<String> {
        self.send_raw(&format!("BDAT {} LAST\r\n{}", chunk.len(), chunk))
            .await;
        self.read(num_responses, code).await
    }

    pub async fn rset(&mut self) -> Vec<String> {
        self.send("RSET").await;
        self.read(1, 2).await
    }

    pub async fn noop(&mut self) -> Vec<String> {
        self.send("NOOP").await;
        self.read(1, 2).await
    }

    pub async fn quit(&mut self) -> Vec<String> {
        self.send("QUIT").await;
        self.read(1, 2).await
    }

    pub async fn read(&mut self, mut num_responses: usize, code: u8) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = line.as_bytes()[3] == b' ';
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        num_responses -= 1;
                        if num_responses != 0 {
                            continue;
                        }

                        if code != u8::MAX {
                            for line in &lines {
                                if line.as_bytes()[0] - b'0' != code {
                                    panic!("Expected completion code {}, got {:?}.", code, lines);
                                }
                            }
                        }
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}

pub trait AssertResult: Sized {
    fn assert_contains(self, text: &str) -> Self;
    fn assert_count(self, text: &str, occurrences: usize) -> Self;
    fn assert_equals(self, text: &str) -> Self;
}

impl AssertResult for Vec<String> {
    fn assert_contains(self, text: &str) -> Self {
        for line in &self {
            if line.contains(text) {
                return self;
            }
        }
        panic!("Expected response to contain {:?}, got {:?}", text, self);
    }

    fn assert_count(self, text: &str, occurrences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurrences,
            "Expected {} occurrences of {:?}, found {}.",
            occurrences,
            text,
            self.iter().filter(|l| l.contains(text)).count()
        );
        self
    }

    fn assert_equals(self, text: &str) -> Self {
        for line in &self {
            if line == text {
                return self;
            }
        }
        panic!("Expected response to be {:?}, got {:?}", text, self);
    }
}
