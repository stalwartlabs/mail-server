use std::{sync::Arc, time::Duration};

use jmap::JMAP;
use jmap_client::client::Client;
use jmap_proto::types::{collection::Collection, id::Id};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};

use crate::jmap::{
    mailbox::destroy_all_mailboxes, test_account_create, test_alias_create, test_alias_remove,
};

pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running message delivery tests...");

    // Create a domain name and a test account
    let account_id_1 = test_account_create(&server, "jdoe@example.com", "12345", "John Doe")
        .await
        .to_string();
    let account_id_2 = test_account_create(&server, "jane@example.com", "abcdef", "Jane Smith")
        .await
        .to_string();
    let account_id_3 = test_account_create(&server, "bill@example.com", "12345", "Bill Foobar")
        .await
        .to_string();
    test_alias_create(&server, "jdoe@example.com", "john.doe@example.com").await;

    // Create a mailing list
    test_alias_create(&server, "jdoe@example.com", "members@example.com").await;
    test_alias_create(&server, "jane@example.com", "members@example.com").await;
    test_alias_create(&server, "bill@example.com", "members@example.com").await;

    // Delivering to individuals
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    assert_eq!(
        server
            .get_document_ids(
                Id::from_bytes(account_id_1.as_bytes())
                    .unwrap()
                    .document_id(),
                Collection::Email
            )
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );

    // Delivering to individuals' aliases
    lmtp.ingest(
        "bill@example.com",
        &["john.doe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: john.doe@example.com\r\n",
            "Subject: Fwd: TPS Report\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    assert_eq!(
        server
            .get_document_ids(
                Id::from_bytes(account_id_1.as_bytes())
                    .unwrap()
                    .document_id(),
                Collection::Email
            )
            .await
            .unwrap()
            .unwrap()
            .len(),
        2
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
    lmtp.vrfy("members@example.com", 2).await;
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
    test_alias_remove(&server, "jdoe@example.com", "members@example.com").await;
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

    // Size checks
    lmtp.send("MAIL FROM:<hello@world> SIZE=943718400").await;
    lmtp.read(1, 5).await;
    lmtp.send("BDAT 943718400").await;
    lmtp.read(1, 5).await;

    // Remove test data
    for account_id in [&account_id_1, &account_id_2, &account_id_3] {
        client.set_default_account_id(account_id);
        destroy_all_mailboxes(client).await;
    }
    server.store.assert_is_empty().await;
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
        self.data_bytes(message, recipients.len(), code).await
    }

    pub async fn ingest(&mut self, from: &str, recipients: &[&str], message: &str) {
        self.ingest_with_code(from, recipients, message, 2).await;
    }

    pub async fn ingest_chunked(
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
    }

    pub async fn connect() -> Self {
        let (reader, writer) =
            tokio::io::split(TcpStream::connect("127.0.0.1:11200").await.unwrap());
        let mut conn = SmtpConnection {
            reader: BufReader::new(reader).lines(),
            writer,
        };
        conn.read(1, 2).await;
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
                    println!("<- {:?}", line);
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
        println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}

pub trait AssertResult: Sized {
    fn assert_contains(self, text: &str) -> Self;
    fn assert_count(self, text: &str, occurences: usize) -> Self;
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

    fn assert_count(self, text: &str, occurences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurences,
            "Expected {} occurrences of {:?}, found {}.",
            occurences,
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
