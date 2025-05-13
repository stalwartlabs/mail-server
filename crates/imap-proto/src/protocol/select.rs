/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ResponseCode, StatusResponse};

use super::{list::ListItem, ImapResponse, Sequence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub mailbox_name: String,
    pub condstore: bool,
    pub qresync: Option<QResync>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QResync {
    pub uid_validity: u32,
    pub modseq: u64,
    pub known_uids: Option<Sequence>,
    pub seq_match: Option<(Sequence, Sequence)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighestModSeq(u64);

#[derive(Debug, Clone)]
pub struct Response {
    pub mailbox: ListItem,
    pub total_messages: usize,
    pub recent_messages: usize,
    pub unseen_seq: u32,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub is_rev2: bool,
    pub closed_previous: bool,
    pub highest_modseq: Option<HighestModSeq>,
    pub mailbox_id: String,
}

#[derive(Debug, Clone)]
pub struct Exists {
    pub total_messages: usize,
}

impl ImapResponse for Response {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        if self.closed_previous {
            buf = StatusResponse::ok("Closed previous mailbox")
                .with_code(ResponseCode::Closed)
                .serialize(buf);
        }
        buf.extend_from_slice(b"* ");
        buf.extend_from_slice(self.total_messages.to_string().as_bytes());
        if !self.is_rev2 && self.recent_messages > 0 {
            buf.extend_from_slice(
                b" EXISTS\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\Recent)\r\n",
            );
        } else {
            buf.extend_from_slice(
                b" EXISTS\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
            );
        }
        if self.is_rev2 {
            self.mailbox.serialize(&mut buf, self.is_rev2, false);
        } else {
            buf.extend_from_slice(b"* ");
            buf.extend_from_slice(self.recent_messages.to_string().as_bytes());
            buf.extend_from_slice(b" RECENT\r\n");
            if self.unseen_seq > 0 {
                buf.extend_from_slice(b"* OK [UNSEEN ");
                buf.extend_from_slice(self.unseen_seq.to_string().as_bytes());
                buf.extend_from_slice(b"] Unseen messages\r\n");
            }
        }
        buf.extend_from_slice(
            b"* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)] All allowed\r\n",
        );
        buf.extend_from_slice(b"* OK [UIDVALIDITY ");
        buf.extend_from_slice(self.uid_validity.to_string().as_bytes());
        buf.extend_from_slice(b"] UIDs valid\r\n* OK [UIDNEXT ");
        buf.extend_from_slice(self.uid_next.to_string().as_bytes());
        buf.extend_from_slice(b"] Next predicted UID\r\n");
        if let Some(highest_modseq) = self.highest_modseq {
            highest_modseq.serialize(&mut buf);
        }
        buf.extend_from_slice(b"* OK [MAILBOXID (");
        buf.extend_from_slice(self.mailbox_id.as_bytes());
        buf.extend_from_slice(b")] Unique Mailbox ID\r\n");
        buf
    }
}

impl HighestModSeq {
    pub fn new(modseq: u64) -> Self {
        Self(modseq)
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* OK [HIGHESTMODSEQ ");
        buf.extend_from_slice(self.0.to_string().as_bytes());
        buf.extend_from_slice(b"] Highest Modseq\r\n");
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        self.serialize(&mut buf);
        buf
    }
}

impl Exists {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* ");
        buf.extend_from_slice(self.total_messages.to_string().as_bytes());
        buf.extend_from_slice(b" EXISTS\r\n");
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(15);
        self.serialize(&mut buf);
        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{list::ListItem, ImapResponse};

    use super::HighestModSeq;

    #[test]
    fn serialize_select() {
        for (mut response, _tag, expected_v2, expected_v1) in [
            (
                super::Response {
                    mailbox: ListItem::new("INBOX"),
                    total_messages: 172,
                    recent_messages: 5,
                    unseen_seq: 3,
                    uid_validity: 3857529045,
                    uid_next: 4392,
                    closed_previous: false,
                    is_rev2: true,
                    highest_modseq: HighestModSeq::new(100).into(),
                    mailbox_id: "abc".into(),
                },
                "A142",
                concat!(
                    "* 172 EXISTS\r\n",
                    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
                    "* LIST () \"/\" \"INBOX\"\r\n",
                    "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)] All allowed\r\n",
                    "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n",
                    "* OK [UIDNEXT 4392] Next predicted UID\r\n",
                    "* OK [HIGHESTMODSEQ 100] Highest Modseq\r\n",
                    "* OK [MAILBOXID (abc)] Unique Mailbox ID\r\n"
                ),
                concat!(
                    "* 172 EXISTS\r\n",
                    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\Recent)\r\n",
                    "* 5 RECENT\r\n",
                    "* OK [UNSEEN 3] Unseen messages\r\n",
                    "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)] All allowed\r\n",
                    "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n",
                    "* OK [UIDNEXT 4392] Next predicted UID\r\n",
                    "* OK [HIGHESTMODSEQ 100] Highest Modseq\r\n",
                    "* OK [MAILBOXID (abc)] Unique Mailbox ID\r\n"
                ),
            ),
            (
                super::Response {
                    mailbox: ListItem::new("~peter/mail/台北/日本語"),
                    total_messages: 172,
                    recent_messages: 5,
                    unseen_seq: 3,
                    uid_validity: 3857529045,
                    uid_next: 4392,
                    closed_previous: true,
                    is_rev2: true,
                    highest_modseq: None,
                    mailbox_id: "abc".into(),
                },
                "A142",
                concat!(
                    "* OK [CLOSED] Closed previous mailbox\r\n",
                    "* 172 EXISTS\r\n",
                    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
                    "* LIST () \"/\" \"~peter/mail/台北/日本語\" (\"OLDNAME\" ",
                    "(\"~peter/mail/&U,BTFw-/&ZeVnLIqe-\"))\r\n",
                    "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)] All allowed\r\n",
                    "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n",
                    "* OK [UIDNEXT 4392] Next predicted UID\r\n",
                    "* OK [MAILBOXID (abc)] Unique Mailbox ID\r\n"
                ),
                concat!(
                    "* OK [CLOSED] Closed previous mailbox\r\n",
                    "* 172 EXISTS\r\n",
                    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\Recent)\r\n",
                    "* 5 RECENT\r\n",
                    "* OK [UNSEEN 3] Unseen messages\r\n",
                    "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)] All allowed\r\n",
                    "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n",
                    "* OK [UIDNEXT 4392] Next predicted UID\r\n",
                    "* OK [MAILBOXID (abc)] Unique Mailbox ID\r\n"
                ),
            ),
        ] {
            let response_v2 = String::from_utf8(response.clone().serialize()).unwrap();
            response.is_rev2 = false;
            let response_v1 = String::from_utf8(response.serialize()).unwrap();

            assert_eq!(response_v2, expected_v2);
            assert_eq!(response_v1, expected_v1);
        }
    }
}
