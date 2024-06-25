/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utf7::utf7_encode;

use super::quoted_string;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub mailbox_name: String,
    pub items: Vec<Status>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Messages,
    UidNext,
    UidValidity,
    Unseen,
    Deleted,
    Size,
    Recent,
    HighestModSeq,
    MailboxId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusItem {
    pub mailbox_name: String,
    pub items: Vec<(Status, StatusItemType)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusItemType {
    Number(u64),
    String(String),
}

impl StatusItem {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_rev2: bool) {
        buf.extend_from_slice(b"* STATUS ");
        if is_rev2 {
            quoted_string(buf, &self.mailbox_name);
        } else {
            quoted_string(buf, &utf7_encode(&self.mailbox_name));
        }
        buf.extend_from_slice(b" (");
        for (pos, (status_item, value)) in self.items.iter().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }

            buf.extend_from_slice(match status_item {
                Status::Messages => b"MESSAGES ",
                Status::UidNext => b"UIDNEXT ",
                Status::UidValidity => b"UIDVALIDITY ",
                Status::Unseen => b"UNSEEN ",
                Status::Deleted => b"DELETED ",
                Status::Size => b"SIZE ",
                Status::HighestModSeq => b"HIGHESTMODSEQ ",
                Status::MailboxId => b"MAILBOXID ",
                Status::Recent => b"RECENT ",
            });

            match value {
                StatusItemType::Number(num) => {
                    buf.extend_from_slice(num.to_string().as_bytes());
                }
                StatusItemType::String(str) => {
                    buf.push(b'(');
                    buf.extend_from_slice(str.as_bytes());
                    buf.push(b')');
                }
            }
        }
        buf.extend_from_slice(b")\r\n");
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::status::{Status, StatusItem, StatusItemType};

    #[test]
    fn serialize_status() {
        let mut buf = Vec::new();
        StatusItem {
            mailbox_name: "blurdybloop".to_string(),
            items: vec![
                (Status::Messages, StatusItemType::Number(231)),
                (Status::UidNext, StatusItemType::Number(44292)),
                (
                    Status::MailboxId,
                    StatusItemType::String("abc-123".to_string()),
                ),
            ],
        }
        .serialize(&mut buf, true);

        assert_eq!(
            String::from_utf8(buf).unwrap(),
            concat!(
                "* STATUS \"blurdybloop\" (MESSAGES 231 UIDNEXT 44292 MAILBOXID (abc-123))\r\n",
            )
        );
    }
}
