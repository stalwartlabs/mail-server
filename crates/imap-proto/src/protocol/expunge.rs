/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{serialize_sequence, ImapResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub is_qresync: bool,
    pub ids: Vec<u32>,
}

impl ImapResponse for Response {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        self.serialize_to(&mut buf);
        buf
    }
}

impl Response {
    pub fn serialize_to(self, buf: &mut Vec<u8>) {
        if !self.is_qresync {
            for (num_deletions, id) in self.ids.into_iter().enumerate() {
                buf.extend_from_slice(b"* ");
                buf.extend_from_slice(
                    id.saturating_sub(num_deletions as u32)
                        .to_string()
                        .as_bytes(),
                );
                buf.extend_from_slice(b" EXPUNGE\r\n");
            }
        } else {
            Vanished {
                earlier: false,
                ids: self.ids,
            }
            .serialize(buf);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vanished {
    pub earlier: bool,
    pub ids: Vec<u32>,
}

impl Vanished {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        if self.earlier {
            buf.extend_from_slice(b"* VANISHED (EARLIER) ");
        } else {
            buf.extend_from_slice(b"* VANISHED ");
        }
        serialize_sequence(buf, &self.ids);
        buf.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::ImapResponse;

    #[test]
    fn serialize_expunge() {
        assert_eq!(
            String::from_utf8(
                super::Response {
                    is_qresync: false,
                    ids: vec![3, 4, 5]
                }
                .serialize()
            )
            .unwrap(),
            concat!("* 3 EXPUNGE\r\n", "* 3 EXPUNGE\r\n", "* 3 EXPUNGE\r\n",)
        );

        assert_eq!(
            String::from_utf8(
                super::Response {
                    is_qresync: false,
                    ids: vec![3, 4, 7, 9, 11]
                }
                .serialize()
            )
            .unwrap(),
            concat!(
                "* 3 EXPUNGE\r\n",
                "* 3 EXPUNGE\r\n",
                "* 5 EXPUNGE\r\n",
                "* 6 EXPUNGE\r\n",
                "* 7 EXPUNGE\r\n",
            )
        );

        assert_eq!(
            String::from_utf8(
                super::Response {
                    is_qresync: true,
                    ids: vec![3, 4, 5]
                }
                .serialize()
            )
            .unwrap(),
            concat!("* VANISHED 3:5\r\n")
        );
    }
}
