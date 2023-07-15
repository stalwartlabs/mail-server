/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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
