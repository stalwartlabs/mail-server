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

use super::{search::Filter, ImapResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub filter: Vec<Filter>,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    OrderedSubject,
    References,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub is_uid: bool,
    pub threads: Vec<Vec<u32>>,
}

impl ImapResponse for Response {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"* THREAD ");
        for thread in &self.threads {
            buf.push(b'(');
            for (pos, id) in thread.iter().enumerate() {
                if pos > 0 {
                    buf.push(b' ');
                }
                buf.extend_from_slice(id.to_string().as_bytes());
            }
            buf.push(b')');
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::ImapResponse;

    #[test]
    fn serialize_thread() {
        assert_eq!(
            String::from_utf8(
                super::Response {
                    is_uid: true,
                    threads: vec![vec![2, 10, 11], vec![49], vec![1, 3]],
                }
                .serialize()
            )
            .unwrap(),
            concat!("* THREAD (2 10 11)(49)(1 3)\r\n",)
        );
    }
}
