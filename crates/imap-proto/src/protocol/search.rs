/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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

use super::{quoted_string, serialize_sequence, Flag, Sequence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub is_esearch: bool,
    pub sort: Option<Vec<Comparator>>,
    pub result_options: Vec<ResultOption>,
    pub filter: Vec<Filter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sort {
    Arrival,
    Cc,
    Date,
    From,
    DisplayFrom,
    Size,
    Subject,
    To,
    DisplayTo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparator {
    pub sort: Sort,
    pub ascending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub is_uid: bool,
    pub is_esearch: bool,
    pub is_sort: bool,
    pub ids: Vec<u32>,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
    pub highest_modseq: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultOption {
    Min,
    Max,
    All,
    Count,
    Save,
    Context,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    Sequence(Sequence, bool),
    All,
    Answered,
    Bcc(String),
    Before(i64),
    Body(String),
    Cc(String),
    Deleted,
    Draft,
    Flagged,
    From(String),
    Header(String, String),
    Keyword(Flag),
    Larger(u32),
    On(i64),
    Seen,
    SentBefore(i64),
    SentOn(i64),
    SentSince(i64),
    Since(i64),
    Smaller(u32),
    Subject(String),
    Text(String),
    To(String),
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unkeyword(Flag),
    Unseen,

    // Logical operators
    And,
    Or,
    Not,
    End,

    // Imap4rev1
    Recent,
    New,
    Old,

    // RFC 5032 - WITHIN
    Older(u32),
    Younger(u32),

    // RFC 4551 - CONDSTORE
    ModSeq((u64, ModSeqEntry)),

    // RFC 8474 - ObjectID
    EmailId(String),
    ThreadId(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModSeqEntry {
    Shared(Flag),
    Private(Flag),
    All(Flag),
    None,
}

impl Filter {
    pub fn seq_saved_search() -> Filter {
        Filter::Sequence(Sequence::SavedSearch, false)
    }

    pub fn seq_range(start: Option<u32>, end: Option<u32>) -> Filter {
        Filter::Sequence(Sequence::Range { start, end }, false)
    }
}

impl Response {
    pub fn serialize(self, tag: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        if self.is_esearch {
            buf.extend_from_slice(b"* ESEARCH (TAG ");
            quoted_string(&mut buf, tag);
            buf.extend_from_slice(b")");
            if self.is_uid {
                buf.extend_from_slice(b" UID");
            }
            if let Some(count) = &self.count {
                buf.extend_from_slice(b" COUNT ");
                buf.extend_from_slice(count.to_string().as_bytes());
            }
            if let Some(min) = &self.min {
                buf.extend_from_slice(b" MIN ");
                buf.extend_from_slice(min.to_string().as_bytes());
            }
            if let Some(max) = &self.max {
                buf.extend_from_slice(b" MAX ");
                buf.extend_from_slice(max.to_string().as_bytes());
            }
            if !self.ids.is_empty() {
                buf.extend_from_slice(b" ALL ");
                serialize_sequence(&mut buf, &self.ids);
            }
            if let Some(highest_modseq) = self.highest_modseq {
                buf.extend_from_slice(b" MODSEQ ");
                buf.extend_from_slice(highest_modseq.to_string().as_bytes());
            }
        } else {
            if !self.is_sort {
                buf.extend_from_slice(b"* SEARCH");
            } else {
                buf.extend_from_slice(b"* SORT");
            }
            if !self.ids.is_empty() {
                for id in &self.ids {
                    buf.push(b' ');
                    buf.extend_from_slice(id.to_string().as_bytes());
                }
            }
            if let Some(highest_modseq) = self.highest_modseq {
                buf.extend_from_slice(b" (MODSEQ ");
                buf.extend_from_slice(highest_modseq.to_string().as_bytes());
                buf.push(b')');
            }
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn serialize_search() {
        for (mut response, tag, expected_v2, expected_v1) in [
            (
                super::Response {
                    is_uid: false,
                    is_esearch: true,
                    is_sort: false,
                    ids: vec![2, 10, 11],
                    min: 2.into(),
                    max: 11.into(),
                    count: 3.into(),
                    highest_modseq: None,
                },
                "A283",
                concat!("* ESEARCH (TAG \"A283\") COUNT 3 MIN 2 MAX 11 ALL 2,10:11\r\n",),
                concat!("* SEARCH 2 10 11\r\n"),
            ),
            (
                super::Response {
                    is_uid: false,
                    is_esearch: true,
                    is_sort: false,
                    ids: vec![
                        1, 2, 3, 5, 10, 11, 12, 13, 90, 92, 93, 94, 95, 96, 97, 98, 99,
                    ],
                    min: None,
                    max: None,
                    count: None,
                    highest_modseq: None,
                },
                "A283",
                concat!("* ESEARCH (TAG \"A283\") ALL 1:3,5,10:13,90,92:99\r\n",),
                concat!("* SEARCH 1 2 3 5 10 11 12 13 90 92 93 94 95 96 97 98 99\r\n",),
            ),
            (
                super::Response {
                    is_uid: false,
                    is_esearch: true,
                    is_sort: false,
                    ids: vec![],
                    min: None,
                    max: None,
                    count: None,
                    highest_modseq: None,
                },
                "A283",
                concat!("* ESEARCH (TAG \"A283\")\r\n",),
                concat!("* SEARCH\r\n"),
            ),
            (
                super::Response {
                    is_uid: false,
                    is_esearch: true,
                    is_sort: false,
                    ids: vec![10, 11, 12, 13, 21],
                    min: None,
                    max: None,
                    count: None,
                    highest_modseq: 12345.into(),
                },
                "A283",
                concat!("* ESEARCH (TAG \"A283\") ALL 10:13,21 MODSEQ 12345\r\n",),
                concat!("* SEARCH 10 11 12 13 21 (MODSEQ 12345)\r\n",),
            ),
        ] {
            let response_v2 = String::from_utf8(response.clone().serialize(tag)).unwrap();
            response.is_esearch = false;
            let response_v1 = String::from_utf8(response.serialize(tag)).unwrap();

            assert_eq!(response_v2, expected_v2);
            assert_eq!(response_v1, expected_v1);
        }
    }
}
