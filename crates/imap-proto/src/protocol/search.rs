/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::fts::{FilterItem, FilterType};

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
    pub highest_modseq: Option<u64>,
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

impl FilterItem for Filter {
    fn filter_type(&self) -> FilterType {
        match self {
            Filter::From(_)
            | Filter::To(_)
            | Filter::Cc(_)
            | Filter::Bcc(_)
            | Filter::Subject(_)
            | Filter::Body(_)
            | Filter::Text(_)
            | Filter::Header(_, _) => FilterType::Fts,
            Filter::And => FilterType::And,
            Filter::Or => FilterType::Or,
            Filter::Not => FilterType::Not,
            Filter::End => FilterType::End,
            _ => FilterType::Store,
        }
    }
}

impl From<FilterType> for Filter {
    fn from(value: FilterType) -> Self {
        match value {
            FilterType::And => Filter::And,
            FilterType::Or => Filter::Or,
            FilterType::Not => Filter::Not,
            FilterType::End => Filter::End,
            _ => unreachable!(),
        }
    }
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
