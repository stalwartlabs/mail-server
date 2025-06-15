/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod append;
pub mod authenticate;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod fetch;
pub mod list;
pub mod login;
pub mod lsub;
pub mod quota;
pub mod rename;
pub mod search;
pub mod select;
pub mod sort;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod thread;

use std::{borrow::Cow, str::FromStr};

use chrono::{DateTime, NaiveDate};

use crate::{
    Command,
    protocol::{Flag, Sequence},
    receiver::CommandParser,
};

pub type Result<T> = std::result::Result<T, Cow<'static, str>>;

impl CommandParser for Command {
    fn parse(value: &[u8], uid: bool) -> Option<Self> {
        hashify::tiny_map!(value,
            "CAPABILITY" => Command::Capability,
            "NOOP" => Command::Noop,
            "LOGOUT" => Command::Logout,
            "STARTTLS" => Command::StartTls,
            "AUTHENTICATE" => Command::Authenticate,
            "LOGIN" => Command::Login,
            "ENABLE" => Command::Enable,
            "SELECT" => Command::Select,
            "EXAMINE" => Command::Examine,
            "CREATE" => Command::Create,
            "DELETE" => Command::Delete,
            "RENAME" => Command::Rename,
            "SUBSCRIBE" => Command::Subscribe,
            "UNSUBSCRIBE" => Command::Unsubscribe,
            "LIST" => Command::List,
            "NAMESPACE" => Command::Namespace,
            "STATUS" => Command::Status,
            "APPEND" => Command::Append,
            "IDLE" => Command::Idle,
            "CLOSE" => Command::Close,
            "UNSELECT" => Command::Unselect,
            "EXPUNGE" => Command::Expunge(uid),
            "SEARCH" => Command::Search(uid),
            "FETCH" => Command::Fetch(uid),
            "STORE" => Command::Store(uid),
            "COPY" => Command::Copy(uid),
            "MOVE" => Command::Move(uid),
            "SORT" => Command::Sort(uid),
            "THREAD" => Command::Thread(uid),
            "LSUB" => Command::Lsub,
            "CHECK" => Command::Check,
            "SETACL" => Command::SetAcl,
            "DELETEACL" => Command::DeleteAcl,
            "GETACL" => Command::GetAcl,
            "LISTRIGHTS" => Command::ListRights,
            "MYRIGHTS" => Command::MyRights,
            "UNAUTHENTICATE" => Command::Unauthenticate,
            "ID" => Command::Id,
            "GETQUOTA" => Command::GetQuota,
            "GETQUOTAROOT" => Command::GetQuotaRoot,
        )
    }

    #[inline(always)]
    fn tokenize_brackets(&self) -> bool {
        matches!(self, Command::Fetch(_))
    }
}

impl Flag {
    pub fn parse_imap(value: Vec<u8>) -> Result<Self> {
        if !value.is_empty() {
            let flag = hashify::tiny_map_ignore_case!(value.as_slice(),
                "\\Seen" => Flag::Seen,
                "\\Answered" => Flag::Answered,
                "\\Flagged" => Flag::Flagged,
                "\\Deleted" => Flag::Deleted,
                "\\Draft" => Flag::Draft,
                "\\Recent" => Flag::Recent,
                "\\Important" => Flag::Important,
                "$Forwarded" => Flag::Forwarded,
                "$MDNSent" => Flag::MDNSent,
                "$Junk" => Flag::Junk,
                "$NotJunk" => Flag::NotJunk,
                "$Phishing" => Flag::Phishing,
                "$Important" => Flag::Important,
            );

            if let Some(flag) = flag {
                Ok(flag)
            } else {
                String::from_utf8(value)
                    .map_err(|_| Cow::from("Invalid UTF-8."))
                    .map(Flag::Keyword)
            }
        } else {
            Err(Cow::from("Null flags are not allowed."))
        }
    }

    pub fn parse_jmap(value: String) -> Self {
        if value.starts_with('$') {
            hashify::tiny_map_ignore_case!(value.as_bytes(),
                "$seen" => Flag::Seen,
                "$draft" => Flag::Draft,
                "$flagged" => Flag::Flagged,
                "$answered" => Flag::Answered,
                "$recent" => Flag::Recent,
                "$important" => Flag::Important,
                "$phishing" => Flag::Phishing,
                "$junk" => Flag::Junk,
                "$notjunk" => Flag::NotJunk,
                "$deleted" => Flag::Deleted,
                "$forwarded" => Flag::Forwarded,
                "$mdnsent" => Flag::MDNSent,
            )
            .unwrap_or_else(|| Flag::Keyword(value))
        } else {
            let mut keyword = String::with_capacity(value.len());
            for c in value.chars() {
                if c.is_ascii_alphanumeric() {
                    keyword.push(c);
                } else {
                    keyword.push('_');
                }
            }
            Flag::Keyword(keyword)
        }
    }
}

pub fn parse_datetime(value: &[u8]) -> Result<i64> {
    std::str::from_utf8(value)
        .map_err(|_| Cow::from("Expected date/time, found an invalid UTF-8 string."))
        .and_then(|datetime| {
            DateTime::parse_from_str(datetime.trim(), "%d-%b-%Y %H:%M:%S %z")
                .map_err(|_| Cow::from(format!("Failed to parse date/time '{}'.", datetime)))
                .map(|dt| dt.timestamp())
        })
}

pub fn parse_date(value: &[u8]) -> Result<i64> {
    std::str::from_utf8(value)
        .map_err(|_| Cow::from("Expected date, found an invalid UTF-8 string."))
        .and_then(|date| {
            NaiveDate::parse_from_str(date.trim(), "%d-%b-%Y")
                .map_err(|_| Cow::from(format!("Failed to parse date '{}'.", date)))
                .map(|dt| {
                    dt.and_hms_opt(0, 0, 0)
                        .unwrap_or_default()
                        .and_utc()
                        .timestamp()
                })
        })
}

pub fn parse_number<T: FromStr>(value: &[u8]) -> Result<T> {
    std::str::from_utf8(value)
        .map_err(|_| Cow::from("Expected a number, found an invalid UTF-8 string."))
        .and_then(|string| {
            string
                .parse::<T>()
                .map_err(|_| Cow::from(format!("Expected a number, found {:?}.", string)))
        })
}

pub fn parse_sequence_set(value: &[u8]) -> Result<Sequence> {
    let mut sequence_set = Vec::new();

    let mut range_start = None;
    let mut token_start = None;

    let mut is_wildcard = false;
    let mut is_range = false;
    let mut is_saved_search = false;

    for (mut pos, ch) in value.iter().enumerate() {
        let mut add_token = false;
        match ch {
            b',' => {
                add_token = true;
            }
            b':' => {
                if !is_range {
                    if let Some(from_pos) = token_start {
                        range_start =
                            parse_number::<u32>(value.get(from_pos..pos).ok_or_else(|| {
                                Cow::from(format!(
                                    "Invalid sequence set {:?}, parse error.",
                                    String::from_utf8_lossy(value)
                                ))
                            })?)?
                            .into();
                        token_start = None;
                    } else if is_wildcard {
                        is_wildcard = false;
                    } else {
                        return Err(Cow::from(format!(
                            "Invalid sequence set {:?}, number expected before ':'.",
                            String::from_utf8_lossy(value)
                        )));
                    }
                    is_range = true;
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, ':' appears multiple times.",
                        String::from_utf8_lossy(value)
                    )));
                }
            }
            b'*' => {
                if !is_wildcard {
                    if value.len() == 1 {
                        return Ok(Sequence::Range {
                            start: None,
                            end: None,
                        });
                    } else if token_start.is_none() {
                        is_wildcard = true;
                    } else {
                        return Err(Cow::from(format!(
                            "Invalid sequence set {:?}, invalid use of '*'.",
                            String::from_utf8_lossy(value)
                        )));
                    }
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, '*' appears multiple times.",
                        String::from_utf8_lossy(value)
                    )));
                }
            }
            b'$' => {
                if value.get(pos + 1).is_none_or(|&ch| ch == b',') {
                    is_saved_search = true;
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, unexpected token after '$'.",
                        String::from_utf8_lossy(value)
                    )));
                }
            }
            _ => {
                if ch.is_ascii_digit() {
                    if is_wildcard {
                        return Err(Cow::from(format!(
                            "Invalid sequence set {:?}, invalid use of '*'.",
                            String::from_utf8_lossy(value)
                        )));
                    }
                    if token_start.is_none() {
                        token_start = pos.into();
                    }
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, found invalid character '{}' at position {}.",
                        String::from_utf8_lossy(value),
                        ch,
                        pos
                    )));
                }
            }
        }

        if add_token || pos == value.len() - 1 {
            if is_range {
                sequence_set.push(Sequence::Range {
                    start: range_start,
                    end: if !is_wildcard {
                        if !add_token {
                            pos += 1;
                        }
                        parse_number::<u32>(
                            value
                                .get(
                                    token_start.ok_or_else(|| {
                                        Cow::from(format!(
                                            "Invalid sequence set {:?}, expected number.",
                                            String::from_utf8_lossy(value)
                                        ))
                                    })?..pos,
                                )
                                .ok_or_else(|| {
                                    Cow::from(format!(
                                        "Invalid sequence set {:?}, parse error.",
                                        String::from_utf8_lossy(value)
                                    ))
                                })?,
                        )?
                        .into()
                    } else {
                        is_wildcard = false;
                        None
                    },
                });
                is_range = false;
                range_start = None;
            } else {
                if !add_token {
                    pos += 1;
                }
                if is_wildcard {
                    sequence_set.push(Sequence::Range {
                        start: None,
                        end: None,
                    });
                    is_wildcard = false;
                } else if is_saved_search {
                    sequence_set.push(Sequence::SavedSearch);
                    is_saved_search = false;
                } else {
                    sequence_set.push(Sequence::Number {
                        value: parse_number(
                            value
                                .get(
                                    token_start.ok_or_else(|| {
                                        Cow::from(format!(
                                            "Invalid sequence set {:?}, expected number.",
                                            String::from_utf8_lossy(value)
                                        ))
                                    })?..pos,
                                )
                                .ok_or_else(|| {
                                    Cow::from(format!(
                                        "Invalid sequence set {:?}, parse error.",
                                        String::from_utf8_lossy(value)
                                    ))
                                })?,
                        )?,
                    });
                }
            }
            token_start = None;
        }
    }

    match sequence_set.len() {
        1 => Ok(sequence_set.pop().unwrap()),
        0 => Err(Cow::from("Invalid empty sequence set.")),
        _ => Ok(Sequence::List {
            items: sequence_set,
        }),
    }
}

pub trait PushUnique<T> {
    fn push_unique(&mut self, value: T);
}

impl<T: PartialEq> PushUnique<T> for Vec<T> {
    fn push_unique(&mut self, value: T) {
        if !self.contains(&value) {
            self.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::Sequence;

    #[test]
    fn parse_sequence_set() {
        for (sequence, expected_result) in [
            ("$", Sequence::SavedSearch),
            (
                "*",
                Sequence::Range {
                    start: None,
                    end: None,
                },
            ),
            (
                "1,3000:3021",
                Sequence::List {
                    items: vec![
                        Sequence::Number { value: 1 },
                        Sequence::Range {
                            start: 3000.into(),
                            end: 3021.into(),
                        },
                    ],
                },
            ),
            (
                "2,4:7,9,12:*",
                Sequence::List {
                    items: vec![
                        Sequence::Number { value: 2 },
                        Sequence::Range {
                            start: 4.into(),
                            end: 7.into(),
                        },
                        Sequence::Number { value: 9 },
                        Sequence::Range {
                            start: 12.into(),
                            end: None,
                        },
                    ],
                },
            ),
            (
                "*:4,5:7",
                Sequence::List {
                    items: vec![
                        Sequence::Range {
                            start: None,
                            end: 4.into(),
                        },
                        Sequence::Range {
                            start: 5.into(),
                            end: 7.into(),
                        },
                    ],
                },
            ),
            (
                "2,4,5",
                Sequence::List {
                    items: vec![
                        Sequence::Number { value: 2 },
                        Sequence::Number { value: 4 },
                        Sequence::Number { value: 5 },
                    ],
                },
            ),
        ] {
            assert_eq!(
                super::parse_sequence_set(sequence.as_bytes()).unwrap(),
                expected_result
            );
        }
    }
}
