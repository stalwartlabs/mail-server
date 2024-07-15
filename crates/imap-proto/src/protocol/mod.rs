/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, fmt::Display};

use ahash::AHashSet;
use chrono::{DateTime, Utc};
use jmap_proto::types::keyword::Keyword;

use crate::{Command, ResponseCode, ResponseType, StatusResponse};

pub mod acl;
pub mod append;
pub mod authenticate;
pub mod capability;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod expunge;
pub mod fetch;
pub mod list;
pub mod login;
pub mod namespace;
pub mod rename;
pub mod search;
pub mod select;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod thread;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    Rev1,
    Rev2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sequence {
    Number {
        value: u32,
    },
    Range {
        start: Option<u32>,
        end: Option<u32>,
    },
    SavedSearch,
    List {
        items: Vec<Sequence>,
    },
}

impl Sequence {
    pub fn number(value: u32) -> Sequence {
        Sequence::Number { value }
    }

    pub fn range(start: Option<u32>, end: Option<u32>) -> Sequence {
        Sequence::Range { start, end }
    }

    pub fn contains(&self, value: u32, max_value: u32) -> bool {
        match self {
            Sequence::Number { value: number } => *number == value,
            Sequence::Range { start, end } => match (start, end) {
                (Some(start), Some(end)) => {
                    value >= *start && value <= *end || value >= *end && value <= *start
                }
                (Some(range), None) | (None, Some(range)) => {
                    value >= *range && value <= max_value || value >= max_value && value <= *range
                }
                (None, None) => value == max_value,
            },
            Sequence::List { items } => {
                for item in items {
                    if item.contains(value, max_value) {
                        return true;
                    }
                }
                false
            }
            Sequence::SavedSearch => false,
        }
    }

    pub fn is_saved_search(&self) -> bool {
        match self {
            Sequence::SavedSearch => true,
            Sequence::List { items } => items.iter().any(|s| s.is_saved_search()),
            _ => false,
        }
    }

    pub fn expand(&self, max_value: u32) -> AHashSet<u32> {
        match self {
            Sequence::Number { value } => AHashSet::from_iter([*value]),
            Sequence::List { items } => {
                let mut result = AHashSet::with_capacity(items.len());
                for item in items {
                    match item {
                        Sequence::Number { value } => {
                            result.insert(*value);
                        }
                        Sequence::Range { start, end } => {
                            let start = start.unwrap_or(max_value);
                            let end = end.unwrap_or(max_value);
                            match start.cmp(&end) {
                                Ordering::Equal => {
                                    result.insert(start);
                                }
                                Ordering::Less => {
                                    result.extend(start..=end);
                                }
                                Ordering::Greater => {
                                    result.extend(end..=start);
                                }
                            }
                        }
                        _ => (),
                    }
                }
                result
            }
            Sequence::Range { start, end } => {
                let mut result = AHashSet::new();
                let start = start.unwrap_or(max_value);
                let end = end.unwrap_or(max_value);
                match start.cmp(&end) {
                    Ordering::Equal => {
                        result.insert(start);
                    }
                    Ordering::Less => {
                        result.extend(start..=end);
                    }
                    Ordering::Greater => {
                        result.extend(end..=start);
                    }
                }
                result
            }
            _ => AHashSet::new(),
        }
    }
}

pub trait ImapResponse {
    fn serialize(self) -> Vec<u8>;
}

pub fn quoted_string(buf: &mut Vec<u8>, text: &str) {
    buf.push(b'"');
    for &c in text.as_bytes() {
        if c == b'\\' || c == b'"' {
            buf.push(b'\\');
        }
        buf.push(c);
    }
    buf.push(b'"');
}

pub fn quoted_or_literal_string(buf: &mut Vec<u8>, text: &str) {
    if text
        .as_bytes()
        .iter()
        .any(|ch| [b'\\', b'"', b'\r', b'\n'].contains(ch))
    {
        literal_string(buf, text.as_bytes())
    } else {
        buf.push(b'"');
        buf.extend_from_slice(text.as_bytes());
        buf.push(b'"');
    }
}
pub fn quoted_or_literal_string_or_nil(buf: &mut Vec<u8>, text: Option<&str>) {
    if let Some(text) = text {
        quoted_or_literal_string(buf, text);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

pub fn quoted_string_or_nil(buf: &mut Vec<u8>, text: Option<&str>) {
    if let Some(text) = text {
        quoted_string(buf, text);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

pub fn literal_string(buf: &mut Vec<u8>, text: &[u8]) {
    buf.push(b'{');
    buf.extend_from_slice(text.len().to_string().as_bytes());
    buf.extend_from_slice(b"}\r\n");
    buf.extend_from_slice(text);
}

pub fn quoted_timestamp(buf: &mut Vec<u8>, timestamp: i64) {
    buf.push(b'"');
    buf.extend_from_slice(
        DateTime::<Utc>::from_timestamp(timestamp, 0)
            .unwrap_or_default()
            .format("%d-%b-%Y %H:%M:%S %z")
            .to_string()
            .as_bytes(),
    );
    buf.push(b'"');
}

pub fn quoted_rfc2822(buf: &mut Vec<u8>, timestamp: &mail_parser::DateTime) {
    buf.push(b'"');
    buf.extend_from_slice(timestamp.to_rfc822().as_bytes());
    buf.push(b'"');
}

pub fn quoted_rfc2822_or_nil(buf: &mut Vec<u8>, timestamp: &Option<mail_parser::DateTime>) {
    if let Some(timestamp) = timestamp {
        quoted_rfc2822(buf, timestamp);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    Seen,
    Draft,
    Flagged,
    Answered,
    Recent,
    Important,
    Phishing,
    Junk,
    NotJunk,
    Deleted,
    Forwarded,
    MDNSent,
    Keyword(String),
}

impl Flag {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            Flag::Seen => b"\\Seen",
            Flag::Draft => b"\\Draft",
            Flag::Flagged => b"\\Flagged",
            Flag::Answered => b"\\Answered",
            Flag::Recent => b"\\Recent",
            Flag::Important => b"\\Important",
            Flag::Phishing => b"$Phishing",
            Flag::Junk => b"$Junk",
            Flag::NotJunk => b"$NotJunk",
            Flag::Deleted => b"\\Deleted",
            Flag::Forwarded => b"$Forwarded",
            Flag::MDNSent => b"$MDNSent",
            Flag::Keyword(keyword) => keyword.as_bytes(),
        });
    }
}

impl From<Keyword> for Flag {
    fn from(value: Keyword) -> Self {
        match value {
            Keyword::Seen => Flag::Seen,
            Keyword::Draft => Flag::Draft,
            Keyword::Flagged => Flag::Flagged,
            Keyword::Answered => Flag::Answered,
            Keyword::Recent => Flag::Recent,
            Keyword::Important => Flag::Important,
            Keyword::Phishing => Flag::Phishing,
            Keyword::Junk => Flag::Junk,
            Keyword::NotJunk => Flag::NotJunk,
            Keyword::Deleted => Flag::Deleted,
            Keyword::Forwarded => Flag::Forwarded,
            Keyword::MdnSent => Flag::MDNSent,
            Keyword::Other(value) => Flag::Keyword(value),
        }
    }
}

impl From<Flag> for Keyword {
    fn from(value: Flag) -> Self {
        match value {
            Flag::Seen => Keyword::Seen,
            Flag::Draft => Keyword::Draft,
            Flag::Flagged => Keyword::Flagged,
            Flag::Answered => Keyword::Answered,
            Flag::Recent => Keyword::Recent,
            Flag::Important => Keyword::Important,
            Flag::Phishing => Keyword::Phishing,
            Flag::Junk => Keyword::Junk,
            Flag::NotJunk => Keyword::NotJunk,
            Flag::Deleted => Keyword::Deleted,
            Flag::Forwarded => Keyword::Forwarded,
            Flag::MDNSent => Keyword::MdnSent,
            Flag::Keyword(value) => Keyword::Other(value),
        }
    }
}

impl ResponseCode {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            ResponseCode::Alert => b"ALERT",
            ResponseCode::AlreadyExists => b"ALREADYEXISTS",
            ResponseCode::AppendUid { uid_validity, uids } => {
                buf.extend_from_slice(b"APPENDUID ");
                buf.extend_from_slice(uid_validity.to_string().as_bytes());
                buf.push(b' ');
                serialize_sequence(buf, uids);
                return;
            }
            ResponseCode::AuthenticationFailed => b"AUTHENTICATIONFAILED",
            ResponseCode::AuthorizationFailed => b"AUTHORIZATIONFAILED",
            ResponseCode::BadCharset => b"BADCHARSET",
            ResponseCode::Cannot => b"CANNOT",
            ResponseCode::Capability { capabilities } => {
                buf.extend_from_slice(b"CAPABILITY");
                for capability in capabilities {
                    buf.push(b' ');
                    capability.serialize(buf);
                }
                return;
            }
            ResponseCode::ClientBug => b"CLIENTBUG",
            ResponseCode::Closed => b"CLOSED",
            ResponseCode::ContactAdmin => b"CONTACTADMIN",
            ResponseCode::CopyUid {
                uid_validity,
                src_uids,
                dest_uids,
            } => {
                buf.extend_from_slice(b"COPYUID ");
                buf.extend_from_slice(uid_validity.to_string().as_bytes());
                buf.push(b' ');
                serialize_sequence(buf, src_uids);
                buf.push(b' ');
                serialize_sequence(buf, dest_uids);
                return;
            }
            ResponseCode::Corruption => b"CORRUPTION",
            ResponseCode::Expired => b"EXPIRED",
            ResponseCode::ExpungeIssued => b"EXPUNGEISSUED",
            ResponseCode::HasChildren => b"HASCHILDREN",
            ResponseCode::InUse => b"INUSE",
            ResponseCode::Limit => b"LIMIT",
            ResponseCode::NonExistent => b"NONEXISTENT",
            ResponseCode::NoPerm => b"NOPERM",
            ResponseCode::OverQuota => b"OVERQUOTA",
            ResponseCode::Parse => b"PARSE",
            ResponseCode::PermanentFlags => b"PERMANENTFLAGS",
            ResponseCode::PrivacyRequired => b"PRIVACYREQUIRED",
            ResponseCode::ReadOnly => b"READ-ONLY",
            ResponseCode::ReadWrite => b"READ-WRITE",
            ResponseCode::ServerBug => b"SERVERBUG",
            ResponseCode::TryCreate => b"TRYCREATE",
            ResponseCode::UidNext => b"UIDNEXT",
            ResponseCode::UidNotSticky => b"UIDNOTSTICKY",
            ResponseCode::UidValidity => b"UIDVALIDITY",
            ResponseCode::Unavailable => b"UNAVAILABLE",
            ResponseCode::UnknownCte => b"UNKNOWN-CTE",
            ResponseCode::Modified { ids } => {
                buf.extend_from_slice(b"MODIFIED ");
                serialize_sequence(buf, ids);
                return;
            }
            ResponseCode::MailboxId { mailbox_id } => {
                buf.extend_from_slice(b"MAILBOXID (");
                buf.extend_from_slice(mailbox_id.as_bytes());
                buf.push(b')');
                return;
            }
            ResponseCode::HighestModseq { modseq } => {
                buf.extend_from_slice(b"HIGHESTMODSEQ ");
                buf.extend_from_slice(modseq.to_string().as_bytes());
                return;
            }
            ResponseCode::UseAttr => b"USEATTR",
        });
    }

    pub fn as_str(&self) -> &'static str {
        // Only returns the name without arguments
        match self {
            ResponseCode::Alert => "ALERT",
            ResponseCode::AlreadyExists => "ALREADYEXISTS",
            ResponseCode::AppendUid { .. } => "APPENDUID",
            ResponseCode::AuthenticationFailed => "AUTHENTICATIONFAILED",
            ResponseCode::AuthorizationFailed => "AUTHORIZATIONFAILED",
            ResponseCode::BadCharset => "BADCHARSET",
            ResponseCode::Cannot => "CANNOT",
            ResponseCode::Capability { .. } => "CAPABILITY",
            ResponseCode::ClientBug => "CLIENTBUG",
            ResponseCode::Closed => "CLOSED",
            ResponseCode::ContactAdmin => "CONTACTADMIN",
            ResponseCode::CopyUid { .. } => "COPYUID",
            ResponseCode::Corruption => "CORRUPTION",
            ResponseCode::Expired => "EXPIRED",
            ResponseCode::ExpungeIssued => "EXPUNGEISSUED",
            ResponseCode::HasChildren => "HASCHILDREN",
            ResponseCode::InUse => "INUSE",
            ResponseCode::Limit => "LIMIT",
            ResponseCode::NonExistent => "NONEXISTENT",
            ResponseCode::NoPerm => "NOPERM",
            ResponseCode::OverQuota => "OVERQUOTA",
            ResponseCode::Parse => "PARSE",
            ResponseCode::PermanentFlags => "PERMANENTFLAGS",
            ResponseCode::PrivacyRequired => "PRIVACYREQUIRED",
            ResponseCode::ReadOnly => "READ-ONLY",
            ResponseCode::ReadWrite => "READ-WRITE",
            ResponseCode::ServerBug => "SERVERBUG",
            ResponseCode::TryCreate => "TRYCREATE",
            ResponseCode::UidNext => "UIDNEXT",
            ResponseCode::UidNotSticky => "UIDNOTSTICKY",
            ResponseCode::UidValidity => "UIDVALIDITY",
            ResponseCode::Unavailable => "UNAVAILABLE",
            ResponseCode::UnknownCte => "UNKNOWN-CTE",
            ResponseCode::Modified { .. } => "MODIFIED",
            ResponseCode::MailboxId { .. } => "MAILBOXID",
            ResponseCode::HighestModseq { .. } => "HIGHESTMODSEQ",
            ResponseCode::UseAttr => "USEATTR",
        }
    }
}

impl ResponseType {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseType::Ok => "OK",
            ResponseType::No => "NO",
            ResponseType::Bad => "BAD",
            ResponseType::PreAuth => "PREAUTH",
            ResponseType::Bye => "BYE",
        }
    }
}

impl From<ResponseCode> for trc::Value {
    fn from(value: ResponseCode) -> Self {
        trc::Value::Static(value.as_str())
    }
}

impl From<ResponseType> for trc::Value {
    fn from(value: ResponseType) -> Self {
        trc::Value::Static(value.as_str())
    }
}

impl StatusResponse {
    pub fn serialize(self, mut buf: Vec<u8>) -> Vec<u8> {
        if let Some(tag) = &self.tag {
            buf.extend_from_slice(tag.as_bytes());
        } else {
            buf.push(b'*');
        }
        buf.push(b' ');
        self.rtype.serialize(&mut buf);
        buf.push(b' ');
        if let Some(code) = &self.code {
            buf.push(b'[');
            code.serialize(&mut buf);
            buf.extend_from_slice(b"] ");
        }
        buf.extend_from_slice(self.message.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.serialize(Vec::with_capacity(16))
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        if let Some(tag) = self.value_as_str(trc::Key::Id) {
            buf.extend_from_slice(tag.as_bytes());
        } else {
            buf.push(b'*');
        }
        buf.push(b' ');
        buf.extend_from_slice(self.value_as_str(trc::Key::Type).unwrap_or("NO").as_bytes());
        buf.push(b' ');
        if let Some(code) = self.value_as_str(trc::Key::Code) {
            buf.push(b'[');
            buf.extend_from_slice(code.as_bytes());
            buf.extend_from_slice(b"] ");
        }
        buf.extend_from_slice(
            self.value_as_str(trc::Key::Details)
                .or_else(|| self.value_as_str(trc::Key::Reason))
                .unwrap_or("Internal server error")
                .as_bytes(),
        );
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

impl ProtocolVersion {
    #[inline(always)]
    pub fn is_rev2(&self) -> bool {
        matches!(self, ProtocolVersion::Rev2)
    }

    #[inline(always)]
    pub fn is_rev1(&self) -> bool {
        matches!(self, ProtocolVersion::Rev1)
    }
}

pub fn serialize_sequence(buf: &mut Vec<u8>, list: &[u32]) {
    let mut ids = list.iter().peekable();
    while let Some(&id) = ids.next() {
        buf.extend_from_slice(id.to_string().as_bytes());
        let mut range_id = id;
        loop {
            match ids.peek() {
                Some(&&next_id) if next_id == range_id + 1 => {
                    range_id += 1;
                    ids.next();
                }
                next => {
                    if range_id != id {
                        buf.push(b':');
                        buf.extend_from_slice(range_id.to_string().as_bytes());
                    }
                    if next.is_some() {
                        buf.push(b',');
                    }
                    break;
                }
            }
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Command::Capability => write!(f, "CAPABILITY"),
            Command::Noop => write!(f, "NOOP"),
            Command::Logout => write!(f, "LOGOUT"),
            Command::StartTls => write!(f, "STARTTLS"),
            Command::Authenticate => write!(f, "AUTHENTICATE"),
            Command::Login => write!(f, "LOGIN"),
            Command::Enable => write!(f, "ENABLE"),
            Command::Select => write!(f, "SELECT"),
            Command::Examine => write!(f, "EXAMINE"),
            Command::Create => write!(f, "CREATE"),
            Command::Delete => write!(f, "DELETE"),
            Command::Rename => write!(f, "RENAME"),
            Command::Subscribe => write!(f, "SUBSCRIBE"),
            Command::Unsubscribe => write!(f, "UNSUBSCRIBE"),
            Command::List => write!(f, "LIST"),
            Command::Namespace => write!(f, "NAMESPACE"),
            Command::Status => write!(f, "STATUS"),
            Command::Append => write!(f, "APPEND"),
            Command::Idle => write!(f, "IDLE"),
            Command::Close => write!(f, "CLOSE"),
            Command::Unselect => write!(f, "UNSELECT"),
            Command::Expunge(false) => write!(f, "EXPUNGE"),
            Command::Search(false) => write!(f, "SEARCH"),
            Command::Fetch(false) => write!(f, "FETCH"),
            Command::Store(false) => write!(f, "STORE"),
            Command::Copy(false) => write!(f, "COPY"),
            Command::Move(false) => write!(f, "MOVE"),
            Command::Sort(false) => write!(f, "SORT"),
            Command::Thread(false) => write!(f, "THREAD"),
            Command::Expunge(true) => write!(f, "UID EXPUNGE"),
            Command::Search(true) => write!(f, "UID SEARCH"),
            Command::Fetch(true) => write!(f, "UID FETCH"),
            Command::Store(true) => write!(f, "UID STORE"),
            Command::Copy(true) => write!(f, "UID COPY"),
            Command::Move(true) => write!(f, "UID MOVE"),
            Command::Sort(true) => write!(f, "UID SORT"),
            Command::Thread(true) => write!(f, "UID THREAD"),
            Command::Lsub => write!(f, "LSUB"),
            Command::Check => write!(f, "CHECK"),
            Command::SetAcl => write!(f, "SETACL"),
            Command::DeleteAcl => write!(f, "DELETEACL"),
            Command::GetAcl => write!(f, "GETACL"),
            Command::ListRights => write!(f, "LISTRIGHTS"),
            Command::MyRights => write!(f, "MYRIGHTS"),
            Command::Unauthenticate => write!(f, "UNAUTHENTICATE"),
            Command::Id => write!(f, "ID"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::parse_sequence_set;

    #[test]
    fn sequence_set_contains() {
        for (sequence, expected_result, max_value) in [
            ("1,5:10", vec![1, 5, 6, 7, 8, 9, 10], 10),
            ("2,4:7,9,12:*", vec![2, 4, 5, 6, 7, 9, 12, 13, 14, 15], 15),
            ("*:4,5:7", vec![4, 5, 6, 7], 7),
            ("2,4,5", vec![2, 4, 5], 5),
        ] {
            let sequence = parse_sequence_set(sequence.as_bytes()).unwrap();

            assert_eq!(
                (1..=15)
                    .filter(|num| sequence.contains(*num, max_value))
                    .collect::<Vec<_>>(),
                expected_result
            );
        }
    }
}
