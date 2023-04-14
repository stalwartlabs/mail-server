use std::fmt::Display;

use crate::parser::{json::Parser, JsonObjectParser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodName {
    pub obj: MethodObject,
    pub fnc: MethodFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodObject {
    Email,
    Mailbox,
    Core,
    Blob,
    PushSubscription,
    Thread,
    SearchSnippet,
    Identity,
    EmailSubmission,
    VacationResponse,
    SieveScript,
    Principal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodFunction {
    Get,
    Set,
    Changes,
    Query,
    QueryChanges,
    Copy,
    Import,
    Parse,
    Validate,
    Echo,
}

impl JsonObjectParser for MethodName {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut shift = 0;
        let mut obj_hash: u128 = 0;
        let mut fnc_hash: u128 = 0;

        loop {
            let ch = parser
                .next_unescaped()?
                .ok_or_else(|| parser.error_value())?;
            if ch != b'/' {
                if shift < 128 {
                    obj_hash |= (ch as u128) << shift;
                    shift += 8;
                } else {
                    return Err(parser.error_value());
                }
            } else {
                break;
            }
        }

        shift = 0;
        while let Some(ch) = parser.next_unescaped()? {
            if shift < 128 {
                fnc_hash |= (ch as u128) << shift;
                shift += 8;
            } else {
                return Err(parser.error_value());
            }
        }

        Ok(MethodName {
            obj: match obj_hash {
                0x6c69_616d_45 => MethodObject::Email,
                0x786f_626c_6961_4d => MethodObject::Mailbox,
                0x6461_6572_6854 => MethodObject::Thread,
                0x626f_6c42 => MethodObject::Blob,
                0x6e6f_6973_7369_6d62_7553_6c69_616d_45 => MethodObject::EmailSubmission,
                0x7465_7070_696e_5368_6372_6165_53 => MethodObject::SearchSnippet,
                0x7974_6974_6e65_6449 => MethodObject::Identity,
                0x6573_6e6f_7073_6552_6e6f_6974_6163_6156 => MethodObject::VacationResponse,
                0x6e6f_6974_7069_7263_7362_7553_6873_7550 => MethodObject::PushSubscription,
                0x7470_6972_6353_6576_6569_53 => MethodObject::SieveScript,
                0x6c61_7069_636e_6972_50 => MethodObject::Principal,
                0x6572_6f43 => MethodObject::Core,
                _ => return Err(parser.error_value()),
            },
            fnc: match fnc_hash {
                0x7465_67 => MethodFunction::Get,
                0x7972_6575_71 => MethodFunction::Query,
                0x7465_73 => MethodFunction::Set,
                0x7365_676e_6168_63 => MethodFunction::Changes,
                0x7365_676e_6168_4379_7265_7571 => MethodFunction::QueryChanges,
                0x7970_6f63 => MethodFunction::Copy,
                0x7472_6f70_6d69 => MethodFunction::Import,
                0x6573_7261_70 => MethodFunction::Parse,
                0x6574_6164_696c_6176 => MethodFunction::Validate,
                0x6f68_6365 => MethodFunction::Echo,
                _ => return Err(parser.error_value()),
            },
        })
    }
}

impl Display for MethodName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MethodName {
    pub fn unknown_method() -> Self {
        Self {
            obj: MethodObject::Thread,
            fnc: MethodFunction::Echo,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match (self.fnc, self.obj) {
            (MethodFunction::Echo, MethodObject::Core) => "Core/echo",
            (MethodFunction::Copy, MethodObject::Blob) => "Blob/copy",
            (MethodFunction::Get, MethodObject::PushSubscription) => "PushSubscription/get",
            (MethodFunction::Set, MethodObject::PushSubscription) => "PushSubscription/set",
            (MethodFunction::Get, MethodObject::Mailbox) => "Mailbox/get",
            (MethodFunction::Changes, MethodObject::Mailbox) => "Mailbox/changes",
            (MethodFunction::Query, MethodObject::Mailbox) => "Mailbox/query",
            (MethodFunction::QueryChanges, MethodObject::Mailbox) => "Mailbox/queryChanges",
            (MethodFunction::Set, MethodObject::Mailbox) => "Mailbox/set",
            (MethodFunction::Get, MethodObject::Thread) => "Thread/get",
            (MethodFunction::Changes, MethodObject::Thread) => "Thread/changes",
            (MethodFunction::Get, MethodObject::Email) => "Email/get",
            (MethodFunction::Changes, MethodObject::Email) => "Email/changes",
            (MethodFunction::Query, MethodObject::Email) => "Email/query",
            (MethodFunction::QueryChanges, MethodObject::Email) => "Email/queryChanges",
            (MethodFunction::Set, MethodObject::Email) => "Email/set",
            (MethodFunction::Copy, MethodObject::Email) => "Email/copy",
            (MethodFunction::Import, MethodObject::Email) => "Email/import",
            (MethodFunction::Parse, MethodObject::Email) => "Email/parse",
            (MethodFunction::Get, MethodObject::SearchSnippet) => "SearchSnippet/get",
            (MethodFunction::Get, MethodObject::Identity) => "Identity/get",
            (MethodFunction::Changes, MethodObject::Identity) => "Identity/changes",
            (MethodFunction::Set, MethodObject::Identity) => "Identity/set",
            (MethodFunction::Get, MethodObject::EmailSubmission) => "EmailSubmission/get",
            (MethodFunction::Changes, MethodObject::EmailSubmission) => "EmailSubmission/changes",
            (MethodFunction::Query, MethodObject::EmailSubmission) => "EmailSubmission/query",
            (MethodFunction::QueryChanges, MethodObject::EmailSubmission) => {
                "EmailSubmission/queryChanges"
            }
            (MethodFunction::Set, MethodObject::EmailSubmission) => "EmailSubmission/set",
            (MethodFunction::Get, MethodObject::VacationResponse) => "VacationResponse/get",
            (MethodFunction::Set, MethodObject::VacationResponse) => "VacationResponse/set",
            (MethodFunction::Get, MethodObject::SieveScript) => "SieveScript/get",
            (MethodFunction::Set, MethodObject::SieveScript) => "SieveScript/set",
            (MethodFunction::Query, MethodObject::SieveScript) => "SieveScript/query",
            (MethodFunction::Validate, MethodObject::SieveScript) => "SieveScript/validate",
            (MethodFunction::Get, MethodObject::Principal) => "Principal/get",
            (MethodFunction::Set, MethodObject::Principal) => "Principal/set",
            (MethodFunction::Query, MethodObject::Principal) => "Principal/query",
            _ => "error",
        }
    }
}

impl Display for MethodObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MethodObject::Blob => "Blob",
            MethodObject::EmailSubmission => "EmailSubmission",
            MethodObject::SearchSnippet => "SearchSnippet",
            MethodObject::Identity => "Identity",
            MethodObject::VacationResponse => "VacationResponse",
            MethodObject::PushSubscription => "PushSubscription",
            MethodObject::SieveScript => "SieveScript",
            MethodObject::Principal => "Principal",
            MethodObject::Core => "Core",
            MethodObject::Mailbox => "Mailbox",
            MethodObject::Thread => "Thread",
            MethodObject::Email => "Email",
        })
    }
}

// Method serialization
impl serde::Serialize for MethodName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
