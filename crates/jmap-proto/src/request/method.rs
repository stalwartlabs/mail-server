/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

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
    Quota,
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
    Lookup,
    Upload,
    Echo,
}

impl JsonObjectParser for MethodName {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
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
                0x006c_6961_6d45 => MethodObject::Email,
                0x0078_6f62_6c69_614d => MethodObject::Mailbox,
                0x6461_6572_6854 => MethodObject::Thread,
                0x626f_6c42 => MethodObject::Blob,
                0x006e_6f69_7373_696d_6275_536c_6961_6d45 => MethodObject::EmailSubmission,
                0x0074_6570_7069_6e53_6863_7261_6553 => MethodObject::SearchSnippet,
                0x7974_6974_6e65_6449 => MethodObject::Identity,
                0x6573_6e6f_7073_6552_6e6f_6974_6163_6156 => MethodObject::VacationResponse,
                0x6e6f_6974_7069_7263_7362_7553_6873_7550 => MethodObject::PushSubscription,
                0x0074_7069_7263_5365_7665_6953 => MethodObject::SieveScript,
                0x006c_6170_6963_6e69_7250 => MethodObject::Principal,
                0x0061_746f_7551 => MethodObject::Quota,
                0x6572_6f43 => MethodObject::Core,
                _ => return Err(parser.error_value()),
            },
            fnc: match fnc_hash {
                0x0074_6567 => MethodFunction::Get,
                0x0079_7265_7571 => MethodFunction::Query,
                0x0074_6573 => MethodFunction::Set,
                0x0073_6567_6e61_6863 => MethodFunction::Changes,
                0x7365_676e_6168_4379_7265_7571 => MethodFunction::QueryChanges,
                0x7970_6f63 => MethodFunction::Copy,
                0x7472_6f70_6d69 => MethodFunction::Import,
                0x0065_7372_6170 => MethodFunction::Parse,
                0x6574_6164_696c_6176 => MethodFunction::Validate,
                0x7075_6b6f_6f6c => MethodFunction::Lookup,
                0x6461_6f6c_7075 => MethodFunction::Upload,
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
    pub fn new(obj: MethodObject, fnc: MethodFunction) -> Self {
        Self { obj, fnc }
    }

    pub fn error() -> Self {
        Self {
            obj: MethodObject::Thread,
            fnc: MethodFunction::Echo,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match (self.fnc, self.obj) {
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

            (MethodFunction::Get, MethodObject::Quota) => "Quota/get",
            (MethodFunction::Changes, MethodObject::Quota) => "Quota/changes",
            (MethodFunction::Query, MethodObject::Quota) => "Quota/query",
            (MethodFunction::QueryChanges, MethodObject::Quota) => "Quota/queryChanges",

            (MethodFunction::Get, MethodObject::Blob) => "Blob/get",
            (MethodFunction::Copy, MethodObject::Blob) => "Blob/copy",
            (MethodFunction::Lookup, MethodObject::Blob) => "Blob/lookup",
            (MethodFunction::Upload, MethodObject::Blob) => "Blob/upload",

            (MethodFunction::Echo, MethodObject::Core) => "Core/echo",
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
            MethodObject::Quota => "Quota",
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
