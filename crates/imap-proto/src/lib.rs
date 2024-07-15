/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use jmap_proto::error::set::SetErrorType;
use protocol::capability::Capability;

pub mod parser;
pub mod protocol;
pub mod receiver;
pub mod utf7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Command {
    // Client Commands - Any State
    Capability,
    #[default]
    Noop,
    Logout,

    // Client Commands - Not Authenticated State
    StartTls,
    Authenticate,
    Login,

    // Client Commands - Authenticated State
    Enable,
    Select,
    Examine,
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
    List,
    Namespace,
    Status,
    Append,
    Idle,

    // Client Commands - Selected State
    Close,
    Unselect,
    Expunge(bool),
    Search(bool),
    Fetch(bool),
    Store(bool),
    Copy(bool),
    Move(bool),

    // IMAP4rev1
    Lsub,
    Check,

    // RFC 5256
    Sort(bool),
    Thread(bool),

    // RFC 4314
    SetAcl,
    DeleteAcl,
    GetAcl,
    ListRights,
    MyRights,

    // RFC 8437
    Unauthenticate,

    // RFC 2971
    Id,
}

impl Command {
    pub fn is_uid(&self) -> bool {
        matches!(
            self,
            Command::Fetch(true)
                | Command::Search(true)
                | Command::Copy(true)
                | Command::Move(true)
                | Command::Store(true)
                | Command::Expunge(true)
                | Command::Sort(true)
                | Command::Thread(true)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCode {
    Alert,
    AlreadyExists,
    AppendUid {
        uid_validity: u32,
        uids: Vec<u32>,
    },
    AuthenticationFailed,
    AuthorizationFailed,
    BadCharset,
    Cannot,
    Capability {
        capabilities: Vec<Capability>,
    },
    ClientBug,
    Closed,
    ContactAdmin,
    CopyUid {
        uid_validity: u32,
        src_uids: Vec<u32>,
        dest_uids: Vec<u32>,
    },
    Corruption,
    Expired,
    ExpungeIssued,
    HasChildren,
    InUse,
    Limit,
    NonExistent,
    NoPerm,
    OverQuota,
    Parse,
    PermanentFlags,
    PrivacyRequired,
    ReadOnly,
    ReadWrite,
    ServerBug,
    TryCreate,
    UidNext,
    UidNotSticky,
    UidValidity,
    Unavailable,
    UnknownCte,

    // CONDSTORE
    Modified {
        ids: Vec<u32>,
    },
    HighestModseq {
        modseq: u64,
    },

    // ObjectID
    MailboxId {
        mailbox_id: String,
    },

    // USEATTR
    UseAttr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub tag: Option<String>,
    pub code: Option<ResponseCode>,
    pub message: Cow<'static, str>,
    pub rtype: ResponseType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseType {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

impl ResponseCode {
    pub fn highest_modseq(modseq: Option<u64>) -> Self {
        ResponseCode::HighestModseq {
            modseq: modseq.map(|id| id + 1).unwrap_or(0),
        }
    }
}

impl StatusResponse {
    pub fn bad(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            tag: None,
            code: None,
            message: message.into(),
            rtype: ResponseType::Bad,
        }
    }

    pub fn parse_error(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            tag: None,
            code: ResponseCode::Parse.into(),
            message: message.into(),
            rtype: ResponseType::Bad,
        }
    }

    pub fn database_failure() -> Self {
        StatusResponse::no("Database failure.").with_code(ResponseCode::ContactAdmin)
    }

    pub fn completed(command: Command) -> Self {
        StatusResponse::ok(format!("{} completed", command))
    }

    pub fn with_code(mut self, code: ResponseCode) -> Self {
        self.code = Some(code);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    pub fn no(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            tag: None,
            code: None,
            message: message.into(),
            rtype: ResponseType::No,
        }
    }

    pub fn ok(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            tag: None,
            code: None,
            message: message.into(),
            rtype: ResponseType::Ok,
        }
    }

    pub fn bye(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            tag: None,
            code: None,
            message: message.into(),
            rtype: ResponseType::Bye,
        }
    }
}

impl From<SetErrorType> for ResponseCode {
    fn from(value: SetErrorType) -> Self {
        match value {
            SetErrorType::Forbidden => ResponseCode::NoPerm,
            SetErrorType::OverQuota => ResponseCode::OverQuota,
            SetErrorType::RateLimit | SetErrorType::TooLarge => ResponseCode::Limit,
            SetErrorType::NotFound | SetErrorType::BlobNotFound => ResponseCode::NonExistent,
            SetErrorType::MailboxHasChild | SetErrorType::MailboxHasEmail => {
                ResponseCode::HasChildren
            }
            SetErrorType::ForbiddenFrom
            | SetErrorType::ForbiddenMailFrom
            | SetErrorType::ForbiddenToSend => ResponseCode::AuthorizationFailed,
            SetErrorType::AlreadyExists => ResponseCode::AlreadyExists,
            _ => ResponseCode::Cannot,
        }
    }
}
