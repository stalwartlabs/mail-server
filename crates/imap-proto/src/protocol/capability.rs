/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{authenticate::Mechanism, ImapResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    IMAP4rev2,
    IMAP4rev1,
    StartTLS,
    LoginDisabled,
    Idle,
    Namespace,
    Id,
    Children,
    MultiAppend,
    Binary,
    Unselect,
    ACL,
    UIDPlus,
    ESearch,
    SASLIR, //SASL-IR
    Within,
    Enable,
    SearchRes,
    Sort,
    Thread,       //THREAD=REFERENCES
    ListExtended, //LIST-EXTENDED
    ESort,
    SortDisplay,      //SORT=DISPLAY
    SpecialUse,       //SPECIAL-USE
    CreateSpecialUse, //CREATE-SPECIAL-USEE
    Move,
    CondStore,
    QResync,
    LiteralPlus, //LITERAL+
    UnAuthenticate,
    StatusSize, //STATUS=SIZE
    ObjectId,
    Preview,
    Utf8Accept,
    Auth(Mechanism),
}

impl Capability {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            Capability::Auth(mechanism) => {
                buf.extend_from_slice(b"AUTH=");
                mechanism.serialize(buf);
                return;
            }
            Capability::IMAP4rev2 => b"IMAP4rev2",
            Capability::IMAP4rev1 => b"IMAP4rev1",
            Capability::StartTLS => b"STARTTLS",
            Capability::LoginDisabled => b"LOGINDISABLED",
            Capability::CondStore => b"CONDSTORE",
            Capability::QResync => b"QRESYNC",
            Capability::LiteralPlus => b"LITERAL+",
            Capability::UnAuthenticate => b"UNAUTHENTICATE",
            Capability::StatusSize => b"STATUS=SIZE",
            Capability::ObjectId => b"OBJECTID",
            Capability::Preview => b"PREVIEW",
            Capability::Idle => b"IDLE",
            Capability::Namespace => b"NAMESPACE",
            Capability::Id => b"ID",
            Capability::Children => b"CHILDREN",
            Capability::MultiAppend => b"MULTIAPPEND",
            Capability::Binary => b"BINARY",
            Capability::Unselect => b"UNSELECT",
            Capability::ACL => b"ACL",
            Capability::UIDPlus => b"UIDPLUS",
            Capability::ESearch => b"ESEARCH",
            Capability::SASLIR => b"SASL-IR",
            Capability::Within => b"WITHIN",
            Capability::Enable => b"ENABLE",
            Capability::SearchRes => b"SEARCHRES",
            Capability::Sort => b"SORT",
            Capability::Thread => b"THREAD=REFERENCES",
            Capability::ListExtended => b"LIST-EXTENDED",
            Capability::ESort => b"ESORT",
            Capability::SortDisplay => b"SORT=DISPLAY",
            Capability::SpecialUse => b"SPECIAL-USE",
            Capability::CreateSpecialUse => b"CREATE-SPECIAL-USE",
            Capability::Move => b"MOVE",
            Capability::Utf8Accept => b"UTF8=ACCEPT",
        });
    }

    pub fn all_capabilities(is_authenticated: bool, is_tls: bool) -> Vec<Capability> {
        let mut capabilties = vec![
            Capability::IMAP4rev2,
            Capability::IMAP4rev1,
            Capability::Enable,
            Capability::SASLIR,
            Capability::LiteralPlus,
            Capability::Id,
            Capability::Utf8Accept,
        ];

        if is_authenticated {
            capabilties.extend([
                Capability::Idle,
                Capability::Namespace,
                Capability::Children,
                Capability::MultiAppend,
                Capability::Binary,
                Capability::Unselect,
                Capability::ACL,
                Capability::UIDPlus,
                Capability::ESearch,
                Capability::Within,
                Capability::SearchRes,
                Capability::Sort,
                Capability::Thread,
                Capability::ListExtended,
                Capability::ESort,
                Capability::SortDisplay,
                Capability::SpecialUse,
                Capability::CreateSpecialUse,
                Capability::Move,
                Capability::CondStore,
                Capability::QResync,
                Capability::UnAuthenticate,
                Capability::StatusSize,
                Capability::ObjectId,
                Capability::Preview,
            ]);
        } else {
            capabilties.extend([
                Capability::Auth(Mechanism::OAuthBearer),
                Capability::Auth(Mechanism::Plain),
            ]);
        }
        if !is_tls {
            capabilties.push(Capability::StartTLS);
        }

        capabilties
    }
}

impl ImapResponse for Response {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"* CAPABILITY");
        for capability in self.capabilities.iter() {
            buf.push(b' ');
            capability.serialize(&mut buf);
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{
        capability::{Capability, Response},
        ImapResponse,
    };

    #[test]
    fn serialize_capability() {
        assert_eq!(
            &Response {
                capabilities: vec![
                    Capability::IMAP4rev2,
                    Capability::StartTLS,
                    Capability::LoginDisabled
                ],
            }
            .serialize(),
            concat!("* CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED\r\n",).as_bytes()
        );
    }
}
