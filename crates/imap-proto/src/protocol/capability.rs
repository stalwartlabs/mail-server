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
