/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    protocol::{
        acl::{self, ModRights, ModRightsOp, Rights},
        ProtocolVersion,
    },
    receiver::Request,
    utf7::utf7_maybe_decode,
    Command,
};

use super::PushUnique;

/*

   setacl          = "SETACL" SP mailbox SP identifier
                       SP mod-rights

   deleteacl       = "DELETEACL" SP mailbox SP identifier

   getacl          = "GETACL" SP mailbox

   listrights      = "LISTRIGHTS" SP mailbox SP identifier

   myrights        = "MYRIGHTS" SP mailbox

*/

impl Request<Command> {
    pub fn parse_acl(self, version: ProtocolVersion) -> crate::Result<acl::Arguments> {
        let (has_identifier, has_mod_rights) = match self.command {
            Command::SetAcl => (true, true),
            Command::DeleteAcl | Command::ListRights => (true, false),
            Command::GetAcl | Command::MyRights => (false, false),
            _ => unreachable!(),
        };
        let mut tokens = self.tokens.into_iter();
        let mailbox_name = utf7_maybe_decode(
            tokens
                .next()
                .ok_or((self.tag.as_str(), "Missing mailbox name."))?
                .unwrap_string()
                .map_err(|v| (self.tag.as_str(), v))?,
            version,
        );
        let identifier = if has_identifier {
            tokens
                .next()
                .ok_or((self.tag.as_str(), "Missing identifier."))?
                .unwrap_string()
                .map_err(|v| (self.tag.as_str(), v))?
                .into()
        } else {
            None
        };
        let mod_rights = if has_mod_rights {
            ModRights::parse(
                &tokens
                    .next()
                    .ok_or((self.tag.as_str(), "Missing rights."))?
                    .unwrap_bytes(),
            )
            .map_err(|v| (self.tag.as_str(), v))?
            .into()
        } else {
            None
        };

        Ok(acl::Arguments {
            tag: self.tag,
            mailbox_name,
            identifier,
            mod_rights,
        })
    }
}

impl ModRights {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        let mut op = ModRightsOp::Replace;
        let mut rights = Vec::with_capacity(value.len());
        for (pos, ch) in value.iter().enumerate() {
            rights.push_unique(match ch {
                b'l' => Rights::Lookup,
                b'r' => Rights::Read,
                b's' => Rights::Seen,
                b'w' => Rights::Write,
                b'i' => Rights::Insert,
                b'p' => Rights::Post,
                b'k' => Rights::CreateMailbox,
                b'x' => Rights::DeleteMailbox,
                b't' => Rights::DeleteMessages,
                b'e' => Rights::Expunge,
                b'a' => Rights::Administer,
                // RFC2086
                b'd' => Rights::DeleteMessages,
                b'c' => Rights::CreateMailbox,
                b'+' if pos == 0 => {
                    op = ModRightsOp::Add;
                    continue;
                }
                b'-' if pos == 0 => {
                    op = ModRightsOp::Remove;
                    continue;
                }
                _ => {
                    return Err(
                        format!("Invalid character {:?} in rights.", char::from(*ch)).into(),
                    );
                }
            })
        }

        if !rights.is_empty() {
            Ok(ModRights { op, rights })
        } else {
            Err("At least one right has to be specified.".into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{
            acl::{self, ModRights, ModRightsOp, Rights},
            ProtocolVersion,
        },
        receiver::Receiver,
    };

    #[test]
    fn parse_acl() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A003 Setacl INBOX/Drafts Byron lrswikda\r\n",
                acl::Arguments {
                    tag: "A003".to_string(),
                    mailbox_name: "INBOX/Drafts".to_string(),
                    identifier: "Byron".to_string().into(),
                    mod_rights: ModRights {
                        op: ModRightsOp::Replace,
                        rights: vec![
                            Rights::Lookup,
                            Rights::Read,
                            Rights::Seen,
                            Rights::Write,
                            Rights::Insert,
                            Rights::CreateMailbox,
                            Rights::DeleteMessages,
                            Rights::Administer,
                        ],
                    }
                    .into(),
                },
            ),
            (
                "A002 SETACL INBOX/Drafts Chris +cda\r\n",
                acl::Arguments {
                    tag: "A002".to_string(),
                    mailbox_name: "INBOX/Drafts".to_string(),
                    identifier: "Chris".to_string().into(),
                    mod_rights: ModRights {
                        op: ModRightsOp::Add,
                        rights: vec![
                            Rights::CreateMailbox,
                            Rights::DeleteMessages,
                            Rights::Administer,
                        ],
                    }
                    .into(),
                },
            ),
            (
                "A036 SETACL INBOX/Drafts John -lrswicda\r\n",
                acl::Arguments {
                    tag: "A036".to_string(),
                    mailbox_name: "INBOX/Drafts".to_string(),
                    identifier: "John".to_string().into(),
                    mod_rights: ModRights {
                        op: ModRightsOp::Remove,
                        rights: vec![
                            Rights::Lookup,
                            Rights::Read,
                            Rights::Seen,
                            Rights::Write,
                            Rights::Insert,
                            Rights::CreateMailbox,
                            Rights::DeleteMessages,
                            Rights::Administer,
                        ],
                    }
                    .into(),
                },
            ),
            (
                "A001 GETACL INBOX/Drafts\r\n",
                acl::Arguments {
                    tag: "A001".to_string(),
                    mailbox_name: "INBOX/Drafts".to_string(),
                    identifier: None,
                    mod_rights: None,
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_acl(ProtocolVersion::Rev1)
                    .unwrap(),
                arguments,
                "{:?}",
                command
            );
        }
    }
}
