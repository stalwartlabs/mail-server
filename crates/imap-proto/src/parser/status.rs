/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::{CompactString, ToCompactString};

use crate::Command;
use crate::protocol::status::Status;
use crate::protocol::{ProtocolVersion, status};
use crate::receiver::{Request, Token, bad};
use crate::utf7::utf7_maybe_decode;

impl Request<Command> {
    pub fn parse_status(self, version: ProtocolVersion) -> trc::Result<status::Arguments> {
        match self.tokens.len() {
            0..=3 => Err(self.into_error("Missing arguments.")),
            len => {
                let mut tokens = self.tokens.into_iter();
                let mailbox_name = utf7_maybe_decode(
                    tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                    version,
                );
                let mut items = Vec::with_capacity(len - 2);

                if tokens
                    .next()
                    .is_none_or(|token| !token.is_parenthesis_open())
                {
                    return Err(bad(
                        self.tag.to_compact_string(),
                        "Expected parenthesis after mailbox name.",
                    ));
                }

                #[allow(clippy::while_let_on_iterator)]
                while let Some(token) = tokens.next() {
                    match token {
                        Token::ParenthesisClose => break,
                        Token::Argument(value) => {
                            items.push(
                                Status::parse(&value)
                                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                            );
                        }
                        _ => {
                            return Err(bad(
                                self.tag.to_compact_string(),
                                "Invalid status return option argument.",
                            ));
                        }
                    }
                }

                if !items.is_empty() {
                    Ok(status::Arguments {
                        tag: self.tag,
                        mailbox_name,
                        items,
                    })
                } else {
                    Err(bad(
                        CompactString::from_string_buffer(self.tag),
                        "At least one status item is required.",
                    ))
                }
            }
        }
    }
}

impl Status {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::tiny_map_ignore_case!(value,
            "MESSAGES" => Self::Messages,
            "UIDNEXT" => Self::UidNext,
            "UIDVALIDITY" => Self::UidValidity,
            "UNSEEN" => Self::Unseen,
            "DELETED" => Self::Deleted,
            "SIZE" => Self::Size,
            "HIGHESTMODSEQ" => Self::HighestModSeq,
            "MAILBOXID" => Self::MailboxId,
            "RECENT" => Self::Recent,
            "DELETED-STORAGE" => Self::DeletedStorage
        )
        .ok_or_else(|| {
            format!(
                "Invalid status option '{}'.",
                String::from_utf8_lossy(value)
            )
            .into()
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{ProtocolVersion, status},
        receiver::Receiver,
    };

    #[test]
    fn parse_status() {
        let mut receiver = Receiver::new();

        assert_eq!(
            receiver
                .parse(
                    &mut "A042 STATUS blurdybloop (UIDNEXT MESSAGES)\r\n"
                        .as_bytes()
                        .iter()
                )
                .unwrap()
                .parse_status(ProtocolVersion::Rev2)
                .unwrap(),
            status::Arguments {
                tag: "A042".into(),
                mailbox_name: "blurdybloop".into(),
                items: vec![status::Status::UidNext, status::Status::Messages],
            }
        );
    }
}
