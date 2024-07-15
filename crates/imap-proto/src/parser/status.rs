/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::protocol::status::Status;
use crate::protocol::{status, ProtocolVersion};
use crate::receiver::{bad, Request, Token};
use crate::utf7::utf7_maybe_decode;
use crate::Command;

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
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    version,
                );
                let mut items = Vec::with_capacity(len - 2);

                if tokens
                    .next()
                    .map_or(true, |token| !token.is_parenthesis_open())
                {
                    return Err(bad(
                        self.tag.to_string(),
                        "Expected parenthesis after mailbox name.",
                    ));
                }

                #[allow(clippy::while_let_on_iterator)]
                while let Some(token) = tokens.next() {
                    match token {
                        Token::ParenthesisClose => break,
                        Token::Argument(value) => {
                            items.push(
                                Status::parse(&value).map_err(|v| bad(self.tag.to_string(), v))?,
                            );
                        }
                        _ => {
                            return Err(bad(
                                self.tag.to_string(),
                                "Invalid status return option argument.",
                            ))
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
                    Err(bad(self.tag, "At least one status item is required."))
                }
            }
        }
    }
}

impl Status {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        if value.eq_ignore_ascii_case(b"messages") {
            Ok(Self::Messages)
        } else if value.eq_ignore_ascii_case(b"uidnext") {
            Ok(Self::UidNext)
        } else if value.eq_ignore_ascii_case(b"uidvalidity") {
            Ok(Self::UidValidity)
        } else if value.eq_ignore_ascii_case(b"unseen") {
            Ok(Self::Unseen)
        } else if value.eq_ignore_ascii_case(b"deleted") {
            Ok(Self::Deleted)
        } else if value.eq_ignore_ascii_case(b"size") {
            Ok(Self::Size)
        } else if value.eq_ignore_ascii_case(b"highestmodseq") {
            Ok(Self::HighestModSeq)
        } else if value.eq_ignore_ascii_case(b"mailboxid") {
            Ok(Self::MailboxId)
        } else if value.eq_ignore_ascii_case(b"recent") {
            Ok(Self::Recent)
        } else {
            Err(format!(
                "Invalid status option '{}'.",
                String::from_utf8_lossy(value)
            )
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{status, ProtocolVersion},
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
                tag: "A042".to_string(),
                mailbox_name: "blurdybloop".to_string(),
                items: vec![status::Status::UidNext, status::Status::Messages],
            }
        );
    }
}
