/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::{CompactString, ToCompactString, format_compact};

use crate::{
    Command,
    protocol::{ProtocolVersion, create, list::Attribute},
    receiver::{Request, Token, bad},
    utf7::utf7_maybe_decode,
};

impl Request<Command> {
    pub fn parse_create(self, version: ProtocolVersion) -> trc::Result<create::Arguments> {
        if !self.tokens.is_empty() {
            let mut tokens = self.tokens.into_iter();
            let mailbox_name = utf7_maybe_decode(
                tokens
                    .next()
                    .unwrap()
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                version,
            );
            let mailbox_role = if let Some(Token::ParenthesisOpen) = tokens.next() {
                match tokens.next() {
                    Some(Token::Argument(param)) if param.eq_ignore_ascii_case(b"USE") => (),
                    _ => {
                        return Err(bad(
                            CompactString::from_string_buffer(self.tag),
                            "Failed to parse, expected 'USE'.",
                        ));
                    }
                }
                if tokens
                    .next()
                    .is_none_or(|token| !token.is_parenthesis_open())
                {
                    return Err(bad(
                        CompactString::from_string_buffer(self.tag),
                        "Expected '(' after 'USE'.",
                    ));
                }
                match tokens.next() {
                    Some(Token::Argument(value)) => {
                        let r = hashify::tiny_map_ignore_case!(value.as_slice(),
                            "\\Archive" => Some(Attribute::Archive),
                            "\\Drafts" => Some(Attribute::Drafts),
                            "\\Junk" => Some(Attribute::Junk),
                            "\\Sent" => Some(Attribute::Sent),
                            "\\Trash" => Some(Attribute::Trash),
                            "\\Important" => Some(Attribute::Important),
                            "\\All" => None,
                        );

                        match r {
                            Some(Some(tag)) => Some(tag),
                            Some(None) => {
                                return Err(bad(
                                    CompactString::from_string_buffer(self.tag),
                                    "A mailbox with the \"\\All\" attribute already exists.",
                                ));
                            }
                            None => {
                                return Err(bad(
                                    CompactString::from_string_buffer(self.tag),
                                    format_compact!(
                                        "Special use attribute {:?} is not supported.",
                                        String::from_utf8_lossy(&value)
                                    ),
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(bad(
                            CompactString::from_string_buffer(self.tag),
                            "Invalid SPECIAL-USE attribute.",
                        ));
                    }
                }
            } else {
                None
            };

            Ok(create::Arguments {
                mailbox_name,
                mailbox_role,
                tag: self.tag,
            })
        } else {
            Err(self.into_error("Missing arguments."))
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{ProtocolVersion, create, list::Attribute},
        receiver::Receiver,
    };

    #[test]
    fn parse_create() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A142 CREATE 12345\r\n",
                create::Arguments {
                    tag: "A142".into(),
                    mailbox_name: "12345".into(),
                    mailbox_role: None,
                },
            ),
            (
                "A142 CREATE \"my funky mailbox\"\r\n",
                create::Arguments {
                    tag: "A142".into(),
                    mailbox_name: "my funky mailbox".into(),
                    mailbox_role: None,
                },
            ),
            (
                "t1 CREATE \"Important Messages\" (USE (\\Important))\r\n",
                create::Arguments {
                    tag: "t1".into(),
                    mailbox_name: "Important Messages".into(),
                    mailbox_role: Some(Attribute::Important),
                },
            ),
            (
                "A142 CREATE \"Test-ąęć-Test\"\r\n",
                create::Arguments {
                    tag: "A142".into(),
                    mailbox_name: "Test-ąęć-Test".into(),
                    mailbox_role: None,
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_create(ProtocolVersion::Rev2)
                    .unwrap(),
                arguments
            );
        }
    }
}
