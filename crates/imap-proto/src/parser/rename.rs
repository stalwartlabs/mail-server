/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    protocol::{rename, ProtocolVersion},
    receiver::Request,
    utf7::utf7_maybe_decode,
    Command,
};

impl Request<Command> {
    pub fn parse_rename(self, version: ProtocolVersion) -> crate::Result<rename::Arguments> {
        match self.tokens.len() {
            2 => {
                let mut tokens = self.tokens.into_iter();
                Ok(rename::Arguments {
                    mailbox_name: utf7_maybe_decode(
                        tokens
                            .next()
                            .unwrap()
                            .unwrap_string()
                            .map_err(|v| (self.tag.as_ref(), v))?,
                        version,
                    ),
                    new_mailbox_name: utf7_maybe_decode(
                        tokens
                            .next()
                            .unwrap()
                            .unwrap_string()
                            .map_err(|v| (self.tag.as_ref(), v))?,
                        version,
                    ),
                    tag: self.tag,
                })
            }
            0 => Err(self.into_error("Missing argument.")),
            1 => Err(self.into_error("Missing new mailbox name.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{rename, ProtocolVersion},
        receiver::Receiver,
    };

    #[test]
    fn parse_rename() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A142 RENAME \"my funky mailbox\" Private\r\n",
                rename::Arguments {
                    mailbox_name: "my funky mailbox".to_string(),
                    new_mailbox_name: "Private".to_string(),
                    tag: "A142".to_string(),
                },
            ),
            (
                "A142 RENAME {1+}\r\na {1+}\r\nb\r\n",
                rename::Arguments {
                    mailbox_name: "a".to_string(),
                    new_mailbox_name: "b".to_string(),
                    tag: "A142".to_string(),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_rename(ProtocolVersion::Rev2)
                    .unwrap(),
                arguments
            );
        }
    }
}
