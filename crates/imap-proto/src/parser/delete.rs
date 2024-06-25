/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    protocol::{delete, ProtocolVersion},
    receiver::Request,
    utf7::utf7_maybe_decode,
    Command,
};

impl Request<Command> {
    pub fn parse_delete(self, version: ProtocolVersion) -> crate::Result<delete::Arguments> {
        match self.tokens.len() {
            1 => Ok(delete::Arguments {
                mailbox_name: utf7_maybe_decode(
                    self.tokens
                        .into_iter()
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| (self.tag.as_ref(), v))?,
                    version,
                ),
                tag: self.tag,
            }),
            0 => Err(self.into_error("Missing mailbox name.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{delete, ProtocolVersion},
        receiver::Receiver,
    };

    #[test]
    fn parse_delete() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A142 DELETE INBOX\r\n",
                delete::Arguments {
                    mailbox_name: "INBOX".to_string(),
                    tag: "A142".to_string(),
                },
            ),
            (
                "A142 DELETE \"my funky mailbox\"\r\n",
                delete::Arguments {
                    mailbox_name: "my funky mailbox".to_string(),
                    tag: "A142".to_string(),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_delete(ProtocolVersion::Rev2)
                    .unwrap(),
                arguments
            );
        }
    }
}
