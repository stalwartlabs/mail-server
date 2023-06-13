/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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
