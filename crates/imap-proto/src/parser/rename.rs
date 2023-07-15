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
