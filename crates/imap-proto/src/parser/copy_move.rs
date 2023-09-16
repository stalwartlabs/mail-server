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
    protocol::{copy_move, ProtocolVersion},
    receiver::Request,
    utf7::utf7_maybe_decode,
    Command,
};

use super::parse_sequence_set;

impl Request<Command> {
    pub fn parse_copy_move(self, version: ProtocolVersion) -> crate::Result<copy_move::Arguments> {
        if self.tokens.len() > 1 {
            let mut tokens = self.tokens.into_iter();

            Ok(copy_move::Arguments {
                sequence_set: parse_sequence_set(
                    &tokens
                        .next()
                        .ok_or((self.tag.as_str(), "Missing sequence set."))?
                        .unwrap_bytes(),
                )
                .map_err(|v| (self.tag.as_str(), v))?,
                mailbox_name: utf7_maybe_decode(
                    tokens
                        .next()
                        .ok_or((self.tag.as_str(), "Missing mailbox name."))?
                        .unwrap_string()
                        .map_err(|v| (self.tag.as_str(), v))?,
                    version,
                ),
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
        protocol::{copy_move, ProtocolVersion, Sequence},
        receiver::Receiver,
    };

    #[test]
    fn parse_copy() {
        let mut receiver = Receiver::new();

        assert_eq!(
            receiver
                .parse(&mut "A003 COPY 2:4 MEETING\r\n".as_bytes().iter())
                .unwrap()
                .parse_copy_move(ProtocolVersion::Rev1)
                .unwrap(),
            copy_move::Arguments {
                sequence_set: Sequence::Range {
                    start: 2.into(),
                    end: 4.into(),
                },
                mailbox_name: "MEETING".to_string(),
                tag: "A003".to_string(),
            }
        );
        assert_eq!(
            receiver
                .parse(&mut "A003 COPY 2:4 \"You &- Me\"\r\n".as_bytes().iter())
                .unwrap()
                .parse_copy_move(ProtocolVersion::Rev1)
                .unwrap(),
            copy_move::Arguments {
                sequence_set: Sequence::Range {
                    start: 2.into(),
                    end: 4.into(),
                },
                mailbox_name: "You & Me".to_string(),
                tag: "A003".to_string(),
            }
        );
    }
}
