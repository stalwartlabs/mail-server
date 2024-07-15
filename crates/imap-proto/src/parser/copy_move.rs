/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    protocol::{copy_move, ProtocolVersion},
    receiver::{bad, Request},
    utf7::utf7_maybe_decode,
    Command,
};

use super::parse_sequence_set;

impl Request<Command> {
    pub fn parse_copy_move(self, version: ProtocolVersion) -> trc::Result<copy_move::Arguments> {
        if self.tokens.len() > 1 {
            let mut tokens = self.tokens.into_iter();

            Ok(copy_move::Arguments {
                sequence_set: parse_sequence_set(
                    &tokens
                        .next()
                        .ok_or_else(|| bad(self.tag.to_string(), "Missing sequence set."))?
                        .unwrap_bytes(),
                )
                .map_err(|v| bad(self.tag.to_string(), v))?,
                mailbox_name: utf7_maybe_decode(
                    tokens
                        .next()
                        .ok_or_else(|| bad(self.tag.to_string(), "Missing mailbox name."))?
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.to_string(), v))?,
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
