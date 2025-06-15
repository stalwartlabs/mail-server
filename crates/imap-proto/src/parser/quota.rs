/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::ToCompactString;

use crate::{
    Command,
    protocol::{ProtocolVersion, quota},
    receiver::{Request, bad},
    utf7::utf7_maybe_decode,
};

impl Request<Command> {
    pub fn parse_get_quota_root(self, version: ProtocolVersion) -> trc::Result<quota::Arguments> {
        match self.tokens.len() {
            1 => Ok(quota::Arguments {
                name: utf7_maybe_decode(
                    self.tokens
                        .into_iter()
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                    version,
                ),
                tag: self.tag,
            }),
            0 => Err(self.into_error("Missing mailbox name.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }

    pub fn parse_get_quota(self) -> trc::Result<quota::Arguments> {
        match self.tokens.len() {
            1 => Ok(quota::Arguments {
                name: self
                    .tokens
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                tag: self.tag,
            }),
            0 => Err(self.into_error("Missing quota root.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{ProtocolVersion, quota},
        receiver::Receiver,
    };

    #[test]
    fn parse_quota() {
        let mut receiver = Receiver::new();

        let (command, arguments) = (
            "A142 GETQUOTAROOT INBOX\r\n",
            quota::Arguments {
                name: "INBOX".into(),
                tag: "A142".into(),
            },
        );
        assert_eq!(
            receiver
                .parse(&mut command.as_bytes().iter())
                .unwrap()
                .parse_get_quota_root(ProtocolVersion::Rev2)
                .unwrap(),
            arguments
        );

        let (command, arguments) = (
            "A142 GETQUOTA \"my funky mailbox\"\r\n",
            quota::Arguments {
                name: "my funky mailbox".into(),
                tag: "A142".into(),
            },
        );
        assert_eq!(
            receiver
                .parse(&mut command.as_bytes().iter())
                .unwrap()
                .parse_get_quota()
                .unwrap(),
            arguments
        );
    }
}
