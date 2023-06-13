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
    protocol::{capability::Capability, enable},
    receiver::Request,
    Command,
};

impl Request<Command> {
    pub fn parse_enable(self) -> crate::Result<enable::Arguments> {
        let len = self.tokens.len();
        if len > 0 {
            let mut capabilities = Vec::with_capacity(len);
            for capability in self.tokens {
                capabilities.push(
                    Capability::parse(&capability.unwrap_bytes())
                        .map_err(|v| (self.tag.as_str(), v))?,
                );
            }
            Ok(enable::Arguments {
                tag: self.tag,
                capabilities,
            })
        } else {
            Err(self.into_error("Missing arguments."))
        }
    }
}

impl Capability {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        if value.eq_ignore_ascii_case(b"IMAP4rev2") {
            Ok(Self::IMAP4rev2)
        } else if value.eq_ignore_ascii_case(b"STARTTLS") {
            Ok(Self::StartTLS)
        } else if value.eq_ignore_ascii_case(b"LOGINDISABLED") {
            Ok(Self::LoginDisabled)
        } else if value.eq_ignore_ascii_case(b"CONDSTORE") {
            Ok(Self::CondStore)
        } else if value.eq_ignore_ascii_case(b"QRESYNC") {
            Ok(Self::QResync)
        } else if value.eq_ignore_ascii_case(b"UTF8=ACCEPT") {
            Ok(Self::Utf8Accept)
        } else {
            Err(format!(
                "Unsupported capability '{}'.",
                String::from_utf8_lossy(value)
            )
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{capability::Capability, enable},
        receiver::Receiver,
    };

    #[test]
    fn parse_enable() {
        let mut receiver = Receiver::new();

        assert_eq!(
            receiver
                .parse(&mut "t2 ENABLE IMAP4rev2 CONDSTORE\r\n".as_bytes().iter())
                .unwrap()
                .parse_enable()
                .unwrap(),
            enable::Arguments {
                tag: "t2".to_string(),
                capabilities: vec![Capability::IMAP4rev2, Capability::CondStore],
            }
        );
    }
}
