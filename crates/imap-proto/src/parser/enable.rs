/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
