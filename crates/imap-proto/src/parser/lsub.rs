/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::ToCompactString;

use crate::{
    Command,
    protocol::{
        ProtocolVersion,
        list::{self, SelectionOption},
    },
    receiver::{Request, bad},
    utf7::utf7_maybe_decode,
};

impl Request<Command> {
    pub fn parse_lsub(self) -> trc::Result<list::Arguments> {
        if self.tokens.len() > 1 {
            let mut tokens = self.tokens.into_iter();

            Ok(list::Arguments::Extended {
                reference_name: tokens
                    .next()
                    .ok_or_else(|| bad(self.tag.to_compact_string(), "Missing reference name."))?
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                mailbox_name: vec![utf7_maybe_decode(
                    tokens
                        .next()
                        .ok_or_else(|| bad(self.tag.to_compact_string(), "Missing mailbox name."))?
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                    ProtocolVersion::Rev1,
                )],
                selection_options: vec![SelectionOption::Subscribed],
                return_options: vec![],
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
        protocol::list::{self, SelectionOption},
        receiver::Receiver,
    };

    #[test]
    fn parse_lsub() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A002 LSUB \"#news.\" \"comp.mail.*\"\r\n",
                list::Arguments::Extended {
                    tag: "A002".into(),
                    reference_name: "#news.".into(),
                    mailbox_name: vec!["comp.mail.*".into()],
                    selection_options: vec![SelectionOption::Subscribed],
                    return_options: vec![],
                },
            ),
            (
                "A002 LSUB \"#news.\" \"comp.%\"\r\n",
                list::Arguments::Extended {
                    tag: "A002".into(),
                    reference_name: "#news.".into(),
                    mailbox_name: vec!["comp.%".into()],
                    selection_options: vec![SelectionOption::Subscribed],
                    return_options: vec![],
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_lsub()
                    .unwrap(),
                arguments
            );
        }
    }
}
