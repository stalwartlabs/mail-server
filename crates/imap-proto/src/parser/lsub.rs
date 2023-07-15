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
    protocol::{
        list::{self, SelectionOption},
        ProtocolVersion,
    },
    receiver::Request,
    utf7::utf7_maybe_decode,
    Command,
};

impl Request<Command> {
    pub fn parse_lsub(self) -> crate::Result<list::Arguments> {
        if self.tokens.len() > 1 {
            let mut tokens = self.tokens.into_iter();

            Ok(list::Arguments::Extended {
                reference_name: tokens
                    .next()
                    .ok_or((self.tag.as_str(), "Missing reference name."))?
                    .unwrap_string()
                    .map_err(|v| (self.tag.as_str(), v))?,
                mailbox_name: vec![utf7_maybe_decode(
                    tokens
                        .next()
                        .ok_or((self.tag.as_str(), "Missing mailbox name."))?
                        .unwrap_string()
                        .map_err(|v| (self.tag.as_str(), v))?,
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
                    tag: "A002".to_string(),
                    reference_name: "#news.".to_string(),
                    mailbox_name: vec!["comp.mail.*".to_string()],
                    selection_options: vec![SelectionOption::Subscribed],
                    return_options: vec![],
                },
            ),
            (
                "A002 LSUB \"#news.\" \"comp.%\"\r\n",
                list::Arguments::Extended {
                    tag: "A002".to_string(),
                    reference_name: "#news.".to_string(),
                    mailbox_name: vec!["comp.%".to_string()],
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
