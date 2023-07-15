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

use imap_proto::{
    protocol::{
        capability::{Capability, Response},
        ImapResponse,
    },
    receiver::Request,
    Command, StatusResponse,
};

use tokio::io::AsyncRead;

use crate::core::Session;

impl<T: AsyncRead> Session<T> {
    pub async fn handle_capability(&mut self, request: Request<Command>) -> crate::OpResult {
        self.write_bytes(
            StatusResponse::completed(Command::Capability)
                .with_tag(request.tag)
                .serialize(
                    Response {
                        capabilities: Capability::all_capabilities(
                            self.state.is_authenticated(),
                            self.is_tls,
                        ),
                    }
                    .serialize(),
                ),
        )
        .await
    }

    pub async fn handle_id(&mut self, request: Request<Command>) -> crate::OpResult {
        self.write_bytes(
            StatusResponse::completed(Command::Id)
                .with_tag(request.tag)
                .serialize(
                    concat!(
                        "* ID (\"name\" \"Stalwart IMAP\" \"version\" \"",
                        env!("CARGO_PKG_VERSION"),
                        "\" \"vendor\" \"Stalwart Labs Ltd.\" ",
                        "\"support-url\" \"https://stalw.art/imap\")\r\n"
                    )
                    .as_bytes()
                    .to_vec(),
                ),
        )
        .await
    }
}
