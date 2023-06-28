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

use imap_proto::{receiver::Request, Command, StatusResponse};

use tokio::io::AsyncRead;

use crate::core::{Session, State};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_noop(
        &mut self,
        request: Request<Command>,
        is_check: bool,
    ) -> Result<(), ()> {
        match &self.state {
            State::Authenticated { data } => {
                data.write_changes(&None, true, false, self.is_qresync, self.version.is_rev2())
                    .await;
            }
            State::Selected { data, mailbox, .. } => {
                data.write_changes(
                    &Some(mailbox.clone()),
                    true,
                    true,
                    self.is_qresync,
                    self.version.is_rev2(),
                )
                .await;
            }
            _ => (),
        }

        self.write_bytes(
            StatusResponse::completed(if !is_check {
                Command::Noop
            } else {
                Command::Check
            })
            .with_tag(request.tag)
            .into_bytes(),
        )
        .await
    }
}
