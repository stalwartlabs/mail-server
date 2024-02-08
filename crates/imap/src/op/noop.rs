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

use imap_proto::{receiver::Request, Command, StatusResponse};

use utils::listener::SessionStream;

use crate::core::{Session, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_noop(&mut self, request: Request<Command>) -> crate::OpResult {
        if let State::Selected { data, mailbox, .. } = &self.state {
            data.write_changes(
                &Some(mailbox.clone()),
                false,
                true,
                self.is_qresync,
                self.version.is_rev2(),
            )
            .await;
        }

        self.write_bytes(
            StatusResponse::completed(request.command)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
