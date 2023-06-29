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

use imap_proto::receiver::Request;
use jmap_proto::types::collection::Collection;
use store::write::log::ChangeLogBuilder;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_deletescript(&mut self, request: Request<Command>) -> super::OpResult {
        let name = request
            .tokens
            .into_iter()
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected script name as a parameter."))?;

        let account_id = self.state.access_token().primary_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        if self
            .jmap
            .sieve_script_delete(account_id, document_id, true)
            .await?
        {
            // Write changes
            let mut changelog = ChangeLogBuilder::new();
            changelog.log_delete(Collection::SieveScript, document_id);
            self.jmap.commit_changes(account_id, changelog).await?;

            Ok(StatusResponse::ok("Deleted.").into_bytes())
        } else {
            Err(StatusResponse::no("You may not delete an active script")
                .with_code(ResponseCode::Active))
        }
    }
}
