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

use imap_proto::receiver::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_havespace(&mut self, request: Request<Command>) -> crate::op::OpResult {
        let mut tokens = request.tokens.into_iter();
        let name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected script name as a parameter."))?;
        let size: usize = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected script size as a parameter."))?
            .parse::<usize>()
            .map_err(|_| StatusResponse::no("Invalid size parameter."))?;

        // Validate name
        let access_token = self.state.access_token();
        let account_id = access_token.primary_id();
        self.validate_name(account_id, &name).await?;

        // Validate quota
        if access_token.quota == 0
            || size as i64 + self.jmap.get_used_quota(account_id).await?
                <= access_token.quota as i64
        {
            Ok(StatusResponse::ok("").into_bytes())
        } else {
            Err(StatusResponse::no("Quota exceeded.").with_code(ResponseCode::QuotaMaxSize))
        }
    }
}
