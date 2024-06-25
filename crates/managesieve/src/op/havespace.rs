/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
