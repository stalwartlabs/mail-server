/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::receiver::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_checkscript(&mut self, request: Request<Command>) -> super::OpResult {
        if request.tokens.is_empty() {
            return Err(StatusResponse::no("Expected script as a parameter."));
        }

        self.jmap
            .core
            .sieve
            .untrusted_compiler
            .compile(&request.tokens.into_iter().next().unwrap().unwrap_bytes())
            .map(|_| StatusResponse::ok("Script is valid.").into_bytes())
            .map_err(|err| StatusResponse::no(err.to_string()))
    }
}
