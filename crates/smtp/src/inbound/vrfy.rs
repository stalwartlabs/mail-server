/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use directory::DirectoryError;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::Session;
use std::fmt::Write;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_vrfy(&mut self, address: String) -> Result<(), ()> {
        match self
            .core
            .session
            .config
            .rcpt
            .directory
            .eval_and_capture(self)
            .await
            .into_value()
        {
            Some(address_lookup) if self.params.can_vrfy => {
                match address_lookup.vrfy(&address.to_lowercase()).await {
                    Ok(values) if !values.is_empty() => {
                        let mut result = String::with_capacity(32);
                        for (pos, value) in values.iter().enumerate() {
                            let _ = write!(
                                result,
                                "250{}{}\r\n",
                                if pos == values.len() - 1 { " " } else { "-" },
                                value
                            );
                        }

                        tracing::debug!(parent: &self.span,
                            context = "vrfy",
                            event = "success",
                            address = &address);

                        self.write(result.as_bytes()).await
                    }
                    Ok(_) | Err(DirectoryError::Unsupported) => {
                        tracing::debug!(parent: &self.span,
                            context = "vrfy",
                            event = "not-found",
                            address = &address);

                        self.write(b"550 5.1.2 Address not found.\r\n").await
                    }
                    Err(_) => {
                        tracing::debug!(parent: &self.span,
                            context = "vrfy",
                            event = "temp-fail",
                            address = &address);

                        self.write(b"252 2.4.3 Unable to verify address at this time.\r\n")
                            .await
                    }
                }
            }
            _ => {
                tracing::debug!(parent: &self.span,
                    context = "vrfy",
                    event = "forbidden",
                    address = &address);

                self.write(b"252 2.5.1 VRFY is disabled.\r\n").await
            }
        }
    }

    pub async fn handle_expn(&mut self, address: String) -> Result<(), ()> {
        match self
            .core
            .session
            .config
            .rcpt
            .directory
            .eval_and_capture(self)
            .await
            .into_value()
        {
            Some(address_lookup) if self.params.can_expn => {
                match address_lookup.expn(&address.to_lowercase()).await {
                    Ok(values) if !values.is_empty() => {
                        let mut result = String::with_capacity(32);
                        for (pos, value) in values.iter().enumerate() {
                            let _ = write!(
                                result,
                                "250{}{}\r\n",
                                if pos == values.len() - 1 { " " } else { "-" },
                                value
                            );
                        }
                        tracing::debug!(parent: &self.span,
                            context = "expn",
                            event = "success",
                            address = &address);
                        self.write(result.as_bytes()).await
                    }
                    Ok(_) | Err(DirectoryError::Unsupported) => {
                        tracing::debug!(parent: &self.span,
                            context = "expn",
                            event = "not-found",
                            address = &address);

                        self.write(b"550 5.1.2 Mailing list not found.\r\n").await
                    }
                    Err(_) => {
                        tracing::debug!(parent: &self.span,
                            context = "expn",
                            event = "temp-fail",
                            address = &address);

                        self.write(b"252 2.4.3 Unable to expand mailing list at this time.\r\n")
                            .await
                    }
                }
            }
            _ => {
                tracing::debug!(parent: &self.span,
                    context = "expn",
                    event = "forbidden",
                    address = &address);

                self.write(b"252 2.5.1 EXPN is disabled.\r\n").await
            }
        }
    }
}
