/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use directory::DirectoryError;

use crate::core::Session;
use std::fmt::Write;

impl<T: SessionStream> Session<T> {
    pub async fn handle_vrfy(&mut self, address: String) -> Result<(), ()> {
        match self
            .core
            .core
            .eval_if::<String, _>(&self.core.core.smtp.session.rcpt.directory, self)
            .await
            .and_then(|name| self.core.core.get_directory(&name))
        {
            Some(directory) if self.params.can_vrfy => {
                match self
                    .core
                    .core
                    .vrfy(directory, &address.to_lowercase())
                    .await
                {
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
            .core
            .eval_if::<String, _>(&self.core.core.smtp.session.rcpt.directory, self)
            .await
            .and_then(|name| self.core.core.get_directory(&name))
        {
            Some(directory) if self.params.can_expn => {
                match self
                    .core
                    .core
                    .expn(directory, &address.to_lowercase())
                    .await
                {
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
