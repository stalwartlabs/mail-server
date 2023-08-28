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

use smtp_proto::{
    RcptTo, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::{Session, SessionAddress},
    queue::DomainPart,
    scripts::ScriptResult,
};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_rcpt_to(&mut self, to: RcptTo<String>) -> Result<(), ()> {
        #[cfg(feature = "test_mode")]
        if self.instance.id.ends_with("-debug") {
            if to.address.contains("fail@") {
                return self.write(b"503 5.5.1 Invalid recipient.\r\n").await;
            } else if to.address.contains("delay@") {
                return self.write(b"451 4.5.3 Try again later.\r\n").await;
            }
        }

        if self.data.mail_from.is_none() {
            return self.write(b"503 5.5.1 MAIL is required first.\r\n").await;
        } else if self.data.rcpt_to.len() >= self.params.rcpt_max {
            return self.write(b"451 4.5.3 Too many recipients.\r\n").await;
        }

        // Verify parameters
        if ((to.flags
            & (RCPT_NOTIFY_DELAY | RCPT_NOTIFY_NEVER | RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE)
            != 0)
            || to.orcpt.is_some())
            && !self.params.rcpt_dsn
        {
            return self
                .write(b"501 5.5.4 DSN extension has been disabled.\r\n")
                .await;
        }

        // Build RCPT
        let address_lcase = to.address.to_lowercase();
        let rcpt = SessionAddress {
            domain: address_lcase.domain_part().to_string(),
            address_lcase,
            address: to.address,
            flags: to.flags,
            dsn_info: to.orcpt,
        };

        if self.data.rcpt_to.contains(&rcpt) {
            return self.write(b"250 2.1.5 OK\r\n").await;
        }
        self.data.rcpt_to.push(rcpt);

        // Address rewriting and Sieve filtering
        let rcpt_script = self
            .core
            .session
            .config
            .rcpt
            .script
            .eval(self)
            .await
            .clone();
        if rcpt_script.is_some() || !self.core.session.config.rcpt.rewrite.is_empty() {
            // Sieve filtering
            if let Some(script) = rcpt_script {
                match self
                    .run_script(script.clone(), self.build_script_parameters())
                    .await
                {
                    ScriptResult::Accept { modifications } => {
                        if !modifications.is_empty() {
                            tracing::debug!(parent: &self.span,
                            context = "sieve",
                            event = "modify",
                            address = self.data.rcpt_to.last().unwrap().address,
                            modifications = ?modifications);
                            self.data.apply_sieve_modifications(modifications);
                        }
                    }
                    ScriptResult::Reject(message) => {
                        tracing::debug!(parent: &self.span,
                        context = "sieve",
                        event = "reject",
                        address = self.data.rcpt_to.last().unwrap().address,
                        reason = message);
                        self.data.rcpt_to.pop();
                        return self.write(message.as_bytes()).await;
                    }
                    _ => (),
                }
            }

            // Address rewriting
            if let Some(new_address) = self
                .core
                .session
                .config
                .rcpt
                .rewrite
                .eval_and_capture(self)
                .await
                .into_value(self)
                .map(|s| s.into_owned())
            {
                let rcpt = self.data.rcpt_to.last_mut().unwrap();
                if new_address.contains('@') {
                    rcpt.address_lcase = new_address.to_lowercase();
                    rcpt.domain = rcpt.address_lcase.domain_part().to_string();
                    rcpt.address = new_address;
                }
            }

            // Check for duplicates
            let rcpt = self.data.rcpt_to.last().unwrap();
            if self.data.rcpt_to.iter().filter(|r| r == &rcpt).count() > 1 {
                self.data.rcpt_to.pop();
                return self.write(b"250 2.1.5 OK\r\n").await;
            }
        }

        // Verify address
        let rcpt = self.data.rcpt_to.last().unwrap();
        if let Some(directory) = self
            .core
            .session
            .config
            .rcpt
            .directory
            .eval_and_capture(self)
            .await
            .into_value(self)
        {
            if let Ok(is_local_domain) = directory.is_local_domain(&rcpt.domain).await {
                if is_local_domain {
                    if let Ok(is_local_address) = directory.rcpt(&rcpt.address_lcase).await {
                        if !is_local_address {
                            tracing::debug!(parent: &self.span,
                                            context = "rcpt", 
                                            event = "error",
                                            address = &rcpt.address_lcase,
                                            "Mailbox does not exist.");

                            self.data.rcpt_to.pop();
                            return self
                                .rcpt_error(b"550 5.1.2 Mailbox does not exist.\r\n")
                                .await;
                        }
                    } else {
                        tracing::debug!(parent: &self.span,
                            context = "rcpt", 
                            event = "error",
                            address = &rcpt.address_lcase,
                            "Temporary address verification failure.");

                        self.data.rcpt_to.pop();
                        return self
                            .write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                            .await;
                    }
                } else if !self.params.rcpt_relay {
                    tracing::debug!(parent: &self.span,
                        context = "rcpt", 
                        event = "error",
                        address = &rcpt.address_lcase,
                        "Relay not allowed.");

                    self.data.rcpt_to.pop();
                    return self.rcpt_error(b"550 5.1.2 Relay not allowed.\r\n").await;
                }
            } else {
                tracing::debug!(parent: &self.span,
                    context = "rcpt", 
                    event = "error",
                    address = &rcpt.address_lcase,
                    "Temporary address verification failure.");

                self.data.rcpt_to.pop();
                return self
                    .write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                    .await;
            }
        } else if !self.params.rcpt_relay {
            tracing::debug!(parent: &self.span,
                context = "rcpt", 
                event = "error",
                address = &rcpt.address_lcase,
                "Relay not allowed.");

            self.data.rcpt_to.pop();
            return self.rcpt_error(b"550 5.1.2 Relay not allowed.\r\n").await;
        }

        if self.is_allowed().await {
            tracing::debug!(parent: &self.span,
                    context = "rcpt",
                    event = "success",
                    address = &self.data.rcpt_to.last().unwrap().address);
        } else {
            self.data.rcpt_to.pop();
            return self
                .write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await;
        }

        self.write(b"250 2.1.5 OK\r\n").await
    }

    async fn rcpt_error(&mut self, response: &[u8]) -> Result<(), ()> {
        tokio::time::sleep(self.params.rcpt_errors_wait).await;
        self.data.rcpt_errors += 1;
        self.write(response).await?;
        if self.data.rcpt_errors < self.params.rcpt_errors_max {
            Ok(())
        } else {
            self.write(b"421 4.3.0 Too many errors, disconnecting.\r\n")
                .await?;
            tracing::debug!(
                parent: &self.span,
                context = "rcpt",
                event = "disconnect",
                reason = "too-many-errors",
                "Too many invalid RCPT commands."
            );
            Err(())
        }
    }
}
