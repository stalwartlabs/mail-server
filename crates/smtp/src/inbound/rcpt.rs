/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{config::smtp::session::Stage, listener::SessionStream, scripts::ScriptModification};
use smtp_proto::{
    RcptTo, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use trc::SmtpEvent;

use crate::{
    core::{Session, SessionAddress},
    queue::DomainPart,
    scripts::ScriptResult,
};

impl<T: SessionStream> Session<T> {
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
            .core
            .eval_if::<String, _>(
                &self.core.core.smtp.session.rcpt.script,
                self,
                self.data.session_id,
            )
            .await
            .and_then(|name| self.core.core.get_sieve_script(&name, self.data.session_id))
            .cloned();

        if rcpt_script.is_some()
            || !self.core.core.smtp.session.rcpt.rewrite.is_empty()
            || self
                .core
                .core
                .smtp
                .session
                .milters
                .iter()
                .any(|m| m.run_on_stage.contains(&Stage::Rcpt))
        {
            // Sieve filtering
            if let Some(script) = rcpt_script {
                match self
                    .run_script(script.clone(), self.build_script_parameters("rcpt"))
                    .await
                {
                    ScriptResult::Accept { modifications } => {
                        if !modifications.is_empty() {
                            for modification in modifications {
                                if let ScriptModification::SetEnvelope { name, value } =
                                    modification
                                {
                                    self.data.apply_envelope_modification(name, value);
                                }
                            }
                        }
                    }
                    ScriptResult::Reject(message) => {
                        self.data.rcpt_to.pop();
                        return self.write(message.as_bytes()).await;
                    }
                    _ => (),
                }
            }

            // Milter filtering
            if let Err(message) = self.run_milters(Stage::Rcpt, None).await {
                self.data.rcpt_to.pop();
                return self.write(message.message.as_bytes()).await;
            }

            // MTAHook filtering
            if let Err(message) = self.run_mta_hooks(Stage::Rcpt, None).await {
                self.data.rcpt_to.pop();
                return self.write(message.message.as_bytes()).await;
            }

            // Address rewriting
            if let Some(new_address) = self
                .core
                .core
                .eval_if::<String, _>(
                    &self.core.core.smtp.session.rcpt.rewrite,
                    self,
                    self.data.session_id,
                )
                .await
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
            .core
            .eval_if::<String, _>(
                &self.core.core.smtp.session.rcpt.directory,
                self,
                self.data.session_id,
            )
            .await
            .and_then(|name| self.core.core.get_directory(&name))
        {
            match directory.is_local_domain(&rcpt.domain).await {
                Ok(is_local_domain) => {
                    if is_local_domain {
                        match self
                            .core
                            .core
                            .rcpt(directory, &rcpt.address_lcase, self.data.session_id)
                            .await
                        {
                            Ok(is_local_address) => {
                                if !is_local_address {
                                    trc::event!(
                                        Smtp(SmtpEvent::MailboxDoesNotExist),
                                        SpanId = self.data.session_id,
                                        To = rcpt.address_lcase.clone(),
                                    );

                                    self.data.rcpt_to.pop();
                                    return self
                                        .rcpt_error(b"550 5.1.2 Mailbox does not exist.\r\n")
                                        .await;
                                }
                            }
                            Err(err) => {
                                trc::error!(err
                                    .span_id(self.data.session_id)
                                    .caused_by(trc::location!())
                                    .details("Failed to verify address."));

                                self.data.rcpt_to.pop();
                                return self
                                    .write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                                    .await;
                            }
                        }
                    } else if !self
                        .core
                        .core
                        .eval_if(
                            &self.core.core.smtp.session.rcpt.relay,
                            self,
                            self.data.session_id,
                        )
                        .await
                        .unwrap_or(false)
                    {
                        trc::event!(
                            Smtp(SmtpEvent::RelayNotAllowed),
                            SpanId = self.data.session_id,
                            To = rcpt.address_lcase.clone(),
                        );

                        self.data.rcpt_to.pop();
                        return self.rcpt_error(b"550 5.1.2 Relay not allowed.\r\n").await;
                    }
                }
                Err(err) => {
                    trc::error!(err
                        .span_id(self.data.session_id)
                        .caused_by(trc::location!())
                        .details("Failed to verify address."));

                    self.data.rcpt_to.pop();
                    return self
                        .write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                        .await;
                }
            }
        } else if !self
            .core
            .core
            .eval_if(
                &self.core.core.smtp.session.rcpt.relay,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(false)
        {
            trc::event!(
                Smtp(SmtpEvent::RelayNotAllowed),
                SpanId = self.data.session_id,
                To = rcpt.address_lcase.clone(),
            );

            self.data.rcpt_to.pop();
            return self.rcpt_error(b"550 5.1.2 Relay not allowed.\r\n").await;
        }

        if self.is_allowed().await {
            trc::event!(
                Smtp(SmtpEvent::RelayNotAllowed),
                SpanId = self.data.session_id,
                To = self.data.rcpt_to.last().unwrap().address_lcase.clone(),
            );
        } else {
            trc::event!(
                Smtp(SmtpEvent::RateLimitExceeded),
                SpanId = self.data.session_id,
                To = self.data.rcpt_to.last().unwrap().address_lcase.clone(),
            );

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
            trc::event!(
                Smtp(SmtpEvent::TooManyInvalidRcpt),
                SpanId = self.data.session_id,
            );

            self.write(b"421 4.3.0 Too many errors, disconnecting.\r\n")
                .await?;
            Err(())
        }
    }
}
