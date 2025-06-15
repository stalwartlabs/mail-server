/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    KV_GREYLIST, config::smtp::session::Stage, listener::SessionStream, scripts::ScriptModification,
};

use directory::backend::RcptType;
use smtp_proto::{
    RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, RcptTo,
};
use store::dispatch::lookup::KeyValue;
use trc::{SecurityEvent, SmtpEvent};

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
            } else if (to.address.contains("delay-random@") && rand::random())
                || to.address.contains("delay@")
            {
                return self.write(b"451 4.5.3 Try again later.\r\n").await;
            } else if to.address.contains("slow@") {
                tokio::time::sleep(std::time::Duration::from_secs(
                    rand::random::<u64>() % 5 + 5,
                ))
                .await;
            }
        }

        if self.data.mail_from.is_none() {
            trc::event!(
                Smtp(SmtpEvent::MailFromMissing),
                SpanId = self.data.session_id,
            );
            return self.write(b"503 5.5.1 MAIL is required first.\r\n").await;
        } else if self.data.rcpt_to.len() >= self.params.rcpt_max {
            trc::event!(
                Smtp(SmtpEvent::TooManyRecipients),
                SpanId = self.data.session_id,
                Limit = self.params.rcpt_max,
            );
            return self.write(b"455 4.5.3 Too many recipients.\r\n").await;
        }

        // Verify parameters
        if ((to.flags
            & (RCPT_NOTIFY_DELAY | RCPT_NOTIFY_NEVER | RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE)
            != 0)
            || to.orcpt.is_some())
            && !self.params.rcpt_dsn
        {
            trc::event!(Smtp(SmtpEvent::DsnDisabled), SpanId = self.data.session_id,);
            return self
                .write(b"501 5.5.4 DSN extension has been disabled.\r\n")
                .await;
        }

        // Build RCPT
        let address_lcase = to.address.to_lowercase();
        let rcpt = SessionAddress {
            domain: address_lcase.domain_part().into(),
            address_lcase,
            address: to.address,
            flags: to.flags,
            dsn_info: to.orcpt,
        };

        if self.data.rcpt_to.contains(&rcpt) {
            trc::event!(
                Smtp(SmtpEvent::RcptToDuplicate),
                SpanId = self.data.session_id,
                To = rcpt.address_lcase,
            );
            self.data.rcpt_oks += 1;
            return self.write(b"250 2.1.5 OK\r\n").await;
        }
        self.data.rcpt_to.push(rcpt);

        // Address rewriting and Sieve filtering
        let rcpt_script = self
            .server
            .eval_if::<String, _>(
                &self.server.core.smtp.session.rcpt.script,
                self,
                self.data.session_id,
            )
            .await
            .and_then(|name| {
                self.server
                    .get_trusted_sieve_script(&name, self.data.session_id)
                    .map(|s| (s.clone(), name))
            });

        if rcpt_script.is_some()
            || !self.server.core.smtp.session.rcpt.rewrite.is_empty()
            || self
                .server
                .core
                .smtp
                .session
                .milters
                .iter()
                .any(|m| m.run_on_stage.contains(&Stage::Rcpt))
        {
            // Sieve filtering
            if let Some((script, script_id)) = rcpt_script {
                match self
                    .run_script(
                        script_id,
                        script.clone(),
                        self.build_script_parameters("rcpt"),
                    )
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
            if let Err(message) = self.run_mta_hooks(Stage::Rcpt, None, None).await {
                self.data.rcpt_to.pop();
                return self.write(message.message.as_bytes()).await;
            }

            // Address rewriting
            if let Some(new_address) = self
                .server
                .eval_if::<String, _>(
                    &self.server.core.smtp.session.rcpt.rewrite,
                    self,
                    self.data.session_id,
                )
                .await
            {
                let rcpt = self.data.rcpt_to.last_mut().unwrap();

                trc::event!(
                    Smtp(SmtpEvent::RcptToRewritten),
                    SpanId = self.data.session_id,
                    Details = rcpt.address_lcase.clone(),
                    To = new_address.clone(),
                );

                if new_address.contains('@') {
                    rcpt.address_lcase = new_address.to_lowercase();
                    rcpt.domain = rcpt.address_lcase.domain_part().into();
                    rcpt.address = new_address;
                }
            }

            // Check for duplicates
            let rcpt = self.data.rcpt_to.last().unwrap();
            if self.data.rcpt_to.iter().filter(|r| r == &rcpt).count() > 1 {
                trc::event!(
                    Smtp(SmtpEvent::RcptToDuplicate),
                    SpanId = self.data.session_id,
                    To = rcpt.address_lcase.clone(),
                );
                self.data.rcpt_to.pop();
                self.data.rcpt_oks += 1;
                return self.write(b"250 2.1.5 OK\r\n").await;
            }
        }

        // Verify address
        let rcpt = self.data.rcpt_to.last().unwrap();
        let mut rcpt_members = None;
        if let Some(directory) = self
            .server
            .eval_if::<String, _>(
                &self.server.core.smtp.session.rcpt.directory,
                self,
                self.data.session_id,
            )
            .await
            .and_then(|name| self.server.get_directory(&name))
        {
            match directory.is_local_domain(&rcpt.domain).await {
                Ok(true) => {
                    match self
                        .server
                        .rcpt(directory, &rcpt.address_lcase, self.data.session_id)
                        .await
                    {
                        Ok(RcptType::Mailbox) => {}
                        Ok(RcptType::List(members)) => {
                            rcpt_members = Some(members);
                        }
                        Ok(RcptType::Invalid) => {
                            trc::event!(
                                Smtp(SmtpEvent::MailboxDoesNotExist),
                                SpanId = self.data.session_id,
                                To = rcpt.address_lcase.clone(),
                            );

                            let rcpt_to = self.data.rcpt_to.pop().unwrap().address_lcase;
                            return self
                                .rcpt_error(b"550 5.1.2 Mailbox does not exist.\r\n", rcpt_to)
                                .await;
                        }
                        Err(err) => {
                            trc::error!(
                                err.span_id(self.data.session_id)
                                    .caused_by(trc::location!())
                                    .details("Failed to verify address.")
                            );

                            self.data.rcpt_to.pop();
                            return self
                                .write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                                .await;
                        }
                    }
                }
                Ok(false) => {
                    if !self
                        .server
                        .eval_if(
                            &self.server.core.smtp.session.rcpt.relay,
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

                        let rcpt_to = self.data.rcpt_to.pop().unwrap().address_lcase;
                        return self
                            .rcpt_error(b"550 5.1.2 Relay not allowed.\r\n", rcpt_to)
                            .await;
                    }
                }
                Err(err) => {
                    trc::error!(
                        err.span_id(self.data.session_id)
                            .caused_by(trc::location!())
                            .details("Failed to verify address.")
                    );

                    self.data.rcpt_to.pop();
                    return self
                        .write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                        .await;
                }
            }
        } else if !self
            .server
            .eval_if(
                &self.server.core.smtp.session.rcpt.relay,
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

            let rcpt_to = self.data.rcpt_to.pop().unwrap().address_lcase;
            return self
                .rcpt_error(b"550 5.1.2 Relay not allowed.\r\n", rcpt_to)
                .await;
        }

        if self.is_allowed().await {
            // Greylist
            if let Some(greylist_duration) = self
                .server
                .core
                .spam
                .expiry
                .grey_list
                .filter(|_| self.data.authenticated_as.is_none())
            {
                let from_addr = self
                    .data
                    .mail_from
                    .as_ref()
                    .unwrap()
                    .address_lcase
                    .as_bytes();
                let to_addr = self.data.rcpt_to.last().unwrap().address_lcase.as_bytes();
                let mut key = Vec::with_capacity(from_addr.len() + to_addr.len() + 1);
                key.push(KV_GREYLIST);
                key.extend_from_slice(from_addr);
                key.extend_from_slice(to_addr);

                match self.server.in_memory_store().key_exists(key.clone()).await {
                    Ok(true) => (),
                    Ok(false) => {
                        match self
                            .server
                            .in_memory_store()
                            .key_set(KeyValue::new(key, vec![]).expires(greylist_duration))
                            .await
                        {
                            Ok(_) => {
                                let rcpt = self.data.rcpt_to.pop().unwrap();

                                trc::event!(
                                    Smtp(SmtpEvent::RcptToGreylisted),
                                    SpanId = self.data.session_id,
                                    To = rcpt.address_lcase,
                                );

                                return self
                                    .write(
                                        concat!(
                                            "452 4.2.2 Greylisted, please try ",
                                            "again in a few moments.\r\n"
                                        )
                                        .as_bytes(),
                                    )
                                    .await;
                            }
                            Err(err) => {
                                trc::error!(
                                    err.span_id(self.data.session_id)
                                        .caused_by(trc::location!())
                                        .details("Failed to set greylist.")
                                );
                            }
                        }
                    }
                    Err(err) => {
                        trc::error!(
                            err.span_id(self.data.session_id)
                                .caused_by(trc::location!())
                                .details("Failed to check greylist.")
                        );
                    }
                }
            }

            trc::event!(
                Smtp(SmtpEvent::RcptTo),
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
                .write(b"452 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await;
        }

        // Expand list
        if let Some(members) = rcpt_members {
            let list_addr = self.data.rcpt_to.pop().unwrap();
            let orcpt = format!("rfc822;{}", list_addr.address_lcase);
            for member in members {
                let mut member_addr = SessionAddress::new(member);
                if !self.data.rcpt_to.contains(&member_addr)
                    && member_addr.address_lcase != list_addr.address_lcase
                {
                    member_addr.dsn_info = orcpt.clone().into();
                    member_addr.flags = list_addr.flags;
                    self.data.rcpt_to.push(member_addr);
                }
            }
        }

        self.data.rcpt_oks += 1;
        self.write(b"250 2.1.5 OK\r\n").await
    }

    async fn rcpt_error(&mut self, response: &[u8], rcpt: String) -> Result<(), ()> {
        tokio::time::sleep(self.params.rcpt_errors_wait).await;
        self.data.rcpt_errors += 1;
        let has_too_many_errors = self.data.rcpt_errors >= self.params.rcpt_errors_max;

        match self
            .server
            .is_rcpt_fail2banned(self.data.remote_ip, &rcpt)
            .await
        {
            Ok(true) => {
                trc::event!(
                    Security(SecurityEvent::AbuseBan),
                    SpanId = self.data.session_id,
                    RemoteIp = self.data.remote_ip,
                    To = rcpt,
                );
            }
            Ok(false) => {
                if has_too_many_errors {
                    trc::event!(
                        Smtp(SmtpEvent::TooManyInvalidRcpt),
                        SpanId = self.data.session_id,
                        Limit = self.params.rcpt_errors_max,
                        To = rcpt,
                    );
                }
            }
            Err(err) => {
                trc::error!(
                    err.span_id(self.data.session_id)
                        .caused_by(trc::location!())
                        .details("Failed to check if IP should be banned.")
                );
            }
        }

        if !has_too_many_errors {
            self.write(response).await
        } else {
            self.write(b"451 4.3.0 Too many errors, disconnecting.\r\n")
                .await?;
            Err(())
        }
    }
}
