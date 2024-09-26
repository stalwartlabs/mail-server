/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use common::{config::smtp::auth::VerifyStrategy, listener::SessionStream};

use super::Session;

impl<T: SessionStream> Session<T> {
    pub async fn eval_session_params(&mut self) {
        let c = &self.server.core.smtp.session;
        self.data.bytes_left = self
            .server
            .eval_if(&c.transfer_limit, self, self.data.session_id)
            .await
            .unwrap_or(250 * 1024 * 1024);
        self.data.valid_until += self
            .server
            .eval_if(&c.duration, self, self.data.session_id)
            .await
            .unwrap_or_else(|| Duration::from_secs(15 * 60));

        self.params.timeout = self
            .server
            .eval_if(&c.timeout, self, self.data.session_id)
            .await
            .unwrap_or_else(|| Duration::from_secs(5 * 60));
        self.params.spf_ehlo = self
            .server
            .eval_if(
                &self.server.core.smtp.mail_auth.spf.verify_ehlo,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        self.params.spf_mail_from = self
            .server
            .eval_if(
                &self.server.core.smtp.mail_auth.spf.verify_mail_from,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        self.params.iprev = self
            .server
            .eval_if(
                &self.server.core.smtp.mail_auth.iprev.verify,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(VerifyStrategy::Relaxed);

        // Ehlo parameters
        let ec = &self.server.core.smtp.session.ehlo;
        self.params.ehlo_require = self
            .server
            .eval_if(&ec.require, self, self.data.session_id)
            .await
            .unwrap_or(true);
        self.params.ehlo_reject_non_fqdn = self
            .server
            .eval_if(&ec.reject_non_fqdn, self, self.data.session_id)
            .await
            .unwrap_or(true);

        // Auth parameters
        let ac = &self.server.core.smtp.session.auth;
        self.params.auth_directory = self
            .server
            .eval_if::<String, _>(&ac.directory, self, self.data.session_id)
            .await
            .and_then(|name| self.server.get_directory(&name))
            .cloned();
        self.params.auth_require = self
            .server
            .eval_if(&ac.require, self, self.data.session_id)
            .await
            .unwrap_or(false);
        self.params.auth_errors_max = self
            .server
            .eval_if(&ac.errors_max, self, self.data.session_id)
            .await
            .unwrap_or(3);
        self.params.auth_errors_wait = self
            .server
            .eval_if(&ac.errors_wait, self, self.data.session_id)
            .await
            .unwrap_or_else(|| Duration::from_secs(30));
        self.params.auth_match_sender = self
            .server
            .eval_if(&ac.must_match_sender, self, self.data.session_id)
            .await
            .unwrap_or(true);

        // VRFY/EXPN parameters
        let ec = &self.server.core.smtp.session.extensions;
        self.params.can_expn = self
            .server
            .eval_if(&ec.expn, self, self.data.session_id)
            .await
            .unwrap_or(false);
        self.params.can_vrfy = self
            .server
            .eval_if(&ec.vrfy, self, self.data.session_id)
            .await
            .unwrap_or(false);
    }

    pub async fn eval_post_auth_params(&mut self) {
        // Refresh VRFY/EXPN parameters
        let ec = &self.server.core.smtp.session.extensions;
        self.params.can_expn = self
            .server
            .eval_if(&ec.expn, self, self.data.session_id)
            .await
            .unwrap_or(false);
        self.params.can_vrfy = self
            .server
            .eval_if(&ec.vrfy, self, self.data.session_id)
            .await
            .unwrap_or(false);
        self.params.auth_match_sender = self
            .server
            .eval_if(
                &self.server.core.smtp.session.auth.must_match_sender,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(true);
    }

    pub async fn eval_rcpt_params(&mut self) {
        let rc = &self.server.core.smtp.session.rcpt;
        self.params.rcpt_errors_max = self
            .server
            .eval_if(&rc.errors_max, self, self.data.session_id)
            .await
            .unwrap_or(10);
        self.params.rcpt_errors_wait = self
            .server
            .eval_if(&rc.errors_wait, self, self.data.session_id)
            .await
            .unwrap_or_else(|| Duration::from_secs(30));
        self.params.rcpt_max = self
            .server
            .eval_if(&rc.max_recipients, self, self.data.session_id)
            .await
            .unwrap_or(100);
        self.params.rcpt_dsn = self
            .server
            .eval_if(
                &self.server.core.smtp.session.extensions.dsn,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(true);

        self.params.max_message_size = self
            .server
            .eval_if(
                &self.server.core.smtp.session.data.max_message_size,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(25 * 1024 * 1024);
    }
}
