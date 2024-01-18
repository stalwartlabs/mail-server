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

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::VerifyStrategy;

use super::Session;

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn eval_session_params(&mut self) {
        let c = &self.core.session.config;
        self.data.bytes_left = self
            .core
            .eval_if(&c.transfer_limit, self)
            .await
            .unwrap_or(250 * 1024 * 1024);
        self.data.valid_until += self
            .core
            .eval_if(&c.duration, self)
            .await
            .unwrap_or_else(|| Duration::from_secs(15 * 60));

        self.params.timeout = self
            .core
            .eval_if(&c.timeout, self)
            .await
            .unwrap_or_else(|| Duration::from_secs(5 * 60));
        self.params.spf_ehlo = self
            .core
            .eval_if(&self.core.mail_auth.spf.verify_ehlo, self)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        self.params.spf_mail_from = self
            .core
            .eval_if(&self.core.mail_auth.spf.verify_mail_from, self)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        self.params.iprev = self
            .core
            .eval_if(&self.core.mail_auth.iprev.verify, self)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);

        // Ehlo parameters
        let ec = &self.core.session.config.ehlo;
        self.params.ehlo_require = self.core.eval_if(&ec.require, self).await.unwrap_or(true);
        self.params.ehlo_reject_non_fqdn = self
            .core
            .eval_if(&ec.reject_non_fqdn, self)
            .await
            .unwrap_or(true);

        // Auth parameters
        let ac = &self.core.session.config.auth;
        self.params.auth_directory = self
            .core
            .eval_if::<String, _>(&ac.directory, self)
            .await
            .and_then(|name| self.core.get_directory(&name))
            .cloned();
        self.params.auth_require = self.core.eval_if(&ac.require, self).await.unwrap_or(false);
        self.params.auth_errors_max = self.core.eval_if(&ac.errors_max, self).await.unwrap_or(3);
        self.params.auth_errors_wait = self
            .core
            .eval_if(&ac.errors_wait, self)
            .await
            .unwrap_or_else(|| Duration::from_secs(30));
        self.params.auth_plain_text = self
            .core
            .eval_if(&ac.allow_plain_text, self)
            .await
            .unwrap_or(false);
        self.params.auth_match_sender = self
            .core
            .eval_if(&ac.must_match_sender, self)
            .await
            .unwrap_or(true);

        // VRFY/EXPN parameters
        let ec = &self.core.session.config.extensions;
        self.params.can_expn = self.core.eval_if(&ec.expn, self).await.unwrap_or(false);
        self.params.can_vrfy = self.core.eval_if(&ec.vrfy, self).await.unwrap_or(false);
    }

    pub async fn eval_post_auth_params(&mut self) {
        // Refresh VRFY/EXPN parameters
        let ec = &self.core.session.config.extensions;
        self.params.can_expn = self.core.eval_if(&ec.expn, self).await.unwrap_or(false);
        self.params.can_vrfy = self.core.eval_if(&ec.vrfy, self).await.unwrap_or(false);
    }

    pub async fn eval_rcpt_params(&mut self) {
        let rc = &self.core.session.config.rcpt;
        self.params.rcpt_errors_max = self.core.eval_if(&rc.errors_max, self).await.unwrap_or(10);
        self.params.rcpt_errors_wait = self
            .core
            .eval_if(&rc.errors_wait, self)
            .await
            .unwrap_or_else(|| Duration::from_secs(30));
        self.params.rcpt_max = self
            .core
            .eval_if(&rc.max_recipients, self)
            .await
            .unwrap_or(100);
        self.params.rcpt_dsn = self
            .core
            .eval_if(&self.core.session.config.extensions.dsn, self)
            .await
            .unwrap_or(true);

        self.params.max_message_size = self
            .core
            .eval_if(&self.core.session.config.data.max_message_size, self)
            .await
            .unwrap_or(25 * 1024 * 1024);
    }
}
