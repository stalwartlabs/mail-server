/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::SystemTime};

use common::listener::SessionStream;
use mail_auth::common::resolver::ToReverseName;
use sieve::{runtime::Variable, Envelope, Sieve};
use smtp_proto::*;

use crate::{core::Session, inbound::AuthResult};

use super::{ScriptParameters, ScriptResult};

impl<T: SessionStream> Session<T> {
    pub fn build_script_parameters(&self, stage: &'static str) -> ScriptParameters<'_> {
        let (tls_version, tls_cipher) = self.stream.tls_version_and_cipher();
        let mut params = ScriptParameters::new()
            .set_variable("remote_ip", self.data.remote_ip.to_string())
            .set_variable("remote_ip.reverse", self.data.remote_ip.to_reverse_name())
            .set_variable("helo_domain", self.data.helo_domain.to_lowercase())
            .set_variable("authenticated_as", self.data.authenticated_as.clone())
            .set_variable(
                "now",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            )
            .set_variable(
                "spf.result",
                self.data
                    .spf_mail_from
                    .as_ref()
                    .map(|r| r.result().as_str())
                    .unwrap_or_default(),
            )
            .set_variable(
                "spf_ehlo.result",
                self.data
                    .spf_ehlo
                    .as_ref()
                    .map(|r| r.result().as_str())
                    .unwrap_or_default(),
            )
            .set_variable("tls.version", tls_version)
            .set_variable("tls.cipher", tls_cipher)
            .set_variable("stage", stage);
        if let Some(ip_rev) = &self.data.iprev {
            params = params.set_variable("iprev.result", ip_rev.result().as_str());
            if let Some(ptr) = ip_rev.ptr.as_ref().and_then(|addrs| addrs.first()) {
                params = params.set_variable(
                    "iprev.ptr",
                    ptr.strip_suffix('.').unwrap_or(ptr).to_lowercase(),
                );
            }
        }

        if let Some(mail_from) = &self.data.mail_from {
            params
                .envelope
                .push((Envelope::From, mail_from.address_lcase.to_string().into()));
            if let Some(env_id) = &mail_from.dsn_info {
                params
                    .envelope
                    .push((Envelope::Envid, env_id.to_lowercase().into()));
            }

            if stage != "data" {
                if let Some(rcpt) = self.data.rcpt_to.last() {
                    params
                        .envelope
                        .push((Envelope::To, rcpt.address_lcase.to_string().into()));
                    if let Some(orcpt) = &rcpt.dsn_info {
                        params
                            .envelope
                            .push((Envelope::Orcpt, orcpt.to_lowercase().into()));
                    }
                }
            } else {
                // Build recipients list
                let mut recipients = vec![];
                for rcpt in &self.data.rcpt_to {
                    recipients.push(Variable::from(rcpt.address_lcase.to_string()));
                }
                params.envelope.push((Envelope::To, recipients.into()));
            }

            if (mail_from.flags & MAIL_RET_FULL) != 0 {
                params.envelope.push((Envelope::Ret, "FULL".into()));
            } else if (mail_from.flags & MAIL_RET_HDRS) != 0 {
                params.envelope.push((Envelope::Ret, "HDRS".into()));
            }
            if (mail_from.flags & MAIL_BY_NOTIFY) != 0 {
                params.envelope.push((Envelope::ByMode, "N".into()));
            } else if (mail_from.flags & MAIL_BY_RETURN) != 0 {
                params.envelope.push((Envelope::ByMode, "R".into()));
            }

            if (mail_from.flags & MAIL_BODY_7BIT) != 0 {
                params = params.set_variable("param.body", "7bit");
            } else if (mail_from.flags & MAIL_BODY_8BITMIME) != 0 {
                params = params.set_variable("param.body", "8bitmime");
            } else if (mail_from.flags & MAIL_BODY_BINARYMIME) != 0 {
                params = params.set_variable("param.body", "binarymime");
            }

            if (mail_from.flags & MAIL_SMTPUTF8) != 0 {
                params = params.set_variable("param.smtputf8", Variable::Integer(1));
            }
            if (mail_from.flags & MAIL_REQUIRETLS) != 0 {
                params = params.set_variable("param.requiretls", Variable::Integer(1));
            }
        }

        params
    }

    pub async fn run_script(
        &self,
        script: Arc<Sieve>,
        params: ScriptParameters<'_>,
    ) -> ScriptResult {
        self.core
            .run_script(
                script,
                params
                    .with_envelope(&self.core.core, self, self.data.session_id)
                    .await,
                self.data.session_id,
            )
            .await
    }
}
