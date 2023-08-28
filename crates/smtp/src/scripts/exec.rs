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

use std::sync::Arc;

use sieve::{Envelope, Sieve};
use smtp_proto::{MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_RET_FULL, MAIL_RET_HDRS};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
};

use crate::{core::Session, inbound::AuthResult};

use super::{ScriptParameters, ScriptResult};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn build_script_parameters(&self) -> ScriptParameters {
        let mut params = ScriptParameters::new()
            .set_variable("remote_ip", self.data.remote_ip.to_string())
            .set_variable("helo_domain", self.data.helo_domain.to_string())
            .set_variable("authenticated_as", self.data.authenticated_as.clone())
            .set_variable(
                "spf",
                self.data
                    .spf_mail_from
                    .as_ref()
                    .map(|r| r.result().as_str())
                    .unwrap_or_default(),
            )
            .set_variable(
                "spf_ehlo",
                self.data
                    .spf_ehlo
                    .as_ref()
                    .map(|r| r.result().as_str())
                    .unwrap_or_default(),
            )
            .set_variable(
                "iprev",
                self.data
                    .iprev
                    .as_ref()
                    .map(|r| r.result().as_str())
                    .unwrap_or_default(),
            );

        if let Some(mail_from) = &self.data.mail_from {
            params
                .envelope
                .push((Envelope::From, mail_from.address.clone().into()));
            if let Some(env_id) = &mail_from.dsn_info {
                params
                    .envelope
                    .push((Envelope::Envid, env_id.clone().into()));
            }
            if let Some(rcpt) = self.data.rcpt_to.last() {
                params
                    .envelope
                    .push((Envelope::To, rcpt.address.clone().into()));
                if let Some(orcpt) = &rcpt.dsn_info {
                    params
                        .envelope
                        .push((Envelope::Orcpt, orcpt.clone().into()));
                }
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
        }

        params
    }

    pub async fn run_script(&self, script: Arc<Sieve>, params: ScriptParameters) -> ScriptResult {
        let core = self.core.clone();
        let span = self.span.clone();

        let handle = Handle::current();
        self.core
            .spawn_worker(move || core.run_script_blocking(script, params, handle, span))
            .await
            .unwrap_or(ScriptResult::Accept {
                modifications: vec![],
            })
    }
}
