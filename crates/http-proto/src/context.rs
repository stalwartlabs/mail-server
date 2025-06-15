/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    expr::{functions::ResolveVariable, *},
};
use compact_str::{ToCompactString, format_compact};
use hyper::StatusCode;

use crate::{HttpContext, HttpRequest, HttpSessionData};

impl<'x> HttpContext<'x> {
    pub fn new(session: &'x HttpSessionData, req: &'x HttpRequest) -> Self {
        Self { session, req }
    }

    pub async fn resolve_response_url(&self, server: &Server) -> String {
        server
            .eval_if(
                &server.core.network.http_response_url,
                self,
                self.session.session_id,
            )
            .await
            .unwrap_or_else(|| {
                format!(
                    "http{}://{}:{}",
                    if self.session.is_tls { "s" } else { "" },
                    self.session.local_ip,
                    self.session.local_port
                )
            })
    }

    pub async fn has_endpoint_access(&self, server: &Server) -> StatusCode {
        server
            .eval_if(
                &server.core.network.http_allowed_endpoint,
                self,
                self.session.session_id,
            )
            .await
            .unwrap_or(StatusCode::OK)
    }
}

impl ResolveVariable for HttpContext<'_> {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_REMOTE_IP => self.session.remote_ip.to_compact_string().into(),
            V_REMOTE_PORT => self.session.remote_port.into(),
            V_LOCAL_IP => self.session.local_ip.to_compact_string().into(),
            V_LOCAL_PORT => self.session.local_port.into(),
            V_TLS => self.session.is_tls.into(),
            V_PROTOCOL => if self.session.is_tls { "https" } else { "http" }.into(),
            V_LISTENER => self.session.instance.id.as_str().into(),
            V_URL => self.req.uri().to_compact_string().into(),
            V_URL_PATH => self.req.uri().path().into(),
            V_METHOD => self.req.method().as_str().into(),
            V_HEADERS => self
                .req
                .headers()
                .iter()
                .map(|(h, v)| {
                    Variable::String(
                        format_compact!("{}: {}", h.as_str(), v.to_str().unwrap_or_default())
                            .into(),
                    )
                })
                .collect::<Vec<_>>()
                .into(),
            _ => Variable::default(),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}
