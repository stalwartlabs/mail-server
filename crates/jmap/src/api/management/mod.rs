/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod dkim;
pub mod domain;
#[cfg(feature = "enterprise")]
pub mod enterprise;
pub mod log;
pub mod principal;
pub mod queue;
pub mod reload;
pub mod report;
pub mod settings;
pub mod sieve;
pub mod stores;

use std::{borrow::Cow, str::FromStr, sync::Arc};

use directory::backend::internal::manage;
use hyper::Method;
use mail_parser::DateTime;
use serde::Serialize;
use store::write::now;

use super::{http::HttpSessionData, HttpRequest, HttpResponse};
use crate::{auth::AccessToken, JMAP};

#[derive(Serialize)]
#[serde(tag = "error")]
#[serde(rename_all = "camelCase")]
pub enum ManagementApiError<'x> {
    FieldAlreadyExists { field: &'x str, value: &'x str },
    FieldMissing { field: &'x str },
    NotFound { item: &'x str },
    Unsupported { details: &'x str },
    AssertFailed,
    Other { details: &'x str },
}

impl JMAP {
    #[allow(unused_variables)]
    pub async fn handle_api_manage_request(
        &self,
        req: &HttpRequest,
        body: Option<Vec<u8>>,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();
        let is_superuser = access_token.is_super_user();

        match path.first().copied().unwrap_or_default() {
            "queue" if is_superuser => self.handle_manage_queue(req, path).await,
            "settings" if is_superuser => self.handle_manage_settings(req, path, body).await,
            "reports" if is_superuser => self.handle_manage_reports(req, path).await,
            "principal" if is_superuser => self.handle_manage_principal(req, path, body).await,
            "domain" if is_superuser => self.handle_manage_domain(req, path).await,
            "store" if is_superuser => self.handle_manage_store(req, path, body, session).await,
            "reload" if is_superuser => self.handle_manage_reload(req, path).await,
            "dkim" if is_superuser => self.handle_manage_dkim(req, path, body).await,
            "update" if is_superuser => self.handle_manage_update(req, path).await,
            "logs" if is_superuser && req.method() == Method::GET => {
                self.handle_view_logs(req).await
            }
            "sieve" if is_superuser => self.handle_run_sieve(req, path, body).await,
            "restart" if is_superuser && req.method() == Method::GET => {
                Err(manage::unsupported("Restart is not yet supported"))
            }
            "oauth" => self.handle_oauth_api_request(access_token, body).await,
            "account" => match (path.get(1).copied().unwrap_or_default(), req.method()) {
                ("crypto", &Method::POST) => self.handle_crypto_post(access_token, body).await,
                ("crypto", &Method::GET) => self.handle_crypto_get(access_token).await,
                ("auth", &Method::GET) => self.handle_account_auth_get(access_token).await,
                ("auth", &Method::POST) => {
                    self.handle_account_auth_post(req, access_token, body).await
                }
                _ => Err(trc::ResourceEvent::NotFound.into_err()),
            },
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            "tracing" if is_superuser => {
                // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
                // Any attempt to modify, bypass, or disable this license validation mechanism
                // constitutes a severe violation of the Stalwart Enterprise License Agreement.
                // Such actions may result in immediate termination of your license, legal action,
                // and substantial financial penalties. Stalwart Labs Ltd. actively monitors for
                // unauthorized modifications and will pursue all available legal remedies against
                // violators to the fullest extent of the law, including but not limited to claims
                // for copyright infringement, breach of contract, and fraud.

                if self.core.is_enterprise_edition() {
                    self.handle_tracing_api_request(req, path, access_token.primary_id())
                        .await
                } else {
                    Err(manage::enterprise())
                }
            }
            // SPDX-SnippetEnd
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

pub fn decode_path_element(item: &str) -> Cow<'_, str> {
    // Bit hackish but avoids an extra dependency
    form_urlencoded::parse(item.as_bytes())
        .into_iter()
        .next()
        .map(|(k, _)| k)
        .unwrap_or_else(|| item.into())
}

pub(super) struct Timestamp(u64);

impl FromStr for Timestamp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(dt) = DateTime::parse_rfc3339(s) {
            let instant = dt.to_timestamp() as u64;
            if instant >= now() {
                return Ok(Timestamp(instant));
            }
        }

        Err(())
    }
}

impl Timestamp {
    pub fn into_inner(self) -> u64 {
        self.0
    }
}
