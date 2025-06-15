/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod crypto;
pub mod dkim;
pub mod dns;
#[cfg(feature = "enterprise")]
pub mod enterprise;
pub mod log;
pub mod principal;
pub mod queue;
pub mod reload;
pub mod report;
pub mod settings;
pub mod spam;
pub mod stores;
pub mod troubleshoot;

use std::{str::FromStr, sync::Arc};

use common::{Server, auth::AccessToken};
use crypto::CryptoHandler;
use directory::{Permission, backend::internal::manage};
use dkim::DkimManagement;
use dns::DnsManagement;
#[cfg(feature = "enterprise")]
use enterprise::telemetry::TelemetryApi;
use hyper::{Method, StatusCode, header};
use jmap::api::{ToJmapHttpResponse, ToRequestError};
use jmap_proto::error::request::RequestError;
use log::LogManagement;
use mail_parser::DateTime;
use principal::PrincipalManager;
use queue::QueueManagement;
use reload::ManageReload;
use report::ManageReports;
use serde::Serialize;
use settings::ManageSettings;
use spam::ManageSpamHandler;
use store::write::now;
use stores::ManageStore;
use troubleshoot::TroubleshootApi;

use crate::auth::oauth::auth::OAuthApiHandler;

use http_proto::{request::fetch_body, *};
use std::future::Future;

#[derive(Serialize)]
#[serde(tag = "error")]
#[serde(rename_all = "camelCase")]
pub enum ManagementApiError<'x> {
    FieldAlreadyExists {
        field: &'x str,
        value: &'x str,
    },
    FieldMissing {
        field: &'x str,
    },
    NotFound {
        item: &'x str,
    },
    Unsupported {
        details: &'x str,
    },
    AssertFailed,
    Other {
        details: &'x str,
        reason: Option<&'x str>,
    },
}

pub trait ManagementApi: Sync + Send {
    fn handle_api_manage_request(
        &self,
        req: &mut HttpRequest,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManagementApi for Server {
    #[allow(unused_variables)]
    async fn handle_api_manage_request(
        &self,
        req: &mut HttpRequest,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let body = fetch_body(req, 1024 * 1024, session.session_id).await;
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();

        match path.first().copied().unwrap_or_default() {
            "queue" => self.handle_manage_queue(req, path, &access_token).await,
            "settings" => {
                self.handle_manage_settings(req, path, body, &access_token)
                    .await
            }
            "reports" => self.handle_manage_reports(req, path, &access_token).await,
            "principal" => {
                self.handle_manage_principal(req, path, body, &access_token)
                    .await
            }
            "dns" => self.handle_manage_dns(req, path, &access_token).await,
            "store" => {
                self.handle_manage_store(req, path, body, session, &access_token)
                    .await
            }
            "reload" => self.handle_manage_reload(req, path, &access_token).await,
            "dkim" => {
                self.handle_manage_dkim(req, path, body, &access_token)
                    .await
            }
            "update" => self.handle_manage_update(req, path, &access_token).await,
            "logs" if req.method() == Method::GET => {
                self.handle_view_logs(req, &access_token).await
            }
            "spam-filter" => {
                self.handle_manage_spam(req, path, body, session, &access_token)
                    .await
            }
            "restart" if req.method() == Method::GET => {
                // Validate the access token
                access_token.assert_has_permission(Permission::Restart)?;

                Err(manage::unsupported("Restart is not yet supported"))
            }
            "oauth" => {
                // Validate the access token
                access_token.assert_has_permission(Permission::AuthenticateOauth)?;

                self.handle_oauth_api_request(access_token, body).await
            }
            "account" => match (path.get(1).copied().unwrap_or_default(), req.method()) {
                ("crypto", &Method::POST) => {
                    // Validate the access token
                    access_token.assert_has_permission(Permission::ManageEncryption)?;

                    self.handle_crypto_post(access_token, body).await
                }
                ("crypto", &Method::GET) => {
                    // Validate the access token
                    access_token.assert_has_permission(Permission::ManageEncryption)?;

                    self.handle_crypto_get(access_token).await
                }
                ("auth", &Method::GET) => {
                    // Validate the access token
                    access_token.assert_has_permission(Permission::ManagePasswords)?;

                    self.handle_account_auth_get(access_token).await
                }
                ("auth", &Method::POST) => {
                    // Validate the access token
                    access_token.assert_has_permission(Permission::ManagePasswords)?;

                    self.handle_account_auth_post(req, access_token, body).await
                }
                _ => Err(trc::ResourceEvent::NotFound.into_err()),
            },
            "troubleshoot" => {
                // Validate the access token
                access_token.assert_has_permission(Permission::Troubleshoot)?;

                self.handle_troubleshoot_api_request(req, path, &access_token, body)
                    .await
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            "telemetry" => {
                // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
                // Any attempt to modify, bypass, or disable this license validation mechanism
                // constitutes a severe violation of the Stalwart Enterprise License Agreement.
                // Such actions may result in immediate termination of your license, legal action,
                // and substantial financial penalties. Stalwart Labs LLC actively monitors for
                // unauthorized modifications and will pursue all available legal remedies against
                // violators to the fullest extent of the law, including but not limited to claims
                // for copyright infringement, breach of contract, and fraud.

                if self.core.is_enterprise_edition() {
                    self.handle_telemetry_api_request(req, path, &access_token)
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

pub(super) struct FutureTimestamp(u64);
pub(super) struct Timestamp(u64);

impl FromStr for Timestamp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(dt) = DateTime::parse_rfc3339(s) {
            Ok(Timestamp(dt.to_timestamp() as u64))
        } else {
            Err(())
        }
    }
}

impl FromStr for FutureTimestamp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(dt) = DateTime::parse_rfc3339(s) {
            let instant = dt.to_timestamp() as u64;
            if instant >= now() {
                return Ok(FutureTimestamp(instant));
            }
        }

        Err(())
    }
}

impl FutureTimestamp {
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

impl Timestamp {
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

pub trait ToManageHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl ToManageHttpResponse for &trc::Error {
    fn into_http_response(self) -> HttpResponse {
        match self.as_ref() {
            trc::EventType::Manage(cause) => {
                match cause {
                    trc::ManageEvent::MissingParameter => ManagementApiError::FieldMissing {
                        field: self.value_as_str(trc::Key::Key).unwrap_or_default(),
                    },
                    trc::ManageEvent::AlreadyExists => ManagementApiError::FieldAlreadyExists {
                        field: self.value_as_str(trc::Key::Key).unwrap_or_default(),
                        value: self.value_as_str(trc::Key::Value).unwrap_or_default(),
                    },
                    trc::ManageEvent::NotFound => ManagementApiError::NotFound {
                        item: self.value_as_str(trc::Key::Key).unwrap_or_default(),
                    },
                    trc::ManageEvent::NotSupported => ManagementApiError::Unsupported {
                        details: self
                            .value(trc::Key::Details)
                            .or_else(|| self.value(trc::Key::Reason))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Requested action is unsupported"),
                    },
                    trc::ManageEvent::AssertFailed => ManagementApiError::AssertFailed,
                    trc::ManageEvent::Error => ManagementApiError::Other {
                        reason: self.value_as_str(trc::Key::Reason),
                        details: self
                            .value_as_str(trc::Key::Details)
                            .unwrap_or("Unknown error"),
                    },
                }
            }
            .into_http_response(),
            trc::EventType::Auth(trc::AuthEvent::Failed) => {
                HttpResponse::new(StatusCode::UNAUTHORIZED)
                    .with_header(header::WWW_AUTHENTICATE, "Bearer realm=\"Stalwart Server\"")
                    .with_header(header::WWW_AUTHENTICATE, "Basic realm=\"Stalwart Server\"")
                    .with_content_type("application/problem+json")
                    .with_text_body(
                        serde_json::to_string(&RequestError::unauthorized()).unwrap_or_default(),
                    )
            }
            _ => self.to_request_error().into_http_response(),
        }
    }
}

impl ManagementApiError<'_> {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}
