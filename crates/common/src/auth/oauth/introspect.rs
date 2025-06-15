/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};
use trc::{AddContext, AuthEvent, EventType};

use crate::{Server, auth::AccessToken};

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct OAuthIntrospect {
    #[serde(default)]
    pub active: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

impl Server {
    pub async fn introspect_access_token(
        &self,
        token: &str,
        access_token: &AccessToken,
    ) -> trc::Result<OAuthIntrospect> {
        match self.validate_access_token(None, token).await {
            Ok(token_info) => Ok(OAuthIntrospect {
                active: true,
                client_id: Some(token_info.client_id),
                username: if access_token.primary_id() == token_info.account_id {
                    access_token.name.clone()
                } else {
                    self.get_access_token(token_info.account_id)
                        .await
                        .caused_by(trc::location!())?
                        .name
                        .clone()
                }
                .into(),
                token_type: Some("bearer".into()),
                exp: Some(token_info.expiry as i64),
                iat: Some(token_info.issued_at as i64),
                ..Default::default()
            }),
            Err(err)
                if matches!(
                    err.event_type(),
                    EventType::Auth(AuthEvent::Error) | EventType::Auth(AuthEvent::TokenExpired)
                ) =>
            {
                Ok(OAuthIntrospect::default())
            }
            Err(err) => Err(err),
        }
    }
}
