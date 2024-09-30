/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use biscuit::{jws::RegisteredHeader, ClaimsSet, RegisteredClaims, SingleOrMultiple, JWT};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use store::write::now;

use crate::Server;

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Userinfo {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(default, deserialize_with = "any_bool")]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub email_verified: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

impl Server {
    pub fn issue_id_token(
        &self,
        subject: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> trc::Result<String> {
        let now = now() as i64;

        JWT::new_decoded(
            From::from(RegisteredHeader {
                algorithm: self.core.oauth.oidc_signature_algorithm,
                key_id: Some("default".into()),
                ..Default::default()
            }),
            ClaimsSet::<()> {
                registered: RegisteredClaims {
                    issuer: Some(issuer.into()),
                    subject: Some(subject.into()),
                    audience: Some(SingleOrMultiple::Single(audience.into())),
                    not_before: Some(now.into()),
                    issued_at: Some(now.into()),
                    expiry: Some((now + self.core.oauth.oidc_expiry_id_token as i64).into()),
                    ..Default::default()
                },
                private: (),
            },
        )
        .into_encoded(&self.core.oauth.oidc_signing_secret)
        .map(|token| token.unwrap_encoded().to_string())
        .map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .reason(err)
                .details("Failed to encode ID token")
        })
    }
}

fn any_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    struct AnyBoolVisitor;

    impl<'de> Visitor<'de> for AnyBoolVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a boolean value")
        }

        fn visit_str<E>(self, value: &str) -> Result<bool, E>
        where
            E: de::Error,
        {
            match value {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(E::custom(format!("Unknown boolean: {value}"))),
            }
        }

        fn visit_bool<E>(self, value: bool) -> Result<bool, E>
        where
            E: de::Error,
        {
            Ok(value)
        }
    }

    deserializer.deserialize_any(AnyBoolVisitor)
}
