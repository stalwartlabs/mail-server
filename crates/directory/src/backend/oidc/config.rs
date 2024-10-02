/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::time::Duration;

use base64::{engine::general_purpose, Engine};
use store::Store;
use utils::config::{utils::AsKey, Config};

use super::{Authentication, EndpointType, OpenIdConfig, OpenIdDirectory};

impl OpenIdDirectory {
    pub fn from_config(config: &mut Config, prefix: impl AsKey, data_store: Store) -> Option<Self> {
        let prefix = prefix.as_key();
        let endpoint_type = match config.value_require((&prefix, "endpoint.method"))? {
            "introspect" => match config.value_require((&prefix, "auth.method"))? {
                #[allow(clippy::to_string_in_format_args)]
                "basic" => EndpointType::Introspect(Authentication::Header(format!(
                    "Basic {}",
                    general_purpose::STANDARD.encode(
                        format!(
                            "{}:{}",
                            config
                                .value_require((&prefix, "auth.username"))?
                                .to_string(),
                            config.value_require((&prefix, "auth.secret"))?
                        )
                        .as_bytes()
                    )
                ))),
                "token" => EndpointType::Introspect(Authentication::Header(format!(
                    "Bearer {}",
                    config.value_require((&prefix, "auth.token"))?
                ))),
                "user-token" => EndpointType::Introspect(Authentication::Bearer),
                "none" => EndpointType::Introspect(Authentication::None),
                _ => {
                    config.new_build_error(
                        (&prefix, "auth.method"),
                        "Invalid authentication method, must be 'header', 'bearer' or 'none'",
                    );
                    return None;
                }
            },
            "userinfo" => EndpointType::UserInfo,
            _ => {
                config.new_build_error(
                    (&prefix, "endpoint.method"),
                    "Invalid endpoint method, must be 'introspect' or 'userinfo'",
                );
                return None;
            }
        };

        Some(OpenIdDirectory {
            config: OpenIdConfig {
                endpoint: config.value_require((&prefix, "endpoint.url"))?.to_string(),
                endpoint_type,
                endpoint_timeout: config
                    .property_or_default::<Duration>((&prefix, "timeout"), "30s")
                    .unwrap_or_else(|| Duration::from_secs(30)),
                email_field: config.value_require((&prefix, "fields.email"))?.to_string(),
                username_field: config
                    .value((&prefix, "fields.username"))
                    .map(|v| v.to_string()),
                full_name_field: config
                    .value((&prefix, "fields.full-name"))
                    .map(|v| v.to_string()),
            },
            data_store,
        })
    }
}
