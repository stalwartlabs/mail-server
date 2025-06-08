/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use ldap3::LdapConnSettings;
use store::Store;
use utils::config::{Config, utils::AsKey};

use crate::core::config::build_pool;

use super::{
    AuthBind, Bind, LdapConnectionManager, LdapDirectory, LdapFilter, LdapFilterItem, LdapMappings,
};

impl LdapDirectory {
    pub fn from_config(config: &mut Config, prefix: impl AsKey, data_store: Store) -> Option<Self> {
        let prefix = prefix.as_key();
        let bind_dn = if let Some(dn) = config.value((&prefix, "bind.dn")) {
            Bind::new(
                dn.to_string(),
                config.value_require((&prefix, "bind.secret"))?.to_string(),
            )
            .into()
        } else {
            None
        };

        let manager = LdapConnectionManager::new(
            config.value_require((&prefix, "url"))?.to_string(),
            LdapConnSettings::new()
                .set_conn_timeout(
                    config
                        .property_or_default((&prefix, "timeout"), "30s")
                        .unwrap_or_else(|| Duration::from_secs(30)),
                )
                .set_starttls(
                    config
                        .property_or_default((&prefix, "tls.enable"), "false")
                        .unwrap_or_default(),
                )
                .set_no_tls_verify(
                    config
                        .property_or_default((&prefix, "tls.allow-invalid-certs"), "false")
                        .unwrap_or_default(),
                ),
            bind_dn,
        );

        let mut mappings = LdapMappings {
            base_dn: config.value_require((&prefix, "base-dn"))?.to_string(),
            filter_name: LdapFilter::from_config(config, (&prefix, "filter.name")),
            filter_email: LdapFilter::from_config(config, (&prefix, "filter.email")),
            attr_name: config
                .values((&prefix, "attributes.name"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_groups: config
                .values((&prefix, "attributes.groups"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_type: config
                .values((&prefix, "attributes.class"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_description: config
                .values((&prefix, "attributes.description"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_secret: config
                .values((&prefix, "attributes.secret"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_secret_changed: config
                .values((&prefix, "attributes.secret-changed"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_email_address: config
                .values((&prefix, "attributes.email"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_quota: config
                .values((&prefix, "attributes.quota"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_email_alias: config
                .values((&prefix, "attributes.email-alias"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attrs_principal: vec!["objectClass".to_string()],
        };

        for attr in [
            &mappings.attr_name,
            &mappings.attr_type,
            &mappings.attr_description,
            &mappings.attr_secret,
            &mappings.attr_secret_changed,
            &mappings.attr_quota,
            &mappings.attr_groups,
            &mappings.attr_email_address,
            &mappings.attr_email_alias,
        ] {
            mappings
                .attrs_principal
                .extend(attr.iter().filter(|a| !a.is_empty()).cloned());
        }

        let auth_bind = match config
            .value((&prefix, "bind.auth.method"))
            .unwrap_or("default")
        {
            "template" => AuthBind::Template {
                template: LdapFilter::from_config(config, (&prefix, "bind.auth.template")),
                can_search: config
                    .property_or_default::<bool>((&prefix, "bind.auth.search"), "true")
                    .unwrap_or(true),
            },
            "lookup" => AuthBind::Lookup,
            "default" => AuthBind::None,
            unknown => {
                config.new_parse_error(
                    (&prefix, "bind.auth.method"),
                    format!("Unknown LDAP bind method: {unknown}"),
                );
                return None;
            }
        };

        Some(LdapDirectory {
            mappings,
            pool: build_pool(config, &prefix, manager)
                .map_err(|e| {
                    config.new_parse_error(prefix, format!("Failed to build LDAP pool: {e:?}"))
                })
                .ok()?,
            auth_bind,
            data_store,
        })
    }
}

impl LdapFilter {
    fn from_config(config: &mut Config, key: impl AsKey) -> Self {
        if let Some(value) = config.value(key.clone()) {
            let mut filter = Vec::new();
            let mut token = String::new();
            let mut value = value.chars();

            while let Some(ch) = value.next() {
                match ch {
                    '?' => {
                        // For backwards compatibility, we treat '?' as a placeholder for the full value.
                        if !token.is_empty() {
                            filter.push(LdapFilterItem::Static(token));
                            token = String::new();
                        }
                        filter.push(LdapFilterItem::Full);
                    }
                    '{' => {
                        if !token.is_empty() {
                            filter.push(LdapFilterItem::Static(token));
                            token = String::new();
                        }
                        for ch in value.by_ref() {
                            if ch == '}' {
                                break;
                            } else {
                                token.push(ch);
                            }
                        }
                        match token.as_str() {
                            "user" | "username" | "email" => filter.push(LdapFilterItem::Full),
                            "local" => filter.push(LdapFilterItem::LocalPart),
                            "domain" => filter.push(LdapFilterItem::DomainPart),
                            _ => {
                                config.new_parse_error(
                                    key,
                                    format!("Unknown LDAP filter placeholder: {}", token),
                                );
                                return Self::default();
                            }
                        }
                        token.clear();
                    }
                    _ => token.push(ch),
                }
            }

            if !token.is_empty() {
                filter.push(LdapFilterItem::Static(token));
            }

            if filter.len() >= 2 {
                return LdapFilter { filter };
            } else {
                config.new_parse_error(
                    key,
                    format!("Missing parameter placeholders in value {:?}", value),
                );
            }
        }

        Self::default()
    }
}
