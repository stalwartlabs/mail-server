/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::expr::{if_block::IfBlock, tokenizer::TokenMap};
use utils::config::{Config, Rate};

use super::*;

#[derive(Clone)]
pub struct Network {
    pub node_id: u64,
    pub security: Security,
    pub contact_form: Option<ContactForm>,
    pub http_response_url: IfBlock,
    pub http_allowed_endpoint: IfBlock,
}

#[derive(Clone)]
pub struct ContactForm {
    pub rcpt_to: Vec<String>,
    pub max_size: usize,
    pub rate: Option<Rate>,
    pub validate_domain: bool,
    pub from_email: FieldOrDefault,
    pub from_subject: FieldOrDefault,
    pub from_name: FieldOrDefault,
    pub field_honey_pot: Option<String>,
}

#[derive(Clone)]
pub struct FieldOrDefault {
    pub field: Option<String>,
    pub default: String,
}

pub(crate) const HTTP_VARS: &[u32; 11] = &[
    V_LISTENER,
    V_REMOTE_IP,
    V_REMOTE_PORT,
    V_LOCAL_IP,
    V_LOCAL_PORT,
    V_PROTOCOL,
    V_TLS,
    V_URL,
    V_URL_PATH,
    V_HEADERS,
    V_METHOD,
];

impl Default for Network {
    fn default() -> Self {
        Self {
            security: Default::default(),
            contact_form: None,
            node_id: 0,
            http_response_url: IfBlock::new::<()>(
                "server.http.url",
                [],
                "protocol + '://' + key_get('default', 'hostname') + ':' + local_port",
            ),
            http_allowed_endpoint: IfBlock::new::<()>("server.http.allowed-endpoint", [], "200"),
        }
    }
}

impl ContactForm {
    pub fn parse(config: &mut Config) -> Option<Self> {
        if !config
            .property_or_default::<bool>("form.enable", "false")
            .unwrap_or_default()
        {
            return None;
        }

        let form = ContactForm {
            rcpt_to: config
                .values("form.deliver-to")
                .filter_map(|(_, addr)| {
                    if addr.contains('@') && addr.contains('.') {
                        Some(addr.trim().to_lowercase())
                    } else {
                        None
                    }
                })
                .collect(),
            max_size: config.property("form.max-size").unwrap_or(100 * 1024),
            validate_domain: config
                .property_or_default::<bool>("form.validate-domain", "true")
                .unwrap_or(true),
            from_email: FieldOrDefault::parse(config, "form.email", "postmaster@localhost"),
            from_subject: FieldOrDefault::parse(config, "form.subject", "Contact form submission"),
            from_name: FieldOrDefault::parse(config, "form.name", "Anonymous"),
            field_honey_pot: config.value("form.honey-pot.field").map(|v| v.to_string()),
            rate: config
                .property_or_default::<Option<Rate>>("form.rate-limit", "5/1h")
                .unwrap_or_default(),
        };

        if !form.rcpt_to.is_empty() {
            Some(form)
        } else {
            config.new_build_error("form.deliver-to", "No valid email addresses found");
            None
        }
    }
}

impl FieldOrDefault {
    pub fn parse(config: &mut Config, key: &str, default: &str) -> Self {
        FieldOrDefault {
            field: config.value((key, "field")).map(|s| s.to_string()),
            default: config
                .value((key, "default"))
                .unwrap_or(default)
                .to_string(),
        }
    }
}

impl Network {
    pub fn parse(config: &mut Config) -> Self {
        let mut network = Network {
            node_id: config.property("cluster.node-id").unwrap_or_default(),
            security: Security::parse(config),
            contact_form: ContactForm::parse(config),
            ..Default::default()
        };
        let token_map = &TokenMap::default().with_variables(HTTP_VARS);

        for (value, key) in [
            (&mut network.http_response_url, "server.http.url"),
            (
                &mut network.http_allowed_endpoint,
                "server.http.allowed-endpoint",
            ),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        network
    }
}
