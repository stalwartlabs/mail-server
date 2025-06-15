/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Duration};

use ahash::AHashMap;
use sieve::{Compiler, Runtime, Sieve, compiler::grammar::Capability};
use store::Stores;
use utils::config::Config;

use crate::{
    VERSION_PUBLIC,
    scripts::{
        functions::{register_functions_trusted, register_functions_untrusted},
        plugins::RegisterSievePlugins,
    },
};

use super::{if_block::IfBlock, smtp::SMTP_RCPT_TO_VARS, tokenizer::TokenMap};

pub struct Scripting {
    pub untrusted_compiler: Compiler,
    pub untrusted_runtime: Runtime,
    pub trusted_runtime: Runtime,
    pub from_addr: IfBlock,
    pub from_name: IfBlock,
    pub return_path: IfBlock,
    pub sign: IfBlock,
    pub trusted_scripts: AHashMap<String, Arc<Sieve>>,
    pub untrusted_scripts: AHashMap<String, Arc<Sieve>>,
}

impl Scripting {
    pub async fn parse(config: &mut Config, stores: &Stores) -> Self {
        // Parse untrusted compiler
        let mut fnc_map_untrusted = register_functions_untrusted().register_plugins_untrusted();
        let untrusted_compiler = Compiler::new()
            .with_max_script_size(
                config
                    .property("sieve.untrusted.limits.script-size")
                    .unwrap_or(1024 * 1024),
            )
            .with_max_string_size(
                config
                    .property("sieve.untrusted.limits.string-length")
                    .unwrap_or(4096),
            )
            .with_max_variable_name_size(
                config
                    .property("sieve.untrusted.limits.variable-name-length")
                    .unwrap_or(32),
            )
            .with_max_nested_blocks(
                config
                    .property("sieve.untrusted.limits.nested-blocks")
                    .unwrap_or(15),
            )
            .with_max_nested_tests(
                config
                    .property("sieve.untrusted.limits.nested-tests")
                    .unwrap_or(15),
            )
            .with_max_nested_foreverypart(
                config
                    .property("sieve.untrusted.limits.nested-foreverypart")
                    .unwrap_or(3),
            )
            .with_max_match_variables(
                config
                    .property("sieve.untrusted.limits.match-variables")
                    .unwrap_or(30),
            )
            .with_max_local_variables(
                config
                    .property("sieve.untrusted.limits.local-variables")
                    .unwrap_or(128),
            )
            .with_max_header_size(
                config
                    .property("sieve.untrusted.limits.header-size")
                    .unwrap_or(1024),
            )
            .with_max_includes(
                config
                    .property("sieve.untrusted.limits.includes")
                    .unwrap_or(3),
            )
            .register_functions(&mut fnc_map_untrusted);

        // Parse untrusted runtime
        let untrusted_runtime = Runtime::new()
            .with_functions(&mut fnc_map_untrusted)
            .with_max_nested_includes(
                config
                    .property("sieve.untrusted.limits.nested-includes")
                    .unwrap_or(3),
            )
            .with_cpu_limit(
                config
                    .property("sieve.untrusted.limits.cpu")
                    .unwrap_or(5000),
            )
            .with_max_variable_size(
                config
                    .property("sieve.untrusted.limits.variable-size")
                    .unwrap_or(4096),
            )
            .with_max_redirects(
                config
                    .property("sieve.untrusted.limits.redirects")
                    .unwrap_or(1),
            )
            .with_max_received_headers(
                config
                    .property("sieve.untrusted.limits.received-headers")
                    .unwrap_or(10),
            )
            .with_max_header_size(
                config
                    .property("sieve.untrusted.limits.header-size")
                    .unwrap_or(1024),
            )
            .with_max_out_messages(
                config
                    .property("sieve.untrusted.limits.outgoing-messages")
                    .unwrap_or(3),
            )
            .with_default_vacation_expiry(
                config
                    .property::<Duration>("sieve.untrusted.default-expiry.vacation")
                    .unwrap_or(Duration::from_secs(30 * 86400))
                    .as_secs(),
            )
            .with_default_duplicate_expiry(
                config
                    .property::<Duration>("sieve.untrusted.default-expiry.duplicate")
                    .unwrap_or(Duration::from_secs(7 * 86400))
                    .as_secs(),
            )
            .with_capability(Capability::Expressions)
            .without_capabilities(
                config
                    .values("sieve.untrusted.disable-capabilities")
                    .map(|(_, v)| v),
            )
            .with_valid_notification_uris({
                let values = config
                    .values("sieve.untrusted.notification-uris")
                    .map(|(_, v)| v.to_string())
                    .collect::<Vec<_>>();
                if !values.is_empty() {
                    values
                } else {
                    vec!["mailto".to_string()]
                }
            })
            .with_protected_headers({
                let values = config
                    .values("sieve.untrusted.protected-headers")
                    .map(|(_, v)| v.to_string())
                    .collect::<Vec<_>>();
                if !values.is_empty() {
                    values
                } else {
                    vec![
                        "Original-Subject".to_string(),
                        "Original-From".to_string(),
                        "Received".to_string(),
                        "Auto-Submitted".to_string(),
                    ]
                }
            })
            .with_vacation_default_subject(
                config
                    .value("sieve.untrusted.vacation.default-subject")
                    .unwrap_or("Automated reply")
                    .to_string(),
            )
            .with_vacation_subject_prefix(
                config
                    .value("sieve.untrusted.vacation.subject-prefix")
                    .unwrap_or("Auto: ")
                    .to_string(),
            )
            .with_env_variable("name", "Stalwart Server")
            .with_env_variable("version", VERSION_PUBLIC)
            .with_env_variable("location", "MS")
            .with_env_variable("phase", "during");

        // Parse trusted compiler and runtime
        let mut fnc_map_trusted = register_functions_trusted().register_plugins_trusted();

        // Allocate compiler and runtime
        let trusted_compiler = Compiler::new()
            .with_max_string_size(52428800)
            .with_max_variable_name_size(100)
            .with_max_nested_blocks(50)
            .with_max_nested_tests(50)
            .with_max_nested_foreverypart(10)
            .with_max_local_variables(8192)
            .with_max_header_size(10240)
            .with_max_includes(10)
            .with_no_capability_check(
                config
                    .property_or_default("sieve.trusted.no-capability-check", "true")
                    .unwrap_or(true),
            )
            .register_functions(&mut fnc_map_trusted);

        let mut trusted_runtime = Runtime::new()
            .without_capabilities([
                Capability::FileInto,
                Capability::Vacation,
                Capability::VacationSeconds,
                Capability::Fcc,
                Capability::Mailbox,
                Capability::MailboxId,
                Capability::MboxMetadata,
                Capability::ServerMetadata,
                Capability::ImapSieve,
                Capability::Duplicate,
            ])
            .with_capability(Capability::Expressions)
            .with_capability(Capability::While)
            .with_max_variable_size(
                config
                    .property_or_default("sieve.trusted.limits.variable-size", "52428800")
                    .unwrap_or(52428800),
            )
            .with_max_header_size(10240)
            .with_valid_notification_uri("mailto")
            .with_valid_ext_lists(stores.in_memory_stores.keys().map(|k| k.to_string()))
            .with_functions(&mut fnc_map_trusted)
            .with_max_redirects(
                config
                    .property_or_default("sieve.trusted.limits.redirects", "3")
                    .unwrap_or(3),
            )
            .with_max_out_messages(
                config
                    .property_or_default("sieve.trusted.limits.out-messages", "5")
                    .unwrap_or(5),
            )
            .with_cpu_limit(
                config
                    .property_or_default("sieve.trusted.limits.cpu", "1048576")
                    .unwrap_or(1048576),
            )
            .with_max_nested_includes(
                config
                    .property_or_default("sieve.trusted.limits.nested-includes", "5")
                    .unwrap_or(5),
            )
            .with_max_received_headers(
                config
                    .property_or_default("sieve.trusted.limits.received-headers", "50")
                    .unwrap_or(50),
            )
            .with_default_duplicate_expiry(
                config
                    .property_or_default::<Duration>("sieve.trusted.limits.duplicate-expiry", "7d")
                    .unwrap_or_else(|| Duration::from_secs(604800))
                    .as_secs(),
            );

        let hostname = config
            .value("sieve.trusted.hostname")
            .or_else(|| config.value("server.hostname"))
            .unwrap_or("localhost")
            .to_string();
        trusted_runtime.set_local_hostname(hostname.clone());

        // Parse trusted scripts
        let mut trusted_scripts = AHashMap::new();
        for id in config
            .sub_keys("sieve.trusted.scripts", ".contents")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            match trusted_compiler.compile(
                config
                    .value(("sieve.trusted.scripts", id.as_str(), "contents"))
                    .unwrap()
                    .as_bytes(),
            ) {
                Ok(compiled) => {
                    trusted_scripts.insert(id, compiled.into());
                }
                Err(err) => config.new_build_error(
                    ("sieve.trusted.scripts", id.as_str(), "contents"),
                    format!("Failed to compile trusted Sieve script: {err}"),
                ),
            }
        }

        // Parse untrusted scripts
        let mut untrusted_scripts = AHashMap::new();
        for id in config
            .sub_keys("sieve.untrusted.scripts", ".contents")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            match untrusted_compiler.compile(
                config
                    .value(("sieve.untrusted.scripts", id.as_str(), "contents"))
                    .unwrap()
                    .as_bytes(),
            ) {
                Ok(compiled) => {
                    untrusted_scripts.insert(id, compiled.into());
                }
                Err(err) => config.new_build_error(
                    ("sieve.untrusted.scripts", id.as_str(), "contents"),
                    format!("Failed to compile untrusted Sieve script: {err}"),
                ),
            }
        }

        let token_map = TokenMap::default().with_variables(SMTP_RCPT_TO_VARS);

        Scripting {
            untrusted_compiler,
            untrusted_runtime,
            trusted_runtime,
            from_addr: IfBlock::try_parse(config, "sieve.trusted.from-addr", &token_map)
                .unwrap_or_else(|| {
                    IfBlock::new::<()>(
                        "sieve.trusted.from-addr",
                        [],
                        "'MAILER-DAEMON@' + config_get('report.domain')",
                    )
                }),
            from_name: IfBlock::try_parse(config, "sieve.trusted.from-name", &token_map)
                .unwrap_or_else(|| {
                    IfBlock::new::<()>("sieve.trusted.from-name", [], "'Automated Message'")
                }),
            return_path: IfBlock::try_parse(config, "sieve.trusted.return-path", &token_map)
                .unwrap_or_else(|| IfBlock::empty("sieve.trusted.return-path")),
            sign: IfBlock::try_parse(config, "sieve.trusted.sign", &token_map).unwrap_or_else(
                || {
                    IfBlock::new::<()>(
                        "sieve.trusted.sign",
                        [],
                        concat!(
                            "['rsa-' + config_get('report.domain'), ",
                            "'ed25519-' + config_get('report.domain')]"
                        ),
                    )
                },
            ),
            untrusted_scripts,
            trusted_scripts,
        }
    }
}

impl Default for Scripting {
    fn default() -> Self {
        Scripting {
            untrusted_compiler: Compiler::new(),
            untrusted_runtime: Runtime::new(),
            trusted_runtime: Runtime::new(),
            from_addr: IfBlock::new::<()>(
                "sieve.trusted.from-addr",
                [],
                "'MAILER-DAEMON@' + config_get('report.domain')",
            ),
            from_name: IfBlock::new::<()>("sieve.trusted.from-name", [], "'Mailer Daemon'"),
            return_path: IfBlock::empty("sieve.trusted.return-path"),
            sign: IfBlock::new::<()>(
                "sieve.trusted.sign",
                [],
                concat!(
                    "['rsa-' + config_get('report.domain'), ",
                    "'ed25519-' + config_get('report.domain')]"
                ),
            ),
            untrusted_scripts: AHashMap::new(),
            trusted_scripts: AHashMap::new(),
        }
    }
}

impl Clone for Scripting {
    fn clone(&self) -> Self {
        Self {
            untrusted_compiler: self.untrusted_compiler.clone(),
            untrusted_runtime: self.untrusted_runtime.clone(),
            trusted_runtime: self.trusted_runtime.clone(),
            from_addr: self.from_addr.clone(),
            from_name: self.from_name.clone(),
            return_path: self.return_path.clone(),
            sign: self.sign.clone(),
            trusted_scripts: self.trusted_scripts.clone(),
            untrusted_scripts: self.untrusted_scripts.clone(),
        }
    }
}
