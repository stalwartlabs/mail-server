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

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use nlp::bayes::cache::BayesTokenCache;
use parking_lot::RwLock;
use sieve::{compiler::grammar::Capability, Compiler, Runtime};

use crate::{
    core::{SieveConfig, SieveCore},
    scripts::{functions::register_functions, plugins::RegisterSievePlugins},
};
use utils::{
    config::{utils::AsKey, Config},
    suffixlist::PublicSuffix,
};

use super::{resolver::ConfigResolver, ConfigContext};

pub trait ConfigSieve {
    fn parse_sieve(&self, ctx: &mut ConfigContext) -> super::Result<SieveCore>;
}

#[derive(Default)]
pub struct SieveContext {
    pub psl: PublicSuffix,
    pub bayes_cache: BayesTokenCache,
    pub remote_lists: RemoteLists,
}

pub struct RemoteLists {
    pub lists: RwLock<AHashMap<String, RemoteList>>,
}

pub struct RemoteList {
    pub entries: HashSet<String>,
    pub expires: Instant,
}

impl Default for RemoteLists {
    fn default() -> Self {
        Self {
            lists: RwLock::new(AHashMap::new()),
        }
    }
}

impl ConfigSieve for Config {
    fn parse_sieve(&self, ctx: &mut ConfigContext) -> super::Result<SieveCore> {
        // Register functions
        let mut fnc_map = register_functions().register_plugins();
        let sieve_ctx = SieveContext {
            psl: self.parse_public_suffix()?,
            bayes_cache: BayesTokenCache::new(
                self.property_or_static("bayes.cache.capacity", "8192")?,
                self.property_or_static("bayes.cache.ttl.positive", "1h")?,
                self.property_or_static("bayes.cache.ttl.negative", "1h")?,
            ),
            remote_lists: Default::default(),
        };

        // Allocate compiler and runtime
        let compiler = Compiler::new()
            .with_max_string_size(52428800)
            .with_max_variable_name_size(100)
            .with_max_nested_blocks(50)
            .with_max_nested_tests(50)
            .with_max_nested_foreverypart(10)
            .with_max_local_variables(8192)
            .with_max_header_size(10240)
            .with_max_includes(10)
            .with_no_capability_check(
                self.property_or_static("sieve.smtp.no-capability-check", "false")?,
            )
            .register_functions(&mut fnc_map);

        let mut runtime = Runtime::new_with_context(sieve_ctx)
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
                self.property_or_static("sieve.smtp.limits.variable-size", "52428800")?,
            )
            .with_max_header_size(10240)
            .with_valid_notification_uri("mailto")
            .with_valid_ext_lists(ctx.directory.lookups.keys().map(|k| k.to_string()))
            .with_functions(&mut fnc_map);

        if let Some(value) = self.property("sieve.smtp.limits.redirects")? {
            runtime.set_max_redirects(value);
        }
        if let Some(value) = self.property("sieve.smtp.limits.out-messages")? {
            runtime.set_max_out_messages(value);
        }
        if let Some(value) = self.property("sieve.smtp.limits.cpu")? {
            runtime.set_cpu_limit(value);
        }
        if let Some(value) = self.property("sieve.smtp.limits.nested-includes")? {
            runtime.set_max_nested_includes(value);
        }
        if let Some(value) = self.property("sieve.smtp.limits.received-headers")? {
            runtime.set_max_received_headers(value);
        }
        if let Some(value) = self.property::<Duration>("sieve.smtp.limits.duplicate-expiry")? {
            runtime.set_default_duplicate_expiry(value.as_secs());
        }
        let hostname = if let Some(hostname) = self.value("sieve.smtp.hostname") {
            hostname
        } else {
            self.value_require("server.hostname")?
        };
        runtime.set_local_hostname(hostname.to_string());

        // Parse scripts
        for id in self.sub_keys("sieve.smtp.scripts") {
            let key = ("sieve.smtp.scripts", id);

            let script = if !self.contains_key(key) {
                let mut script = Vec::new();
                for sub_key in self.sub_keys(key) {
                    script.extend(self.file_contents(sub_key)?);
                }
                script
            } else {
                self.file_contents(key)?
            };

            ctx.scripts.insert(
                id.to_string(),
                compiler
                    .compile(&script)
                    .map_err(|err| format!("Failed to compile Sieve script {id:?}: {err}"))?
                    .into(),
            );
        }

        // Parse DKIM signatures
        let mut sign = Vec::new();
        for (pos, id) in self.values("sieve.smtp.sign") {
            if let Some(dkim) = ctx.signers.get(id) {
                sign.push(dkim.clone());
            } else {
                return Err(format!(
                    "No DKIM signer found with id {:?} for key {:?}.",
                    id,
                    ("sieve.smtp.sign", pos).as_key()
                ));
            }
        }

        Ok(SieveCore {
            runtime,
            scripts: ctx.scripts.clone(),
            lookup: ctx.directory.lookups.clone(),
            config: SieveConfig {
                from_addr: self
                    .value("sieve.smtp.from-addr")
                    .map(|a| a.to_string())
                    .unwrap_or(format!("MAILER-DAEMON@{hostname}")),
                from_name: self
                    .value("sieve.smtp.from-name")
                    .unwrap_or("Mailer Daemon")
                    .to_string(),
                return_path: self
                    .value("sieve.smtp.return-path")
                    .unwrap_or_default()
                    .to_string(),
                sign,
                directories: ctx.directory.directories.clone(),
            },
        })
    }
}
