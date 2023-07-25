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

use std::sync::Arc;

use utils::config::{utils::AsKey, Config};

use crate::{config::ConfigDirectory, Directory, DirectoryOptions, Principal, Type};

use super::{EmailType, MemoryDirectory};

fn parse_secret(value: &str) -> utils::config::Result<String> {
    match value.strip_prefix("file://") {
        None => Ok(value.to_string()),
        Some(path) => std::fs::read_to_string(path)
            .map_err(|err| format!("Failed to read {path:?} for user secret: {err}")),
    }
}

impl MemoryDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let mut directory = MemoryDirectory {
            opt: DirectoryOptions::from_config(config, prefix.clone())?,
            ..Default::default()
        };

        for lookup_id in config.sub_keys((prefix.as_str(), "users")) {
            let name = config
                .value_require((prefix.as_str(), "users", lookup_id, "name"))?
                .to_string();
            let mut typ = Type::Individual;
            let mut member_of = Vec::new();

            for (_, group) in config.values((prefix.as_str(), "users", lookup_id, "member-of")) {
                if !group.eq_ignore_ascii_case(&directory.opt.superuser_group) {
                    member_of.push(group.to_string());
                } else {
                    typ = Type::Superuser;
                }
            }

            directory.principals.insert(
                name.clone(),
                Principal {
                    name: name.clone(),
                    secrets: config
                        .values((prefix.as_str(), "users", lookup_id, "secret"))
                        .map(|(_, v)| parse_secret(v))
                        .collect::<Result<_, _>>()?,
                    typ,
                    description: config
                        .value((prefix.as_str(), "users", lookup_id, "description"))
                        .map(|v| v.to_string()),
                    quota: config
                        .property((prefix.as_str(), "users", lookup_id, "quota"))?
                        .unwrap_or(0),
                    member_of,
                },
            );
            let mut emails = Vec::new();
            for (pos, (_, email)) in config
                .values((prefix.as_str(), "users", lookup_id, "email"))
                .enumerate()
            {
                directory
                    .emails_to_names
                    .entry(email.to_string())
                    .or_default()
                    .push(if pos > 0 {
                        EmailType::Alias(name.clone())
                    } else {
                        EmailType::Primary(name.clone())
                    });

                if let Some((_, domain)) = email.rsplit_once('@') {
                    directory.domains.insert(domain.to_lowercase());
                }

                emails.push(if pos > 0 {
                    EmailType::Alias(email.to_lowercase())
                } else {
                    EmailType::Primary(email.to_lowercase())
                });
            }
            for (_, email) in config.values((prefix.as_str(), "users", lookup_id, "email-list")) {
                directory
                    .emails_to_names
                    .entry(email.to_lowercase())
                    .or_default()
                    .push(EmailType::List(name.clone()));
                if let Some((_, domain)) = email.rsplit_once('@') {
                    directory.domains.insert(domain.to_lowercase());
                }
                emails.push(EmailType::List(email.to_lowercase()));
            }
            directory.names_to_email.insert(name, emails);
        }

        for lookup_id in config.sub_keys((prefix.as_str(), "groups")) {
            let name = config
                .value_require((prefix.as_str(), "groups", lookup_id, "name"))?
                .to_string();
            directory.principals.insert(
                name.clone(),
                Principal {
                    name,
                    secrets: vec![],
                    typ: Type::Group,
                    description: config
                        .value((prefix.as_str(), "groups", lookup_id, "description"))
                        .map(|v| v.to_string()),
                    quota: config
                        .property((prefix.as_str(), "groups", lookup_id, "quota"))?
                        .unwrap_or(0),
                    member_of: config
                        .values((prefix.as_str(), "groups", lookup_id, "member-of"))
                        .map(|(_, v)| v.to_string())
                        .collect(),
                },
            );
        }

        directory
            .domains
            .extend(config.parse_lookup_list((&prefix, "lookup.domains"))?);

        Ok(Arc::new(directory))
    }
}
