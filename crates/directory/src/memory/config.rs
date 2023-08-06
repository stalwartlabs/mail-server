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
                        .map(|(_, v)| v.to_string())
                        .collect(),
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

            directory.parse_emails(config, (prefix.as_str(), "users", lookup_id), name)?;
        }

        for lookup_id in config.sub_keys((prefix.as_str(), "groups")) {
            let name = config
                .value_require((prefix.as_str(), "groups", lookup_id, "name"))?
                .to_string();
            directory.principals.insert(
                name.clone(),
                Principal {
                    name: name.clone(),
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

            directory.parse_emails(config, (prefix.as_str(), "groups", lookup_id), name)?;
        }

        directory
            .domains
            .extend(config.parse_lookup_list((&prefix, "lookup.domains"))?);

        Ok(Arc::new(directory))
    }
}

impl MemoryDirectory {
    fn parse_emails(
        &mut self,
        config: &Config,
        prefix: impl AsKey,
        name: String,
    ) -> utils::config::Result<()> {
        let prefix = prefix.as_key();
        let mut emails = Vec::new();

        for (pos, (_, email)) in config.values((prefix.as_str(), "email")).enumerate() {
            self.emails_to_names
                .entry(email.to_string())
                .or_default()
                .push(if pos > 0 {
                    EmailType::Alias(name.clone())
                } else {
                    EmailType::Primary(name.clone())
                });

            if let Some((_, domain)) = email.rsplit_once('@') {
                self.domains.insert(domain.to_lowercase());
            }

            emails.push(if pos > 0 {
                EmailType::Alias(email.to_lowercase())
            } else {
                EmailType::Primary(email.to_lowercase())
            });
        }
        for (_, email) in config.values((prefix.as_str(), "email-list")) {
            self.emails_to_names
                .entry(email.to_lowercase())
                .or_default()
                .push(EmailType::List(name.clone()));
            if let Some((_, domain)) = email.rsplit_once('@') {
                self.domains.insert(domain.to_lowercase());
            }
            emails.push(EmailType::List(email.to_lowercase()));
        }

        self.names_to_email.insert(name, emails);
        Ok(())
    }
}
