/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::Store;
use utils::config::{utils::AsKey, Config};

use crate::{backend::internal::manage::ManageDirectory, Principal, Type};

use super::{EmailType, MemoryDirectory};

impl MemoryDirectory {
    pub async fn from_config(
        config: &mut Config,
        prefix: impl AsKey,
        data_store: Store,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let mut directory = MemoryDirectory {
            data_store,
            principals: Default::default(),
            emails_to_ids: Default::default(),
            domains: Default::default(),
        };

        for lookup_id in config
            .sub_keys((prefix.as_str(), "principals"), ".name")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            let lookup_id = lookup_id.as_str();
            let name = config
                .value_require((prefix.as_str(), "principals", lookup_id, "name"))?
                .to_string();
            let typ = match config.value((prefix.as_str(), "principals", lookup_id, "class")) {
                Some("individual") => Type::Individual,
                Some("admin") => Type::Superuser,
                Some("group") => Type::Group,
                _ => Type::Individual,
            };

            // Obtain id
            let id = directory
                .data_store
                .get_or_create_account_id(&name)
                .await
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!(
                            "Failed to obtain id for principal {} ({}): {:?}",
                            name, lookup_id, err
                        ),
                    )
                })
                .ok()?;

            // Obtain group ids
            let mut member_of = Vec::new();
            for group in config
                .values((prefix.as_str(), "principals", lookup_id, "member-of"))
                .map(|(_, s)| s.to_string())
                .collect::<Vec<_>>()
            {
                member_of.push(
                    directory
                        .data_store
                        .get_or_create_account_id(&group)
                        .await
                        .map_err(|err| {
                            config.new_build_error(
                                prefix.as_str(),
                                format!(
                                    "Failed to obtain id for principal {} ({}): {:?}",
                                    name, lookup_id, err
                                ),
                            )
                        })
                        .ok()?,
                );
            }

            // Parse email addresses
            let mut emails = Vec::new();
            for (pos, (_, email)) in config
                .values((prefix.as_str(), "principals", lookup_id, "email"))
                .enumerate()
            {
                directory
                    .emails_to_ids
                    .entry(email.to_string())
                    .or_default()
                    .push(if pos > 0 {
                        EmailType::Alias(id)
                    } else {
                        EmailType::Primary(id)
                    });

                if let Some((_, domain)) = email.rsplit_once('@') {
                    directory.domains.insert(domain.to_lowercase());
                }

                emails.push(email.to_lowercase());
            }

            // Parse mailing lists
            for (_, email) in
                config.values((prefix.as_str(), "principals", lookup_id, "email-list"))
            {
                directory
                    .emails_to_ids
                    .entry(email.to_lowercase())
                    .or_default()
                    .push(EmailType::List(id));
                if let Some((_, domain)) = email.rsplit_once('@') {
                    directory.domains.insert(domain.to_lowercase());
                }
            }

            directory.principals.push(Principal {
                name: name.clone(),
                secrets: config
                    .values((prefix.as_str(), "principals", lookup_id, "secret"))
                    .map(|(_, v)| v.to_string())
                    .collect(),
                typ,
                description: config
                    .value((prefix.as_str(), "principals", lookup_id, "description"))
                    .map(|v| v.to_string()),
                quota: config
                    .property((prefix.as_str(), "principals", lookup_id, "quota"))
                    .unwrap_or(0),
                member_of,
                id,
                emails,
            });
        }

        Some(directory)
    }
}
