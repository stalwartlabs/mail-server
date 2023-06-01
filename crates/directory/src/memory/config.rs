use std::sync::Arc;

use utils::config::{utils::AsKey, Config};

use crate::{Directory, Principal, Type};

use super::{EmailType, MemoryDirectory};

impl MemoryDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let mut directory = MemoryDirectory::default();

        for lookup_id in config.sub_keys((prefix.as_str(), "users")) {
            let id = directory.principals.len() as u32;
            let name = config
                .value_require((prefix.as_str(), "users", lookup_id, "name"))?
                .to_string();
            directory.names.insert(name.clone(), id);
            directory.principals.push(Principal {
                id,
                name,
                secrets: config
                    .values((prefix.as_str(), "users", lookup_id, "secret"))
                    .map(|(_, v)| v.to_string())
                    .collect(),
                typ: Type::Individual,
                description: config
                    .value((prefix.as_str(), "users", lookup_id, "description"))
                    .map(|v| v.to_string()),
                quota: config
                    .property((prefix.as_str(), "users", lookup_id, "quota"))?
                    .unwrap_or(0),
                member_of: config
                    .values((prefix.as_str(), "users", lookup_id, "member-of"))
                    .map(|(_, v)| v.to_string())
                    .collect(),
            });
            let mut emails = Vec::new();
            for (pos, (_, email)) in config
                .values((prefix.as_str(), "users", lookup_id, "email"))
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

                emails.push(if pos > 0 {
                    EmailType::Alias(email.to_string())
                } else {
                    EmailType::Primary(email.to_string())
                });
            }
            for (_, email) in config.values((prefix.as_str(), "users", lookup_id, "email-list")) {
                directory
                    .emails_to_ids
                    .entry(email.to_string())
                    .or_default()
                    .push(EmailType::List(id));
                emails.push(EmailType::List(email.to_string()));
            }
            directory.ids_to_email.insert(id, emails);
        }

        for lookup_id in config.sub_keys((prefix.as_str(), "groups")) {
            let id = directory.principals.len() as u32;
            let name = config
                .value_require((prefix.as_str(), "groups", lookup_id, "name"))?
                .to_string();
            directory.names.insert(name.clone(), id);
            directory.principals.push(Principal {
                id,
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
            });
        }

        Ok(Arc::new(directory))
    }
}