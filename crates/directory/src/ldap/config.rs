use std::sync::Arc;

use ldap3::LdapConnSettings;
use utils::config::{utils::AsKey, Config};

use crate::{config::build_pool, Directory};

use super::{Bind, LdapConnectionManager, LdapDirectory, LdapFilter, LdapMappings};

impl LdapDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
    ) -> utils::config::Result<Arc<dyn Directory>> {
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
            config.value_require((&prefix, "address"))?.to_string(),
            LdapConnSettings::new()
                .set_conn_timeout(config.property_or_static((&prefix, "timeout"), "30s")?)
                .set_starttls(config.property_or_static((&prefix, "tls"), "false")?)
                .set_no_tls_verify(
                    config.property_or_static((&prefix, "allow-invalid-certs"), "false")?,
                ),
            bind_dn,
        );

        let mut mappings = LdapMappings {
            base_dn: config.value_require((&prefix, "address"))?.to_string(),
            filter_login: LdapFilter::from_config(config, (&prefix, "filter.login"))?,
            filter_name: LdapFilter::from_config(config, (&prefix, "filter.name"))?,
            filter_email: LdapFilter::from_config(config, (&prefix, "filter.email"))?,
            filter_id: LdapFilter::from_config(config, (&prefix, "filter.id"))?,
            filter_verify: LdapFilter::from_config(config, (&prefix, "filter.verify"))?,
            filter_expand: LdapFilter::from_config(config, (&prefix, "filter.expand"))?,
            obj_user: config
                .value_require((&prefix, "object-classes.user"))?
                .to_string(),
            obj_group: config
                .value_require((&prefix, "object-classes.group"))?
                .to_string(),
            attr_name: config
                .values((&prefix, "attributes.name"))
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
            attr_groups: config
                .values((&prefix, "attributes.groups"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_id: config
                .values((&prefix, "attributes.id"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_email_address: config
                .values((&prefix, "attributes.email"))
                .map(|(_, v)| v.to_string())
                .collect(),
            attr_quota: config
                .values((&prefix, "attributes."))
                .map(|(_, v)| v.to_string())
                .collect(),
            attrs_principal: vec!["objectClass".to_string()],
            attrs_email: config
                .values((&prefix, "attributes.email-alias"))
                .map(|(_, v)| v.to_string())
                .collect(),
        };

        for attr in [
            &mappings.attr_id,
            &mappings.attr_name,
            &mappings.attr_description,
            &mappings.attr_secret,
            &mappings.attr_quota,
            &mappings.attr_groups,
        ] {
            mappings.attrs_principal.extend(attr.iter().cloned());
        }

        mappings
            .attrs_email
            .extend(mappings.attr_email_address.iter().cloned());

        Ok(Arc::new(LdapDirectory {
            mappings,
            pool: build_pool(config, &prefix, manager)?,
        }))
    }
}

impl LdapFilter {
    fn from_config(config: &Config, key: impl AsKey) -> utils::config::Result<Self> {
        if let Some(value) = config.value(key.clone()) {
            let filter = LdapFilter {
                filter: value.split('?').map(|s| s.to_string()).collect(),
            };
            if filter.filter.len() >= 2 {
                Ok(filter)
            } else {
                Err(format!(
                    "Missing '?' parameter placeholder in filter {:?} with value {:?}",
                    key.as_key(),
                    value
                ))
            }
        } else {
            Ok(Self::default())
        }
    }
}
