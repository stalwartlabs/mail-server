use bb8::{ManageConnection, Pool};
use std::{sync::Arc, time::Duration};
use utils::config::Config;

use ahash::AHashMap;

use crate::{
    imap::ImapDirectory, ldap::LdapDirectory, smtp::SmtpDirectory, sql::SqlDirectory, Directory,
};

pub trait ConfigDirectory {
    fn parse_directory(&self) -> utils::config::Result<AHashMap<String, Arc<dyn Directory>>>;
}

impl ConfigDirectory for Config {
    fn parse_directory(&self) -> utils::config::Result<AHashMap<String, Arc<dyn Directory>>> {
        let mut directories = AHashMap::new();
        for id in self.sub_keys("directory") {
            directories.insert(
                id.to_string(),
                match self.value_require(("directory", id, "protocol"))? {
                    "ldap" => LdapDirectory::from_config(self, ("directory", id))?,
                    "sql" => SqlDirectory::from_config(self, ("directory", id))?,
                    "imap" => ImapDirectory::from_config(self, ("directory", id))?,
                    "smtp" => SmtpDirectory::from_config(self, ("directory", id), false)?,
                    "lmtp" => SmtpDirectory::from_config(self, ("directory", id), true)?,
                    unknown => {
                        return Err(format!("Unknown directory type: {unknown:?}"));
                    }
                },
            );
        }

        Ok(directories)
    }
}

pub(crate) fn build_pool<M: ManageConnection>(
    config: &Config,
    prefix: &str,
    manager: M,
) -> utils::config::Result<Pool<M>> {
    Ok(Pool::builder()
        .min_idle(
            config
                .property((prefix, "pool.min-connections"))?
                .and_then(|v| if v > 0 { Some(v) } else { None }),
        )
        .max_size(config.property_or_static((prefix, "pool.max-connections"), "10")?)
        .max_lifetime(
            config
                .property_or_static::<Duration>((prefix, "pool.max-lifetime"), "30m")?
                .into(),
        )
        .idle_timeout(
            config
                .property_or_static::<Duration>((prefix, "pool.idle-timeout"), "10m")?
                .into(),
        )
        .connection_timeout(config.property_or_static((prefix, "pool.connect-timeout"), "30s")?)
        .test_on_check_out(true)
        .build_unchecked(manager))
}
