use bb8::Pool;
use ldap3::{ldap_escape, LdapConnSettings};

use crate::DirectoryOptions;

pub mod config;
pub mod lookup;
pub mod pool;

pub struct LdapDirectory {
    pool: Pool<LdapConnectionManager>,
    mappings: LdapMappings,
    opt: DirectoryOptions,
}

#[derive(Debug, Default)]
pub struct LdapMappings {
    base_dn: String,
    filter_login: LdapFilter,
    filter_name: LdapFilter,
    filter_email: LdapFilter,
    filter_id: LdapFilter,
    filter_verify: LdapFilter,
    filter_expand: LdapFilter,
    filter_domains: LdapFilter,
    obj_user: String,
    obj_group: String,
    attr_name: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_groups: Vec<String>,
    attr_id: Vec<String>,
    attr_email_address: Vec<String>,
    attr_quota: Vec<String>,
    attrs_principal: Vec<String>,
    attrs_email: Vec<String>,
}

#[derive(Debug, Default)]
struct LdapFilter {
    filter: Vec<String>,
}

impl LdapFilter {
    pub fn build(&self, value: &str) -> String {
        let value = ldap_escape(value);
        self.filter.join(value.as_ref())
    }
}

pub(crate) struct LdapConnectionManager {
    address: String,
    settings: LdapConnSettings,
    bind_dn: Option<Bind>,
}

pub(crate) struct Bind {
    dn: String,
    password: String,
}

impl LdapConnectionManager {
    pub fn new(address: String, settings: LdapConnSettings, bind_dn: Option<Bind>) -> Self {
        Self {
            address,
            settings,
            bind_dn,
        }
    }
}

impl Bind {
    pub fn new(dn: String, password: String) -> Self {
        Self { dn, password }
    }
}
