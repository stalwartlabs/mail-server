/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::managed::Pool;
use ldap3::{LdapConnSettings, ldap_escape};
use store::Store;

pub mod config;
pub mod lookup;
pub mod pool;

pub struct LdapDirectory {
    pool: Pool<LdapConnectionManager>,
    mappings: LdapMappings,
    auth_bind: AuthBind,
    pub(crate) data_store: Store,
}

#[derive(Debug, Default)]
pub struct LdapMappings {
    base_dn: String,
    filter_name: LdapFilter,
    filter_email: LdapFilter,
    attr_name: Vec<String>,
    attr_type: Vec<String>,
    attr_groups: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_secret_changed: Vec<String>,
    attr_email_address: Vec<String>,
    attr_email_alias: Vec<String>,
    attr_quota: Vec<String>,
    attrs_principal: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct LdapFilter {
    filter: Vec<LdapFilterItem>,
}

#[derive(Debug)]
enum LdapFilterItem {
    Static(String),
    Full,
    LocalPart,
    DomainPart,
}

impl LdapFilter {
    pub fn build(&self, value: &str) -> String {
        let mut result = String::with_capacity(value.len() + 16);

        for item in &self.filter {
            match item {
                LdapFilterItem::Static(s) => result.push_str(s),
                LdapFilterItem::Full => result.push_str(ldap_escape(value).as_ref()),
                LdapFilterItem::LocalPart => {
                    if let Some((value, _)) = value.rsplit_once('@') {
                        result.push_str(value);
                    }
                }
                LdapFilterItem::DomainPart => {
                    if let Some((_, domain)) = value.rsplit_once('@') {
                        result.push_str(domain);
                    }
                }
            }
        }

        result
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

pub(crate) enum AuthBind {
    Template {
        template: LdapFilter,
        can_search: bool,
    },
    Lookup,
    None,
}
