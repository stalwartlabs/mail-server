/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::managed::Pool;
use ldap3::{ldap_escape, LdapConnSettings};
use store::Store;

pub mod config;
pub mod lookup;
pub mod pool;

pub struct LdapDirectory {
    pool: Pool<LdapConnectionManager>,
    mappings: LdapMappings,
    auth_bind: Option<LdapFilter>,
    pub(crate) data_store: Store,
}

#[derive(Debug, Default)]
pub struct LdapMappings {
    base_dn: String,
    filter_name: LdapFilter,
    filter_email: LdapFilter,
    filter_verify: LdapFilter,
    filter_expand: LdapFilter,
    filter_domains: LdapFilter,
    attr_name: Vec<String>,
    attr_type: Vec<String>,
    attr_groups: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_email_address: Vec<String>,
    attr_email_alias: Vec<String>,
    attr_quota: Vec<String>,
    attrs_principal: Vec<String>,
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
