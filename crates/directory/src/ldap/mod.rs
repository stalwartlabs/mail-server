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
    filter_name: LdapFilter,
    filter_email: LdapFilter,
    filter_verify: LdapFilter,
    filter_expand: LdapFilter,
    filter_domains: LdapFilter,
    obj_user: String,
    obj_group: String,
    attr_name: Vec<String>,
    attr_description: Vec<String>,
    attr_secret: Vec<String>,
    attr_groups: Vec<String>,
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
