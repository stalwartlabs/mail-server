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

use std::{borrow::Cow, fmt::Debug, sync::Arc};

use ahash::AHashMap;
use deadpool::managed::PoolError;
use imap::ImapError;
use ldap3::LdapError;
use mail_send::Credentials;
use utils::config::DynValue;

pub mod cache;
pub mod config;
pub mod imap;
pub mod ldap;
pub mod memory;
pub mod secret;
pub mod smtp;
pub mod sql;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub secrets: Vec<String>,
    pub typ: Type,
    pub description: Option<String>,
    pub quota: u32,
    pub member_of: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Individual,
    Group,
    Resource,
    Location,
    #[default]
    Other,
    Superuser,
}

#[derive(Debug)]
pub enum DirectoryError {
    Ldap(LdapError),
    Sql(store::Error),
    Imap(ImapError),
    Smtp(mail_send::Error),
    Pool(String),
    TimedOut,
    Unsupported,
}

#[async_trait::async_trait]
pub trait Directory: Sync + Send {
    async fn authenticate(&self, credentials: &Credentials<String>) -> Result<Option<Principal>>;
    async fn principal(&self, name: &str) -> Result<Option<Principal>>;
    async fn emails_by_name(&self, name: &str) -> Result<Vec<String>>;
    async fn names_by_email(&self, email: &str) -> Result<Vec<String>>;
    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool>;
    async fn rcpt(&self, address: &str) -> crate::Result<bool>;
    async fn vrfy(&self, address: &str) -> Result<Vec<String>>;
    async fn expn(&self, address: &str) -> Result<Vec<String>>;
}

impl Principal {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn has_name(&self) -> bool {
        !self.name.is_empty()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl Debug for dyn Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory").finish()
    }
}

impl Type {
    pub fn to_jmap(&self) -> &'static str {
        match self {
            Self::Individual | Self::Superuser => "individual",
            Self::Group => "group",
            Self::Resource => "resource",
            Self::Location => "location",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Default)]
struct DirectoryOptions {
    catch_all: AddressMapping,
    subaddressing: AddressMapping,
    superuser_group: String,
}

#[derive(Debug, Default)]
pub enum AddressMapping {
    Enable,
    Custom {
        regex: regex::Regex,
        mapping: DynValue<String>,
    },
    #[default]
    Disable,
}

#[derive(Default, Clone, Debug)]
pub struct Directories {
    pub directories: AHashMap<String, Arc<dyn Directory>>,
}

pub type Result<T> = std::result::Result<T, DirectoryError>;

impl From<PoolError<LdapError>> for DirectoryError {
    fn from(error: PoolError<LdapError>) -> Self {
        match error {
            PoolError::Backend(error) => error.into(),
            PoolError::Timeout(_) => DirectoryError::timeout("ldap"),
            error => DirectoryError::Pool(error.to_string()),
        }
    }
}

impl From<PoolError<ImapError>> for DirectoryError {
    fn from(error: PoolError<ImapError>) -> Self {
        match error {
            PoolError::Backend(error) => error.into(),
            PoolError::Timeout(_) => DirectoryError::timeout("imap"),
            error => DirectoryError::Pool(error.to_string()),
        }
    }
}

impl From<PoolError<mail_send::Error>> for DirectoryError {
    fn from(error: PoolError<mail_send::Error>) -> Self {
        match error {
            PoolError::Backend(error) => error.into(),
            PoolError::Timeout(_) => DirectoryError::timeout("smtp"),
            error => DirectoryError::Pool(error.to_string()),
        }
    }
}

impl From<LdapError> for DirectoryError {
    fn from(error: LdapError) -> Self {
        tracing::warn!(
            context = "directory",
            event = "error",
            protocol = "ldap",
            reason = %error,
            "LDAP directory error"
        );

        DirectoryError::Ldap(error)
    }
}

impl From<store::Error> for DirectoryError {
    fn from(error: store::Error) -> Self {
        tracing::warn!(
            context = "directory",
            event = "error",
            protocol = "sql",
            reason = %error,
            "SQL directory error"
        );

        DirectoryError::Sql(error)
    }
}

impl From<ImapError> for DirectoryError {
    fn from(error: ImapError) -> Self {
        tracing::warn!(
            context = "directory",
            event = "error",
            protocol = "imap",
            reason = %error,
            "IMAP directory error"
        );

        DirectoryError::Imap(error)
    }
}

impl From<mail_send::Error> for DirectoryError {
    fn from(error: mail_send::Error) -> Self {
        tracing::warn!(
            context = "directory",
            event = "error",
            protocol = "smtp",
            reason = %error,
            "SMTP directory error"
        );

        DirectoryError::Smtp(error)
    }
}

impl DirectoryError {
    pub fn unsupported(protocol: &str, method: &str) -> Self {
        tracing::warn!(
            context = "directory",
            event = "error",
            protocol = protocol,
            method = method,
            "Method not supported by directory"
        );
        DirectoryError::Unsupported
    }

    pub fn timeout(protocol: &str) -> Self {
        tracing::warn!(
            context = "directory",
            event = "error",
            protocol = protocol,
            "Directory timed out"
        );
        DirectoryError::TimedOut
    }
}

impl AddressMapping {
    pub fn to_subaddress<'x, 'y: 'x>(&'x self, address: &'y str) -> Cow<'x, str> {
        match self {
            AddressMapping::Enable => {
                if let Some((local_part, domain_part)) = address.rsplit_once('@') {
                    if let Some((local_part, _)) = local_part.split_once('+') {
                        return format!("{}@{}", local_part, domain_part).into();
                    }
                }
            }
            AddressMapping::Custom { regex, mapping } => {
                let mut regex_capture = Vec::new();
                for captures in regex.captures_iter(address) {
                    for capture in captures.iter() {
                        regex_capture.push(capture.map_or("", |m| m.as_str()).to_string());
                    }
                }

                if !regex_capture.is_empty() {
                    return mapping.apply(regex_capture, &());
                }
            }
            AddressMapping::Disable => (),
        }

        address.into()
    }

    pub fn to_catch_all<'x, 'y: 'x>(&'x self, address: &'y str) -> Option<Cow<'x, str>> {
        match self {
            AddressMapping::Enable => address
                .rsplit_once('@')
                .map(|(_, domain_part)| format!("@{}", domain_part))
                .map(Cow::Owned),
            AddressMapping::Custom { regex, mapping } => {
                let mut regex_capture = Vec::new();
                for captures in regex.captures_iter(address) {
                    for capture in captures.iter() {
                        regex_capture.push(capture.map_or("", |m| m.as_str()).to_string());
                    }
                }
                if !regex_capture.is_empty() {
                    Some(mapping.apply(regex_capture, &()))
                } else {
                    None
                }
            }
            AddressMapping::Disable => None,
        }
    }
}
