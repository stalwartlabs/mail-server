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

use core::cache::CachedDirectory;
use std::{
    fmt::{Debug, Display},
    sync::Arc,
};

use ahash::AHashMap;
use backend::{
    imap::{ImapDirectory, ImapError},
    internal::PrincipalField,
    ldap::LdapDirectory,
    memory::MemoryDirectory,
    smtp::SmtpDirectory,
    sql::SqlDirectory,
};
use deadpool::managed::PoolError;
use ldap3::LdapError;
use mail_send::Credentials;
use store::Store;

pub mod backend;
pub mod core;

pub struct Directory {
    pub store: DirectoryInner,
    pub cache: Option<CachedDirectory>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Principal<T> {
    #[serde(default, skip)]
    pub id: u32,
    #[serde(rename = "type")]
    pub typ: Type,
    #[serde(default)]
    pub quota: u64,
    pub name: String,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    #[serde(rename = "memberOf")]
    pub member_of: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Type {
    #[serde(rename = "individual")]
    #[default]
    Individual = 0,
    #[serde(rename = "group")]
    Group = 1,
    #[serde(rename = "resource")]
    Resource = 2,
    #[serde(rename = "location")]
    Location = 3,
    #[serde(rename = "superuser")]
    Superuser = 4,
    #[serde(rename = "list")]
    List = 5,
    #[serde(rename = "other")]
    Other = 6,
}

#[derive(Debug)]
pub enum DirectoryError {
    Ldap(LdapError),
    Store(store::Error),
    Imap(ImapError),
    Smtp(mail_send::Error),
    Pool(String),
    Management(ManagementError),
    TimedOut,
    Unsupported,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ManagementError {
    MissingField(PrincipalField),
    AlreadyExists {
        field: PrincipalField,
        value: String,
    },
    NotFound(String),
}

pub enum DirectoryInner {
    Internal(Store),
    Ldap(LdapDirectory),
    Sql(SqlDirectory),
    Imap(ImapDirectory),
    Smtp(SmtpDirectory),
    Memory(MemoryDirectory),
}

pub enum QueryBy<'x> {
    Name(&'x str),
    Id(u32),
    Credentials(&'x Credentials<String>),
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Principal<T> {
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

impl Default for Directory {
    fn default() -> Self {
        Self {
            store: DirectoryInner::Internal(Store::None),
            cache: None,
        }
    }
}

impl Debug for Directory {
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
            Self::List => "list",
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Directories {
    pub directories: AHashMap<String, Arc<Directory>>,
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

impl Principal<u32> {
    pub fn fallback_admin(fallback_pass: impl Into<String>) -> Self {
        Principal {
            id: u32::MAX,
            typ: Type::Superuser,
            quota: 0,
            name: "Fallback Administrator".to_string(),
            secrets: vec![fallback_pass.into()],
            ..Default::default()
        }
    }
}

impl<T: Ord> Principal<T> {
    pub fn into_sorted(mut self) -> Self {
        self.member_of.sort_unstable();
        self.emails.sort_unstable();
        self
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
            protocol = "store",
            reason = %error,
            "Directory error"
        );

        DirectoryError::Store(error)
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

impl PartialEq for DirectoryError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Store(l0), Self::Store(r0)) => l0 == r0,
            (Self::Pool(l0), Self::Pool(r0)) => l0 == r0,
            (Self::Management(l0), Self::Management(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ldap(error) => write!(f, "LDAP error: {}", error),
            Self::Store(error) => write!(f, "Store error: {}", error),
            Self::Imap(error) => write!(f, "IMAP error: {}", error),
            Self::Smtp(error) => write!(f, "SMTP error: {}", error),
            Self::Pool(error) => write!(f, "Pool error: {}", error),
            Self::Management(error) => write!(f, "Management error: {:?}", error),
            Self::TimedOut => write!(f, "Directory timed out"),
            Self::Unsupported => write!(f, "Method not supported by directory"),
        }
    }
}
