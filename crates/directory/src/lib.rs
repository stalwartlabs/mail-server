/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use core::cache::CachedDirectory;
use std::{fmt::Debug, sync::Arc};

use ahash::AHashMap;
use backend::{
    imap::{ImapDirectory, ImapError},
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

trait IntoError {
    fn into_error(self) -> trc::Error;
}

impl IntoError for PoolError<LdapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .ctx(trc::Key::Protocol, trc::Protocol::Ldap)
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError
                .ctx(trc::Key::Protocol, trc::Protocol::Ldap)
                .reason(err),
        }
    }
}

impl IntoError for PoolError<ImapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .ctx(trc::Key::Protocol, trc::Protocol::Imap)
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError
                .ctx(trc::Key::Protocol, trc::Protocol::Imap)
                .reason(err),
        }
    }
}

impl IntoError for PoolError<mail_send::Error> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .ctx(trc::Key::Protocol, trc::Protocol::Smtp)
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError
                .ctx(trc::Key::Protocol, trc::Protocol::Smtp)
                .reason(err),
        }
    }
}

impl IntoError for ImapError {
    fn into_error(self) -> trc::Error {
        trc::ImapEvent::Error.into_err().reason(self)
    }
}

impl IntoError for mail_send::Error {
    fn into_error(self) -> trc::Error {
        trc::SmtpEvent::Error.into_err().reason(self)
    }
}

impl IntoError for LdapError {
    fn into_error(self) -> trc::Error {
        if let LdapError::LdapResult { result } = &self {
            trc::StoreEvent::LdapError
                .ctx(trc::Key::Code, result.rc)
                .reason(self)
        } else {
            trc::StoreEvent::LdapError.reason(self)
        }
    }
}
