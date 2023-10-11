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

use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    sync::Arc,
};

use ahash::{AHashMap, AHashSet};
use bb8::RunError;
use imap::ImapError;
use ldap3::LdapError;
use mail_send::Credentials;
use sieve::runtime::{tests::glob::GlobPattern, Variable};
use smtp_proto::IntoString;
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
    Sql(sqlx::Error),
    Imap(ImapError),
    Smtp(mail_send::Error),
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
    async fn lookup(&self, query: &str, params: &[DatabaseColumn<'_>]) -> Result<bool>;
    async fn query(
        &self,
        query: &str,
        params: &[DatabaseColumn<'_>],
    ) -> Result<Vec<DatabaseColumn<'static>>>;

    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

#[derive(Clone, Debug)]
pub enum DatabaseColumn<'x> {
    Integer(i64),
    Bool(bool),
    Float(f64),
    Text(Cow<'x, str>),
    Blob(Cow<'x, [u8]>),
    Null,
}

#[derive(Clone)]
pub enum Lookup {
    Directory {
        directory: Arc<dyn Directory>,
        query: String,
    },
    List {
        list: LookupList,
    },
    Map {
        map: AHashMap<String, Variable<'static>>,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LookupList {
    pub set: AHashSet<String>,
    pub matches: Vec<MatchType>,
}

#[derive(Debug, Clone)]
pub enum MatchType {
    StartsWith(String),
    EndsWith(String),
    Glob(GlobPattern),
    Regex(regex::Regex),
}

impl LookupList {
    pub fn contains(&self, value: &str) -> bool {
        if self.set.contains(value) {
            true
        } else {
            for match_type in &self.matches {
                let result = match match_type {
                    MatchType::StartsWith(s) => value.starts_with(s),
                    MatchType::EndsWith(s) => value.ends_with(s),
                    MatchType::Glob(g) => g.matches(value),
                    MatchType::Regex(r) => r.is_match(value),
                };
                if result {
                    return true;
                }
            }
            false
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.set.extend(other.set);
        self.matches.extend(other.matches);
    }
}

impl PartialEq for MatchType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::StartsWith(l0), Self::StartsWith(r0)) => l0 == r0,
            (Self::EndsWith(l0), Self::EndsWith(r0)) => l0 == r0,
            (Self::Glob(l0), Self::Glob(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => true,
            _ => false,
        }
    }
}

impl Eq for MatchType {}

impl Lookup {
    pub async fn contains(&self, item: impl Into<DatabaseColumn<'_>>) -> Option<bool> {
        match self {
            Lookup::Directory { directory, query } => {
                match directory.lookup(query, &[item.into()]).await {
                    Ok(result) => result.into(),
                    Err(_) => None,
                }
            }
            Lookup::List { list } => list.contains(item.into().as_str()).into(),
            Lookup::Map { map } => map.contains_key(item.into().as_str()).into(),
        }
    }

    pub async fn lookup(&self, items: &[DatabaseColumn<'_>]) -> Option<Variable<'static>> {
        match self {
            Lookup::Directory { directory, query } => match directory.query(query, items).await {
                Ok(mut result) => match result.len() {
                    1 if !matches!(result.first(), Some(DatabaseColumn::Null)) => {
                        result.pop().map(Variable::from).unwrap()
                    }
                    0 => Variable::default(),
                    _ => Variable::Array(result.into_iter().map(Variable::from).collect()),
                }
                .into(),
                Err(_) => None,
            },
            Lookup::List { list } => Some(list.contains(items[0].as_str()).into()),
            Lookup::Map { map } => map.get(items[0].as_str()).cloned(),
        }
    }

    pub async fn query(
        &self,
        items: &[DatabaseColumn<'_>],
    ) -> Option<Vec<DatabaseColumn<'static>>> {
        match self {
            Lookup::Directory { directory, query } => match directory.query(query, items).await {
                Ok(result) => Some(result),
                Err(_) => None,
            },
            _ => None,
        }
    }
}

impl<'x> From<DatabaseColumn<'x>> for Variable<'static> {
    fn from(value: DatabaseColumn) -> Self {
        match value {
            DatabaseColumn::Integer(v) => Variable::Integer(v),
            DatabaseColumn::Bool(v) => Variable::Integer(i64::from(v)),
            DatabaseColumn::Float(v) => Variable::Float(v),
            DatabaseColumn::Text(v) => Variable::String(v.into_owned()),
            DatabaseColumn::Blob(v) => Variable::String(v.into_owned().into_string()),
            DatabaseColumn::Null => Variable::StringRef(""),
        }
    }
}

impl PartialEq for Lookup {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Lookup::Directory { query, .. }, Lookup::Directory { query: other, .. }) => {
                query == other
            }
            (Lookup::List { list }, Lookup::List { list: other }) => list == other,
            _ => false,
        }
    }
}

impl Eq for Lookup {}

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
        f.debug_struct("Directory")
            .field("type", &self.type_name())
            .finish()
    }
}

impl Debug for Lookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory { query, .. } => {
                f.debug_struct("Directory").field("query", query).finish()
            }
            Self::List { list } => f.debug_struct("List").field("list", list).finish(),
            Self::Map { map } => f.debug_struct("Map").field("map", &map.keys()).finish(),
        }
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
pub struct DirectoryConfig {
    pub directories: AHashMap<String, Arc<dyn Directory>>,
    pub lookups: AHashMap<String, Arc<Lookup>>,
}

pub type Result<T> = std::result::Result<T, DirectoryError>;

impl From<RunError<LdapError>> for DirectoryError {
    fn from(error: RunError<LdapError>) -> Self {
        match error {
            RunError::User(error) => error.into(),
            RunError::TimedOut => DirectoryError::timeout("ldap"),
        }
    }
}

impl From<RunError<ImapError>> for DirectoryError {
    fn from(error: RunError<ImapError>) -> Self {
        match error {
            RunError::User(error) => error.into(),
            RunError::TimedOut => DirectoryError::timeout("imap"),
        }
    }
}

impl From<RunError<mail_send::Error>> for DirectoryError {
    fn from(error: RunError<mail_send::Error>) -> Self {
        match error {
            RunError::User(error) => error.into(),
            RunError::TimedOut => DirectoryError::timeout("smtp"),
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

impl From<sqlx::Error> for DirectoryError {
    fn from(error: sqlx::Error) -> Self {
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
            protocol = "ldap",
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

impl<'x> DatabaseColumn<'x> {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text(v) => v.as_ref(),
            _ => "",
        }
    }
}

impl<'x> From<&'x str> for DatabaseColumn<'x> {
    fn from(value: &'x str) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<String> for DatabaseColumn<'x> {
    fn from(value: String) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<&'x String> for DatabaseColumn<'x> {
    fn from(value: &'x String) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<Cow<'x, str>> for DatabaseColumn<'x> {
    fn from(value: Cow<'x, str>) -> Self {
        Self::Text(value)
    }
}

impl<'x> From<bool> for DatabaseColumn<'x> {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl<'x> From<i64> for DatabaseColumn<'x> {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl<'x> From<u64> for DatabaseColumn<'x> {
    fn from(value: u64) -> Self {
        Self::Integer(value as i64)
    }
}

impl<'x> From<u32> for DatabaseColumn<'x> {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl<'x> From<f64> for DatabaseColumn<'x> {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl<'x> From<&'x [u8]> for DatabaseColumn<'x> {
    fn from(value: &'x [u8]) -> Self {
        Self::Blob(value.into())
    }
}

impl<'x> From<Vec<u8>> for DatabaseColumn<'x> {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(value.into())
    }
}

impl<'x> From<Variable<'x>> for DatabaseColumn<'x> {
    fn from(value: Variable<'x>) -> Self {
        match value {
            Variable::String(v) => Self::Text(v.into()),
            Variable::StringRef(v) => Self::Text(v.into()),
            Variable::Integer(v) => Self::Integer(v),
            Variable::Float(v) => Self::Float(v),
            v => Self::Text(v.into_string().into()),
        }
    }
}

impl<'x> From<&'x Variable<'x>> for DatabaseColumn<'x> {
    fn from(value: &'x Variable<'x>) -> Self {
        match value {
            Variable::String(v) => Self::Text(v.into()),
            Variable::StringRef(v) => Self::Text((*v).into()),
            Variable::Integer(v) => Self::Integer(*v),
            Variable::Float(v) => Self::Float(*v),
            v => Self::Text(v.to_string().into()),
        }
    }
}

impl<'x> Display for DatabaseColumn<'x> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseColumn::Text(v) => f.write_str(v.as_ref()),
            DatabaseColumn::Integer(v) => write!(f, "{}", v),
            DatabaseColumn::Bool(v) => write!(f, "{}", v),
            DatabaseColumn::Float(v) => write!(f, "{}", v),
            DatabaseColumn::Blob(v) => write!(f, "{}", String::from_utf8_lossy(v.as_ref())),
            DatabaseColumn::Null => write!(f, "NULL"),
        }
    }
}
