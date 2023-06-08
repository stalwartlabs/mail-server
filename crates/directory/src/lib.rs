use std::{borrow::Cow, fmt::Debug, sync::Arc};

use ahash::{AHashMap, AHashSet};
use bb8::RunError;
use imap::ImapError;
use ldap3::LdapError;
use mail_send::Credentials;

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
    pub id: u32,
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
    async fn principal_by_name(&self, name: &str) -> Result<Option<Principal>>;
    async fn principal_by_id(&self, id: u32) -> Result<Option<Principal>>;
    async fn member_of(&self, principal: &Principal) -> Result<Vec<u32>>;
    async fn emails_by_id(&self, id: u32) -> Result<Vec<String>>;
    async fn ids_by_email(&self, email: &str) -> Result<Vec<u32>>;
    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool>;
    async fn rcpt(&self, address: &str) -> crate::Result<bool>;
    async fn vrfy(&self, address: &str) -> Result<Vec<String>>;
    async fn expn(&self, address: &str) -> Result<Vec<String>>;
    async fn query(&self, query: &str, params: &[&str]) -> Result<bool>;

    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

#[derive(Clone)]
pub enum Lookup {
    Directory {
        directory: Arc<dyn Directory>,
        query: String,
    },
    List {
        list: AHashSet<String>,
    },
}

impl Lookup {
    pub async fn contains(&self, item: &str) -> Option<bool> {
        match self {
            Lookup::Directory { directory, query } => match directory.query(query, &[item]).await {
                Ok(result) => result.into(),
                Err(_) => None,
            },
            Lookup::List { list } => list.contains(item).into(),
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
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn has_id(&self) -> bool {
        self.id != u32::MAX
    }

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
        }
    }
}

#[derive(Debug, Default)]
struct DirectoryOptions {
    catch_all: bool,
    subaddressing: bool,
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

#[inline(always)]
fn unwrap_subaddress(address: &str, allow_subaddessing: bool) -> Cow<'_, str> {
    if allow_subaddessing {
        if let Some((local_part, domain_part)) = address.rsplit_once('@') {
            if let Some((local_part, _)) = local_part.split_once('+') {
                return format!("{}@{}", local_part, domain_part).into();
            }
        }
    }

    address.into()
}

#[inline(always)]
fn to_catch_all_address(address: &str) -> String {
    address
        .rsplit_once('@')
        .map(|(_, domain_part)| format!("@{}", domain_part))
        .unwrap_or_else(|| address.into())
}
