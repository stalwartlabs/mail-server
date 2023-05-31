use bb8::RunError;
use imap::ImapError;
use ldap3::LdapError;
use mail_send::Credentials;

pub mod config;
pub mod imap;
pub mod ldap;
pub mod smtp;
pub mod sql;

#[derive(Debug, Default, Clone)]
pub struct Principal {
    pub id: u32,
    pub name: String,
    pub secret: Option<String>,
    pub typ: Type,
    pub description: Option<String>,
    pub quota: u32,
    pub member_of: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
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
    async fn rcpt(&self, address: &str) -> crate::Result<bool>;
    async fn vrfy(&self, address: &str) -> Result<Vec<String>>;
    async fn expn(&self, address: &str) -> Result<Vec<String>>;
    async fn query(&self, query: &str, params: &[&str]) -> Result<bool>;
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

#[cfg(test)]
mod tests {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

    use crate::ldap::{Bind, LdapConnectionManager};

    #[tokio::test]
    async fn ldap() {
        let manager = LdapConnectionManager::new(
            "ldap://localhost:3893".to_string(),
            LdapConnSettings::new(),
            Bind::new(
                "cn=serviceuser,ou=svcaccts,dc=example,dc=com".into(),
                "mysecret".into(),
            )
            .into(),
        );
        let pool = bb8::Pool::builder()
            .min_idle(None)
            .max_size(10)
            .max_lifetime(std::time::Duration::from_secs(30 * 60).into())
            .idle_timeout(std::time::Duration::from_secs(10 * 60).into())
            .connection_timeout(std::time::Duration::from_secs(30))
            .test_on_check_out(true)
            .build(manager)
            .await
            .unwrap();

        let mut ldap = pool.get().await.unwrap();

        let (rs, _res) = ldap
            .search(
                "dc=example,dc=com",
                Scope::Subtree,
                "(&(objectClass=posixAccount)(cn=johndoe))",
                vec!["cocomiel", "cn", "uidNumber"], //Vec::<String>::new(),
            )
            .await
            .unwrap()
            .success()
            .unwrap();
        for entry in rs {
            println!("{:#?}", SearchEntry::construct(entry));
        }
        ldap.unbind().await.unwrap()
    }
}
