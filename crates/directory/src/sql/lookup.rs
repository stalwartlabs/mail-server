use mail_send::Credentials;
use sqlx::{any::AnyRow, Column, Row};

use crate::{Directory, Principal, Type};

use super::{SqlDirectory, SqlMappings};

#[async_trait::async_trait]
impl Directory for SqlDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        let (username, secret) = match credentials {
            Credentials::Plain { username, secret } => (username, secret),
            Credentials::OAuthBearer { token } => (token, token),
            Credentials::XOauth2 { username, secret } => (username, secret),
        };

        if let Some(row) = sqlx::query(&self.mappings.query_login)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?
        {
            self.mappings.row_to_principal(row).map(|p| {
                if p.verify_secret(secret) {
                    Some(p)
                } else {
                    None
                }
            })
        } else {
            Ok(None)
        }
    }

    async fn principal_by_name(&self, name: &str) -> crate::Result<Option<Principal>> {
        if let Some(row) = sqlx::query(&self.mappings.query_name)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
        {
            self.mappings.row_to_principal(row).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn principal_by_id(&self, id: u32) -> crate::Result<Option<Principal>> {
        if let Some(row) = sqlx::query(&self.mappings.query_id)
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await?
        {
            self.mappings.row_to_principal(row).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn member_of(&self, principal: &Principal) -> crate::Result<Vec<u32>> {
        sqlx::query_scalar::<_, i64>(&self.mappings.query_members)
            .bind(principal.id as i64)
            .fetch_all(&self.pool)
            .await
            .map(|ids| ids.into_iter().map(|id| id as u32).collect())
            .map_err(Into::into)
    }

    async fn emails_by_id(&self, id: u32) -> crate::Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(&self.mappings.query_emails)
            .bind(id as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    async fn ids_by_email(&self, address: &str) -> crate::Result<Vec<u32>> {
        sqlx::query_scalar::<_, i64>(&self.mappings.query_recipients)
            .bind(address)
            .fetch_all(&self.pool)
            .await
            .map(|ids| ids.into_iter().map(|id| id as u32).collect())
            .map_err(Into::into)
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        sqlx::query(&self.mappings.query_recipients)
            .bind(address)
            .fetch_optional(&self.pool)
            .await
            .map(|id| id.is_some())
            .map_err(Into::into)
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(&self.mappings.query_verify)
            .bind(address)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(&self.mappings.query_expand)
            .bind(address)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    async fn query(&self, query: &str, params: &[&str]) -> crate::Result<bool> {
        let mut q = sqlx::query(query);
        for param in params {
            q = q.bind(param);
        }

        q.fetch_optional(&self.pool)
            .await
            .map(|r| r.is_some())
            .map_err(Into::into)
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        if self.domains.contains(domain) {
            return Ok(true);
        }

        sqlx::query(&self.mappings.query_domains)
            .bind(domain)
            .fetch_optional(&self.pool)
            .await
            .map(|id| id.is_some())
            .map_err(Into::into)
    }
}

impl SqlMappings {
    pub fn row_to_principal(&self, row: AnyRow) -> crate::Result<Principal> {
        let mut principal = Principal {
            id: u32::MAX,
            ..Default::default()
        };
        for col in row.columns() {
            let name = col.name();
            let idx = col.ordinal();
            if name.eq_ignore_ascii_case(&self.column_id) {
                principal.id = row.try_get::<i64, _>(idx)? as u32;
            } else if name.eq_ignore_ascii_case(&self.column_name) {
                principal.name = row.try_get::<Option<String>, _>(idx)?.unwrap_or_default();
            } else if name.eq_ignore_ascii_case(&self.column_secret) {
                if let Some(secret) = row.try_get::<Option<String>, _>(idx)? {
                    principal.secrets.push(secret);
                }
            } else if name.eq_ignore_ascii_case(&self.column_type) {
                if let Some(typ) = row.try_get::<Option<String>, _>(idx)? {
                    match typ.as_str() {
                        "individual" | "person" | "user" => principal.typ = Type::Individual,
                        "group" => principal.typ = Type::Group,
                        _ => (),
                    }
                }
            } else if name.eq_ignore_ascii_case(&self.column_description) {
                principal.description = row.try_get::<Option<String>, _>(idx)?;
            } else if name.eq_ignore_ascii_case(&self.column_quota) {
                principal.quota = row.try_get::<i64, _>(idx).unwrap_or_default() as u32;
            }
        }

        Ok(principal)
    }
}
