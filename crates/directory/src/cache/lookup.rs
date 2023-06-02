use mail_send::Credentials;

use crate::{Directory, Principal};

use super::CachedDirectory;

#[async_trait::async_trait]
impl<T: Directory> Directory for CachedDirectory<T> {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        self.inner.authenticate(credentials).await
    }

    async fn principal_by_name(&self, name: &str) -> crate::Result<Option<Principal>> {
        self.inner.principal_by_name(name).await
    }

    async fn principal_by_id(&self, id: u32) -> crate::Result<Option<Principal>> {
        self.inner.principal_by_id(id).await
    }

    async fn member_of(&self, _principal: &Principal) -> crate::Result<Vec<u32>> {
        self.inner.member_of(_principal).await
    }

    async fn emails_by_id(&self, id: u32) -> crate::Result<Vec<String>> {
        self.inner.emails_by_id(id).await
    }

    async fn ids_by_email(&self, address: &str) -> crate::Result<Vec<u32>> {
        self.inner.ids_by_email(address).await
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        if let Some(result) = {
            let result = self.cached_rcpts.lock().get(address);
            result
        } {
            Ok(result)
        } else if self.inner.rcpt(address).await? {
            self.cached_rcpts.lock().insert_pos(address.to_string());
            Ok(true)
        } else {
            self.cached_rcpts.lock().insert_neg(address.to_string());
            Ok(false)
        }
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        self.inner.vrfy(address).await
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        self.inner.expn(address).await
    }

    async fn query(&self, query: &str, params: &[&str]) -> crate::Result<bool> {
        self.inner.query(query, params).await
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        if let Some(result) = {
            let result = self.cached_domains.lock().get(domain);
            result
        } {
            Ok(result)
        } else if self.inner.is_local_domain(domain).await? {
            self.cached_domains.lock().insert_pos(domain.to_string());
            Ok(true)
        } else {
            self.cached_domains.lock().insert_neg(domain.to_string());
            Ok(false)
        }
    }
}
