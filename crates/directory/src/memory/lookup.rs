use mail_send::Credentials;

use crate::{Directory, DirectoryError, Principal};

use super::{EmailType, MemoryDirectory};

#[async_trait::async_trait]
impl Directory for MemoryDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        let (username, secret) = match credentials {
            Credentials::Plain { username, secret } => (username, secret),
            Credentials::OAuthBearer { token } => (token, token),
            Credentials::XOauth2 { username, secret } => (username, secret),
        };
        match self
            .names
            .get(username)
            .and_then(|id| self.principals.get(*id as usize))
        {
            Some(principal) if principal.verify_secret(secret) => Ok(Some(principal.clone())),
            _ => Ok(None),
        }
    }

    async fn principal_by_name(&self, name: &str) -> crate::Result<Option<Principal>> {
        Ok(self
            .names
            .get(name)
            .and_then(|id| self.principals.get(*id as usize))
            .cloned())
    }

    async fn principal_by_id(&self, id: u32) -> crate::Result<Option<Principal>> {
        Ok(self.principals.get(id as usize).cloned())
    }

    async fn member_of(&self, principal: &Principal) -> crate::Result<Vec<u32>> {
        let mut result = Vec::with_capacity(principal.member_of.len());
        for member in &principal.member_of {
            if let Some(id) = self.names.get(member) {
                result.push(*id);
            }
        }
        Ok(result)
    }

    async fn emails_by_id(&self, id: u32) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        if let Some(emails) = self.ids_to_email.get(&id) {
            for email in emails {
                match email {
                    EmailType::Primary(email) | EmailType::Alias(email) => {
                        result.push(email.clone())
                    }
                    _ => {}
                }
            }
        }

        Ok(result)
    }

    async fn ids_by_email(&self, address: &str) -> crate::Result<Vec<u32>> {
        Ok(self
            .emails_to_ids
            .get(address)
            .map(|ids| {
                ids.iter()
                    .map(|t| match t {
                        EmailType::Primary(id) | EmailType::Alias(id) | EmailType::List(id) => *id,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default())
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        Ok(self.emails_to_ids.get(address).is_some())
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        for (key, value) in &self.emails_to_ids {
            if key.contains(address) && value.iter().any(|t| matches!(t, EmailType::Primary(_))) {
                result.push(key.clone())
            }
        }
        Ok(result)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        for (key, value) in &self.emails_to_ids {
            if key == address {
                for item in value {
                    if let EmailType::List(id) = item {
                        for addr in self.ids_to_email.get(id).unwrap() {
                            if let EmailType::Primary(addr) = addr {
                                result.push(addr.clone())
                            }
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    async fn query(&self, _query: &str, _params: &[&str]) -> crate::Result<bool> {
        Err(DirectoryError::unsupported("memory", "query"))
    }
}
