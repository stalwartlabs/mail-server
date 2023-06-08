use mail_send::Credentials;

use crate::{to_catch_all_address, unwrap_subaddress, Directory, DirectoryError, Principal};

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
            Some(principal) if principal.verify_secret(secret).await => Ok(Some(principal.clone())),
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
            .get(unwrap_subaddress(address, self.opt.subaddressing).as_ref())
            .or_else(|| {
                if self.opt.catch_all {
                    self.emails_to_ids.get(&to_catch_all_address(address))
                } else {
                    None
                }
            })
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
        Ok(self
            .emails_to_ids
            .contains_key(unwrap_subaddress(address, self.opt.subaddressing).as_ref())
            || (self.opt.catch_all && self.domains.contains(&to_catch_all_address(address))))
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        let address = unwrap_subaddress(address, self.opt.subaddressing);
        for (key, value) in &self.emails_to_ids {
            if key.contains(address.as_ref())
                && value.iter().any(|t| matches!(t, EmailType::Primary(_)))
            {
                result.push(key.clone())
            }
        }
        Ok(result)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        let address = unwrap_subaddress(address, self.opt.subaddressing);
        for (key, value) in &self.emails_to_ids {
            if key == address.as_ref() {
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

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}
