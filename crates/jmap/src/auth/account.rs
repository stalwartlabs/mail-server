use jmap_proto::types::collection::Collection;

use crate::{JMAP, SUPERUSER_ID};

use super::{AccountDetails, AccountKey, AclToken};

impl JMAP {
    pub async fn authenticate(&self, account: &str, secret: &str) -> Option<AclToken> {
        todo!()
    }

    pub async fn get_acl_token(&self, account_id: u32) -> Option<AclToken> {
        todo!()
    }

    pub async fn get_account_details(&self, account: &str) -> Option<AccountDetails> {
        None
    }

    pub async fn map_account_id(&self, account: &str) -> Option<u32> {
        match self
            .store
            .get_value::<u32>(AccountKey::new(account.to_lowercase()))
            .await
        {
            Ok(Some(id)) => Some(id),
            Ok(None) => {
                match self
                    .assign_document_id(SUPERUSER_ID, Collection::Identity)
                    .await
                {
                    Ok(account_id) => {
                        match self
                            .store
                            .set_value(AccountKey::new(account.to_lowercase()), account_id)
                            .await
                        {
                            Ok(_) => Some(account_id),
                            Err(err) => {
                                tracing::error!(
                                    event = "error",
                                    context = "get_account_id",
                                    error = ?err,
                                    "Failed to write account id.");
                                None
                            }
                        }
                    }
                    Err(_) => None,
                }
            }
            Err(err) => {
                tracing::error!(
                    event = "error",
                    context = "get_account_id",
                    error = ?err,
                    "Failed to obtain account id.");
                None
            }
        }
    }

    pub async fn map_account_name(&self, account_id: u32) -> Option<String> {
        None
    }
}
