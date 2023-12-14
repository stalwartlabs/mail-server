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

use jmap_proto::types::collection::Collection;
use store::{
    write::{assert::HashedValue, BatchBuilder, DirectoryValue, ValueClass},
    Serialize, Store, ValueKey,
};

use crate::{Principal, Type};

#[async_trait::async_trait]
pub trait ManageDirectory {
    async fn delete_account_by_name(&self, name: &str) -> store::Result<bool>;
    async fn delete_account_by_id(&self, id: u32) -> store::Result<bool>;
    async fn rename_account(&self, name: &str, new_name: String) -> store::Result<bool>;
    async fn get_account_id(&self, name: &str) -> store::Result<Option<u32>>;
    async fn get_or_create_account_id(&self, name: &str) -> crate::Result<u32>;
}

#[async_trait::async_trait]
impl ManageDirectory for Store {
    async fn get_account_id(&self, name: &str) -> store::Result<Option<u32>> {
        self.get_value::<u32>(ValueKey::from(ValueClass::Directory(
            DirectoryValue::NameToId(name.as_bytes().to_vec()),
        )))
        .await
    }

    // Used by all directories except internal
    async fn get_or_create_account_id(&self, name: &str) -> crate::Result<u32> {
        let mut try_count = 0;

        loop {
            // Try to obtain ID
            if let Some(account_id) = self.get_account_id(name).await? {
                return Ok(account_id);
            }

            // Assign new ID
            let account_id = self
                .assign_document_id(u32::MAX, Collection::Principal)
                .await?;

            // Write account ID
            let name_key =
                ValueClass::Directory(DirectoryValue::NameToId(name.as_bytes().to_vec()));
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .create_document(account_id)
                .assert_value(name_key.clone(), ())
                .set(name_key, account_id.serialize())
                .set(
                    ValueClass::Directory(DirectoryValue::Principal(account_id)),
                    Principal {
                        id: account_id,
                        typ: Type::Individual,
                        name: name.to_string(),
                        ..Default::default()
                    }
                    .serialize(),
                );

            match self.write(batch.build()).await {
                Ok(_) => {
                    return Ok(account_id);
                }
                Err(store::Error::AssertValueFailed) if try_count < 3 => {
                    try_count += 1;
                    continue;
                }
                Err(err) => {
                    tracing::error!(event = "error",
                                            context = "store",
                                            error = ?err,
                                            "Failed to generate account id");
                    return Err(err.into());
                }
            }
        }
    }

    async fn delete_account_by_name(&self, name: &str) -> store::Result<bool> {
        if let Some(account_id) = self.get_account_id(name).await? {
            self.delete_account_by_id(account_id).await
        } else {
            Ok(false)
        }
    }

    async fn delete_account_by_id(&self, account_id: u32) -> store::Result<bool> {
        let principal = if let Some(principal) = self
            .get_value::<Principal>(ValueKey::from(ValueClass::Directory(
                DirectoryValue::Principal(account_id),
            )))
            .await?
        {
            principal
        } else {
            return Ok(false);
        };

        // Unlink all account's blobs
        self.blob_hash_unlink_account(account_id).await?;

        // Revoke ACLs
        self.acl_revoke_all(account_id).await?;

        // Delete account
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .clear(DirectoryValue::NameToId(principal.name.as_bytes().to_vec()))
            .clear(DirectoryValue::Principal(account_id))
            .clear(DirectoryValue::UsedQuota(account_id));

        for email in principal.emails {
            batch.clear(DirectoryValue::EmailToId(email.as_bytes().to_vec()));
        }

        self.write(batch.build()).await?;

        // Delete account data
        self.purge_account(account_id).await?;

        Ok(true)
    }

    async fn rename_account(&self, name: &str, new_name: String) -> store::Result<bool> {
        if let Some(account_id) = self.get_account_id(name).await? {
            if let Some(mut principal) = self
                .get_value::<HashedValue<Principal>>(ValueKey::from(ValueClass::Directory(
                    DirectoryValue::Principal(account_id),
                )))
                .await?
            {
                if principal.inner.name != name {
                    return Ok(false);
                }
                principal.inner.name = new_name.clone();

                let mut batch = BatchBuilder::new();
                batch
                    .assert_value(
                        ValueClass::Directory(DirectoryValue::Principal(account_id)),
                        &principal,
                    )
                    .set(
                        ValueClass::Directory(DirectoryValue::Principal(account_id)),
                        principal.inner.serialize(),
                    )
                    .clear(ValueClass::Directory(DirectoryValue::NameToId(
                        name.as_bytes().to_vec(),
                    )))
                    .set(
                        ValueClass::Directory(DirectoryValue::NameToId(new_name.into_bytes())),
                        account_id.serialize(),
                    );
                self.write(batch.build()).await?;

                return Ok(true);
            }
        }

        Ok(false)
    }
}

/*
pub async fn try_get_account_id(store: &Store, name: &str) -> crate::Result<Option<u32>> {
    store
        .get_value::<u32>(NamedKey::Name(name))
        .await
        .map_err(|err| {
            tracing::error!(event = "error",
            context = "store",
            account_name = name,
            error = ?err,
            "Failed to retrieve account id");
            MethodError::ServerPartialFail
        })
}



pub async fn map_member_of(store: &Store, names: Vec<String>) -> crate::Result<Vec<u32>> {
    let mut ids = Vec::with_capacity(names.len());
    for name in names {
        ids.push(self.get_account_id(&name).await?);
    }
    Ok(ids)
}

pub async fn get_account_name(store: &Store, account_id: u32) -> crate::Result<Option<String>> {
    store
        .get_value::<String>(NamedKey::Id::<&[u8]>(account_id))
        .await
        .map_err(|err| {
            tracing::error!(event = "error",
                        context = "store",
                        account_id = account_id,
                        error = ?err,
                        "Failed to retrieve account name");
            MethodError::ServerPartialFail
        })
}
*/
