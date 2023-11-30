/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use crate::{
    write::{key::DeserializeBigEndian, BatchBuilder, Operation, ValueClass, ValueOp},
    Deserialize, Error, IterateParams, Store, ValueKey, U32_LEN,
};

pub enum AclQuery {
    SharedWith {
        grant_account_id: u32,
        to_account_id: u32,
        to_collection: u8,
    },
    HasAccess {
        grant_account_id: u32,
    },
}

#[derive(Debug)]
pub struct AclItem {
    pub to_account_id: u32,
    pub to_collection: u8,
    pub to_document_id: u32,
    pub permissions: u64,
}

impl Store {
    pub async fn acl_query(&self, query: AclQuery) -> crate::Result<Vec<AclItem>> {
        let mut results = Vec::new();
        let (from_key, to_key) = match query {
            AclQuery::SharedWith {
                grant_account_id,
                to_account_id,
                to_collection,
            } => {
                let from_key = ValueKey {
                    account_id: to_account_id,
                    collection: to_collection,
                    document_id: 0,
                    class: ValueClass::Acl(grant_account_id),
                };
                let mut to_key = from_key.clone();
                to_key.document_id = u32::MAX;

                (from_key, to_key)
            }
            AclQuery::HasAccess { grant_account_id } => (
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Acl(grant_account_id),
                },
                ValueKey {
                    account_id: u32::MAX,
                    collection: u8::MAX,
                    document_id: u32::MAX,
                    class: ValueClass::Acl(grant_account_id),
                },
            ),
        };

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                results.push(AclItem::deserialize(key)?.with_permissions(u64::deserialize(value)?));

                Ok(true)
            },
        )
        .await?;

        Ok(results)
    }

    pub async fn acl_revoke_all(&self, account_id: u32) -> crate::Result<()> {
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Acl(0),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Acl(u32::MAX),
        };

        let mut delete_keys = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                if account_id == key.deserialize_be_u32(U32_LEN)? {
                    delete_keys.push((
                        ValueClass::Acl(key.deserialize_be_u32(0)?),
                        AclItem::deserialize(key)?,
                    ));
                }

                Ok(true)
            },
        )
        .await?;

        // Remove permissions
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        let mut last_collection = u8::MAX;
        for (pos, (class, acl_item)) in delete_keys.into_iter().enumerate() {
            if pos > 0 && pos & 511 == 0 {
                self.write(batch.build()).await?;
                batch = BatchBuilder::new();
                batch.with_account_id(account_id);
                last_collection = u8::MAX;
            }
            if acl_item.to_collection != last_collection {
                batch.with_collection(acl_item.to_collection);
                last_collection = acl_item.to_collection;
            }
            batch.update_document(acl_item.to_document_id);
            batch.ops.push(Operation::Value {
                class,
                op: ValueOp::Clear,
            })
        }
        if !batch.is_empty() {
            self.write(batch.build()).await?;
        }

        Ok(())
    }
}

impl Deserialize for AclItem {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(AclItem {
            to_account_id: bytes.deserialize_be_u32(U32_LEN + 1)?,
            to_collection: *bytes
                .get((U32_LEN * 2) + 1)
                .ok_or_else(|| Error::InternalError(format!("Corrupted acl key {bytes:?}")))?,
            to_document_id: bytes.deserialize_be_u32((U32_LEN * 2) + 2)?,
            permissions: 0,
        })
    }
}

impl AclItem {
    fn with_permissions(mut self, permissions: u64) -> Self {
        self.permissions = permissions;
        self
    }
}
