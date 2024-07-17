/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;

use crate::{
    write::{key::DeserializeBigEndian, BatchBuilder, Operation, ValueClass, ValueOp},
    Deserialize, IterateParams, Store, ValueKey, U32_LEN,
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
    pub async fn acl_query(&self, query: AclQuery) -> trc::Result<Vec<AclItem>> {
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
        .await
        .caused_by(trc::location!())
        .map(|_| results)
    }

    pub async fn acl_revoke_all(&self, account_id: u32) -> trc::Result<()> {
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
        .await
        .caused_by(trc::location!())?;

        // Remove permissions
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        let mut last_collection = u8::MAX;
        for (class, acl_item) in delete_keys.into_iter() {
            if batch.ops.len() >= 1000 {
                self.write(batch.build())
                    .await
                    .caused_by(trc::location!())?;
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
            self.write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }
}

impl Deserialize for AclItem {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(AclItem {
            to_account_id: bytes.deserialize_be_u32(U32_LEN)?,
            to_collection: *bytes
                .get(U32_LEN * 2)
                .ok_or_else(|| trc::StoreCause::DataCorruption.caused_by(trc::location!()))?,
            to_document_id: bytes.deserialize_be_u32((U32_LEN * 2) + 1)?,
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
