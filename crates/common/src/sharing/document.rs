/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{acl::Acl, collection::Collection};
use store::{ValueKey, query::acl::AclQuery, roaring::RoaringBitmap, write::ValueClass};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{Server, auth::AccessToken};

impl Server {
    pub async fn shared_documents(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
        let check_acls = check_acls.into();
        let mut document_ids = RoaringBitmap::new();
        let to_collection = u8::from(to_collection);
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            for acl_item in self
                .core
                .storage
                .data
                .acl_query(AclQuery::SharedWith {
                    grant_account_id,
                    to_account_id,
                    to_collection,
                })
                .await
                .caused_by(trc::location!())?
            {
                let mut acls = Bitmap::<Acl>::from(acl_item.permissions);

                acls.intersection(&check_acls);
                if !acls.is_empty() {
                    document_ids.insert(acl_item.to_document_id);
                }
            }
        }

        Ok(document_ids)
    }

    pub async fn shared_document_children(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
        let check_acls = check_acls.into();
        let shared_documents = self
            .shared_documents(access_token, to_account_id, to_collection, check_acls)
            .await?;
        if shared_documents.is_empty() {
            return Ok(shared_documents);
        }
        let child_collection = to_collection.child_collection().unwrap();
        let child_property = child_collection.parent_property().unwrap();
        let mut shared_items = RoaringBitmap::new();
        for document_id in shared_documents {
            if let Some(documents_in_folder) = self
                .get_tag(
                    to_account_id,
                    child_collection,
                    child_property.clone(),
                    document_id,
                )
                .await?
            {
                shared_items |= documents_in_folder;
            }
        }

        Ok(shared_items)
    }

    pub async fn owned_or_shared_documents(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
        let check_acls = check_acls.into();
        let mut document_ids = self
            .get_document_ids(account_id, collection)
            .await?
            .unwrap_or_default();
        if !document_ids.is_empty() && !access_token.is_member(account_id) {
            document_ids &= self
                .shared_documents(access_token, account_id, collection, check_acls)
                .await?;
        }
        Ok(document_ids)
    }

    pub async fn owned_or_shared_document_children(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
        let check_acls = check_acls.into();
        let mut document_ids = self
            .get_document_ids(account_id, collection)
            .await?
            .unwrap_or_default();
        if !document_ids.is_empty() && !access_token.is_member(account_id) {
            document_ids &= self
                .shared_document_children(access_token, account_id, collection, check_acls)
                .await?;
        }
        Ok(document_ids)
    }

    pub async fn has_access_to_document(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: impl Into<u8>,
        to_document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<bool> {
        let to_collection = to_collection.into();
        let check_acls = check_acls.into();
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            match self
                .core
                .storage
                .data
                .get_value::<u64>(ValueKey {
                    account_id: to_account_id,
                    collection: to_collection,
                    document_id: to_document_id,
                    class: ValueClass::Acl(grant_account_id),
                })
                .await
            {
                Ok(Some(acls)) => {
                    let mut acls = Bitmap::<Acl>::from(acls);

                    acls.intersection(&check_acls);
                    if !acls.is_empty() {
                        return Ok(true);
                    }
                }
                Ok(None) => (),
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
        Ok(false)
    }
}
