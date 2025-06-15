/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{acl::Acl, collection::Collection};
use store::{ValueKey, query::acl::AclQuery, roaring::RoaringBitmap, write::ValueClass};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{Server, auth::AccessToken};

impl Server {
    pub async fn shared_containers(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: Collection,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> trc::Result<RoaringBitmap> {
        let check_acls = Bitmap::<Acl>::from_iter(check_acls);
        let mut document_ids = RoaringBitmap::new();
        let to_collection = u8::from(to_collection);
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            for acl_item in self
                .store()
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
                if acls == check_acls || (match_any && !acls.is_empty()) {
                    document_ids.insert(acl_item.to_document_id);
                }
            }
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
        for grant_account_id in [access_token.primary_id]
            .into_iter()
            .chain(access_token.member_of.iter().copied())
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

    pub async fn document_acl(
        &self,
        grant_account_id: u32,
        to_account_id: u32,
        to_collection: impl Into<u8>,
        to_document_id: u32,
    ) -> trc::Result<Bitmap<Acl>> {
        self.core
            .storage
            .data
            .get_value::<u64>(ValueKey {
                account_id: to_account_id,
                collection: to_collection.into(),
                document_id: to_document_id,
                class: ValueClass::Acl(grant_account_id),
            })
            .await
            .map(|v| v.map(Bitmap::<Acl>::from).unwrap_or_default())
    }
}
