/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavResources, auth::AccessToken};
use jmap_proto::types::acl::Acl;
use store::roaring::RoaringBitmap;
use utils::map::bitmap::Bitmap;

impl DavResources {
    pub fn shared_containers(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let check_acls = Bitmap::<Acl>::from_iter(check_acls);
        let mut document_ids = RoaringBitmap::new();

        for resource in &self.resources {
            if let Some(acls) = resource.acls() {
                for acl in acls {
                    if access_token.is_member(acl.account_id) {
                        let mut grants = acl.grants;
                        grants.intersection(&check_acls);
                        if grants == check_acls || (match_any && !grants.is_empty()) {
                            document_ids.insert(resource.document_id);
                        }
                    }
                }
            }
        }

        document_ids
    }

    pub fn has_access_to_container(
        &self,
        access_token: &AccessToken,
        document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> bool {
        let check_acls = check_acls.into();

        for resource in &self.resources {
            if resource.document_id == document_id {
                if let Some(acls) = resource.acls() {
                    for acl in acls {
                        if access_token.is_member(acl.account_id) {
                            let mut grants = acl.grants;
                            grants.intersection(&check_acls);
                            return !grants.is_empty();
                        }
                    }
                    break;
                }
            }
        }

        false
    }

    pub fn container_acl(&self, access_token: &AccessToken, document_id: u32) -> Bitmap<Acl> {
        let mut account_acls = Bitmap::<Acl>::new();

        for resource in &self.resources {
            if resource.document_id == document_id {
                if let Some(acls) = resource.acls() {
                    for acl in acls {
                        if access_token.is_member(acl.account_id) {
                            account_acls.union(&acl.grants);
                        }
                    }
                    break;
                }
            }
        }

        account_acls
    }
}
