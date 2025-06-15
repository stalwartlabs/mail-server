/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::AccessToken;
use jmap_proto::types::{
    acl::Acl,
    value::{AclGrant, ArchivedAclGrant},
};
use rkyv::vec::ArchivedVec;
use utils::map::bitmap::Bitmap;

pub mod acl;
pub mod document;
pub mod resources;

pub trait EffectiveAcl {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl>;
}

impl EffectiveAcl for Vec<AclGrant> {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl> {
        self.as_slice().effective_acl(access_token)
    }
}

impl EffectiveAcl for &[AclGrant] {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl> {
        let mut acl = Bitmap::<Acl>::new();
        for item in self.iter() {
            if access_token.is_member(item.account_id) {
                acl.union(&item.grants);
            }
        }

        acl
    }
}

impl EffectiveAcl for ArchivedVec<ArchivedAclGrant> {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl> {
        let mut acl = Bitmap::<Acl>::new();
        for item in self.iter() {
            if access_token.is_member(item.account_id.into()) {
                acl.union_raw(item.grants.bitmap);
            }
        }

        acl
    }
}
