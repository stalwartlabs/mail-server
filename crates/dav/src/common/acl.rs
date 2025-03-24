/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::schema::{
    property::Privilege,
    response::{Ace, GrantDeny, Href, Principal},
};
use directory::{QueryBy, backend::internal::PrincipalField};
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection, value::ArchivedAclGrant};
use rkyv::vec::ArchivedVec;
use store::ahash::AHashSet;
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{DavError, DavResource};

pub(crate) trait DavAclHandler: Sync + Send {
    fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = crate::Result<u32>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn validate_child_or_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        parent_id: Option<u32>,
        child_acl: impl Into<Bitmap<Acl>> + Send,
        parent_acl: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = crate::Result<()>> + Send;

    fn resolve_ace(
        &self,
        unresolved_aces: Vec<UnresolvedAce>,
    ) -> impl Future<Output = trc::Result<Vec<Ace>>> + Send;
}

impl DavAclHandler for Server {
    async fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<u32> {
        match parent_id {
            Some(parent_id) => {
                if access_token.is_member(account_id)
                    || self
                        .has_access_to_document(
                            access_token,
                            account_id,
                            collection,
                            parent_id,
                            check_acls,
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    Ok(parent_id + 1)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
            None => {
                if access_token.is_member(account_id) {
                    Ok(0)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
        }
    }

    async fn validate_child_or_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        parent_id: Option<u32>,
        child_acl: impl Into<Bitmap<Acl>> + Send,
        parent_acl: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<()> {
        if access_token.is_member(account_id)
            || self
                .has_access_to_document(
                    access_token,
                    account_id,
                    collection,
                    document_id,
                    child_acl,
                )
                .await
                .caused_by(trc::location!())?
            || (parent_id.is_some()
                && self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        collection,
                        parent_id.unwrap(),
                        parent_acl,
                    )
                    .await
                    .caused_by(trc::location!())?)
        {
            Ok(())
        } else {
            Err(DavError::Code(StatusCode::FORBIDDEN))
        }
    }

    async fn resolve_ace(&self, unresolved_aces: Vec<UnresolvedAce>) -> trc::Result<Vec<Ace>> {
        let mut aces = Vec::with_capacity(unresolved_aces.len());

        for ace in unresolved_aces {
            let grant_account_name = self
                .directory()
                .query(QueryBy::Id(ace.account_id), false)
                .await
                .caused_by(trc::location!())?
                .and_then(|mut p| p.take_str(PrincipalField::Name))
                .unwrap_or_else(|| format!("_{}", ace.account_id));

            aces.push(Ace::new(
                Principal::Href(Href(format!(
                    "{}/{}",
                    DavResource::Principal.base_path(),
                    grant_account_name,
                ))),
                GrantDeny::grant(ace.privileges),
            ));
        }

        Ok(aces)
    }
}

pub(crate) struct UnresolvedAce {
    account_id: u32,
    privileges: Vec<Privilege>,
}

pub(crate) trait Privileges {
    fn ace(&self, account_id: u32, grants: &ArchivedVec<ArchivedAclGrant>) -> Vec<UnresolvedAce>;

    fn current_privilege_set(
        &self,
        account_id: u32,
        grants: &ArchivedVec<ArchivedAclGrant>,
    ) -> Vec<Privilege>;
}

impl Privileges for AccessToken {
    fn ace(&self, account_id: u32, grants: &ArchivedVec<ArchivedAclGrant>) -> Vec<UnresolvedAce> {
        let mut aces = Vec::with_capacity(grants.len());
        if self.is_member(account_id) || grants.effective_acl(self).contains(Acl::Administer) {
            for grant in grants.iter() {
                let grant_account_id = u32::from(grant.account_id);
                let mut privileges = Vec::with_capacity(4);
                let acl = Bitmap::<Acl>::from(&grant.grants);
                if acl.contains(Acl::Read) || acl.contains(Acl::ReadItems) {
                    privileges.push(Privilege::Read);
                }
                if acl.contains(Acl::Modify)
                    || acl.contains(Acl::Delete)
                    || acl.contains(Acl::ModifyItems)
                    || acl.contains(Acl::RemoveItems)
                {
                    privileges.push(Privilege::Write);
                }
                if acl.contains(Acl::Administer) {
                    privileges.push(Privilege::ReadAcl);
                    privileges.push(Privilege::WriteAcl);
                }
                if acl.contains(Acl::ReadFreeBusy) {
                    privileges.push(Privilege::ReadFreeBusy);
                }

                aces.push(UnresolvedAce {
                    account_id: grant_account_id,
                    privileges,
                });
            }
        }
        aces
    }

    fn current_privilege_set(
        &self,
        account_id: u32,
        grants: &ArchivedVec<ArchivedAclGrant>,
    ) -> Vec<Privilege> {
        if self.is_member(account_id) {
            vec![
                Privilege::Read,
                Privilege::Write,
                Privilege::WriteProperties,
                Privilege::WriteContent,
                Privilege::Unlock,
                Privilege::ReadAcl,
                Privilege::ReadCurrentUserPrivilegeSet,
                Privilege::WriteAcl,
                Privilege::Bind,
                Privilege::Unbind,
                Privilege::ReadFreeBusy,
            ]
        } else {
            let mut acls = AHashSet::with_capacity(16);
            for grant in grants.effective_acl(self) {
                match grant {
                    Acl::Read | Acl::ReadItems => {
                        acls.insert(Privilege::Read);
                        acls.insert(Privilege::ReadCurrentUserPrivilegeSet);
                    }
                    Acl::Modify | Acl::Delete | Acl::ModifyItems | Acl::RemoveItems => {
                        acls.insert(Privilege::Write);
                    }
                    Acl::Administer => {
                        acls.insert(Privilege::ReadAcl);
                        acls.insert(Privilege::WriteAcl);
                    }
                    Acl::ReadFreeBusy => {
                        acls.insert(Privilege::ReadFreeBusy);
                    }
                    _ => {}
                }
            }

            acls.into_iter().collect()
        }
    }
}
