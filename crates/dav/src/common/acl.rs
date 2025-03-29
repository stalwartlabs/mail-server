/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::{
    RequestHeaders,
    schema::{
        property::{DavProperty, Privilege, WebDavProperty},
        request::{AclPrincipalPropSet, PropFind},
        response::{Ace, BaseCondition, GrantDeny, Href, MultiStatus, Principal},
    },
};
use directory::{QueryBy, Type, backend::internal::PrincipalField};
use groupware::{calendar::Calendar, contact::AddressBook, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::Collection,
    property::Property,
    value::{AclGrant, ArchivedAclGrant},
};
use rkyv::vec::ArchivedVec;
use store::{
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{
    DavError, DavErrorCondition, DavResource, common::uri::DavUriResource,
    principal::propfind::PrincipalPropFind,
};

pub(crate) trait DavAclHandler: Sync + Send {
    fn handle_acl_prop_set(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: AclPrincipalPropSet,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn validate_and_map_aces(
        &self,
        access_token: &AccessToken,
        acl: dav_proto::schema::request::Acl,
        collection: Collection,
    ) -> impl Future<Output = crate::Result<Vec<AclGrant>>> + Send;

    fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = crate::Result<u32>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn validate_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        acl: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = crate::Result<()>> + Send;

    fn resolve_ace(
        &self,
        unresolved_aces: Vec<UnresolvedAce>,
    ) -> impl Future<Output = trc::Result<Vec<Ace>>> + Send;
}

impl DavAclHandler for Server {
    async fn handle_acl_prop_set(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        mut request: AclPrincipalPropSet,
    ) -> crate::Result<HttpResponse> {
        let uri = self
            .validate_uri(access_token, headers.uri)
            .await
            .and_then(|uri| uri.into_owned_uri())?;
        let uri = self
            .map_uri_resource(uri)
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        if !matches!(
            uri.collection,
            Collection::Calendar | Collection::AddressBook | Collection::FileNode
        ) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let archive = self
            .get_property::<Archive<AlignedBytes>>(
                uri.account_id,
                uri.collection,
                uri.resource,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        let acls = match uri.collection {
            Collection::FileNode => {
                &archive
                    .unarchive::<FileNode>()
                    .caused_by(trc::location!())?
                    .acls
            }
            Collection::AddressBook => {
                &archive
                    .unarchive::<AddressBook>()
                    .caused_by(trc::location!())?
                    .acls
            }
            Collection::Calendar => {
                &archive
                    .unarchive::<Calendar>()
                    .caused_by(trc::location!())?
                    .acls
            }
            _ => unreachable!(),
        };

        // Validate ACLs
        if !access_token.is_member(uri.account_id)
            && !acls.effective_acl(access_token).contains(Acl::Read)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate
        let account_ids = RoaringBitmap::from_iter(acls.iter().map(|a| u32::from(a.account_id)));
        let mut response = MultiStatus::new(Vec::with_capacity(16));

        if !account_ids.is_empty() {
            if request.properties.is_empty() {
                request
                    .properties
                    .push(DavProperty::WebDav(WebDavProperty::DisplayName));
            }
            let request = PropFind::Prop(request.properties);
            self.prepare_principal_propfind_response(
                access_token,
                Collection::Principal,
                account_ids.into_iter(),
                &request,
                &mut response,
            )
            .await?;
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }

    async fn validate_and_map_aces(
        &self,
        access_token: &AccessToken,
        acl: dav_proto::schema::request::Acl,
        collection: Collection,
    ) -> crate::Result<Vec<AclGrant>> {
        let mut grants = Vec::with_capacity(acl.aces.len());
        for ace in acl.aces {
            if ace.invert {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::FORBIDDEN,
                    BaseCondition::NoInvert,
                )));
            }
            let privileges = match ace.grant_deny {
                GrantDeny::Grant(list) => list.0,
                GrantDeny::Deny(_) => {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::GrantOnly,
                    )));
                }
            };
            let principal_uri = match ace.principal {
                Principal::Href(href) => href.0,
                _ => {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::AllowedPrincipal,
                    )));
                }
            };

            let mut acls = Bitmap::<Acl>::default();
            for privilege in privileges {
                match privilege {
                    Privilege::Read => {
                        acls.insert(Acl::Read);
                        acls.insert(Acl::ReadItems);
                    }
                    Privilege::Write => {
                        acls.insert(Acl::Modify);
                        acls.insert(Acl::Delete);
                        acls.insert(Acl::ModifyItems);
                        acls.insert(Acl::RemoveItems);
                    }
                    Privilege::WriteContent => {
                        acls.insert(Acl::Modify);
                        acls.insert(Acl::ModifyItems);
                        acls.insert(Acl::RemoveItems);
                    }
                    Privilege::WriteProperties => {
                        acls.insert(Acl::Modify);
                    }
                    Privilege::ReadCurrentUserPrivilegeSet
                    | Privilege::Unlock
                    | Privilege::Bind
                    | Privilege::Unbind => {}
                    Privilege::All => {
                        return Err(DavError::Condition(DavErrorCondition::new(
                            StatusCode::FORBIDDEN,
                            BaseCondition::NoAbstract,
                        )));
                    }
                    Privilege::ReadAcl => {}
                    Privilege::WriteAcl => {
                        acls.insert(Acl::Administer);
                    }
                    Privilege::ReadFreeBusy => {
                        if collection == Collection::Calendar {
                            acls.insert(Acl::ReadFreeBusy);
                        } else {
                            return Err(DavError::Condition(DavErrorCondition::new(
                                StatusCode::FORBIDDEN,
                                BaseCondition::NotSupportedPrivilege,
                            )));
                        }
                    }
                }
            }

            if acls.is_empty() {
                continue;
            }

            let principal_id = self
                .validate_uri(access_token, &principal_uri)
                .await
                .map_err(|_| {
                    DavError::Condition(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::AllowedPrincipal,
                    ))
                })?
                .account_id
                .ok_or_else(|| {
                    DavError::Condition(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::AllowedPrincipal,
                    ))
                })?;

            // Verify that the principal is a valid principal
            let principal = self
                .directory()
                .query(QueryBy::Id(principal_id), false)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| {
                    DavError::Condition(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::AllowedPrincipal,
                    ))
                })?;
            if !matches!(principal.typ(), Type::Individual | Type::Group) {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::FORBIDDEN,
                    BaseCondition::AllowedPrincipal,
                )));
            }

            grants.push(AclGrant {
                account_id: principal_id,
                grants: acls,
            });
        }

        Ok(grants)
    }

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

    async fn validate_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        acl: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<()> {
        if access_token.is_member(account_id)
            || self
                .has_access_to_document(access_token, account_id, collection, document_id, acl)
                .await
                .caused_by(trc::location!())?
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
