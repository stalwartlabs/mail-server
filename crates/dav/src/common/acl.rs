/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavErrorCondition, DavResourceName, common::uri::DavUriResource,
    principal::propfind::PrincipalPropFind,
};
use common::{DavResources, Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::{
    RequestHeaders,
    schema::{
        property::{DavProperty, Privilege, WebDavProperty},
        request::{AclPrincipalPropSet, PropFind},
        response::{Ace, BaseCondition, GrantDeny, Href, MultiStatus, Principal},
    },
};
use directory::{QueryBy, Type, backend::internal::manage::ManageDirectory};
use groupware::RFC_3986;
use groupware::{cache::GroupwareCache, calendar::Calendar, contact::AddressBook, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::Collection,
    value::{AclGrant, ArchivedAclGrant},
};
use rkyv::vec::ArchivedVec;
use store::{ahash::AHashSet, roaring::RoaringBitmap, write::BatchBuilder};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use super::ArchivedResource;

pub(crate) trait DavAclHandler: Sync + Send {
    fn handle_acl_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: dav_proto::schema::request::Acl,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_acl_prop_set(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: AclPrincipalPropSet,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn validate_and_map_aces(
        &self,
        access_token: &AccessToken,
        acl: dav_proto::schema::request::Acl,
        collection: Collection,
    ) -> impl Future<Output = crate::Result<Vec<AclGrant>>> + Send;

    fn resolve_ace(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        grants: &ArchivedVec<ArchivedAclGrant>,
        expand: Option<&PropFind>,
    ) -> impl Future<Output = crate::Result<Vec<Ace>>> + Send;
}

pub(crate) trait ResourceAcl {
    fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        is_member: bool,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<u32>;
}

impl DavAclHandler for Server {
    async fn handle_acl_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: dav_proto::schema::request::Acl,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let collection = resource_.collection;

        if !matches!(
            collection,
            Collection::AddressBook | Collection::Calendar | Collection::FileNode
        ) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }
        let resources = self
            .fetch_dav_resources(access_token, account_id, collection.into())
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|r| resources.by_path(r))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if !resource.resource.is_container() && !matches!(collection, Collection::FileNode) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Fetch node
        let archive = self
            .get_archive(account_id, collection, resource.document_id())
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        let container =
            ArchivedResource::from_archive(&archive, collection).caused_by(trc::location!())?;

        // Validate ACL
        let acls = container.acls().unwrap();
        if !access_token.is_member(account_id)
            && !acls.effective_acl(access_token).contains(Acl::Administer)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate ACEs
        let grants = self
            .validate_and_map_aces(access_token, request, collection)
            .await?;

        if grants.len() != acls.len() || acls.iter().zip(grants.iter()).any(|(a, b)| a != b) {
            // Refresh ACLs
            self.refresh_archived_acls(&grants, acls).await;

            let mut batch = BatchBuilder::new();
            match container {
                ArchivedResource::Calendar(calendar) => {
                    let mut new_calendar = calendar
                        .deserialize::<Calendar>()
                        .caused_by(trc::location!())?;
                    new_calendar.acls = grants;
                    new_calendar
                        .update(
                            access_token,
                            calendar,
                            account_id,
                            resource.document_id(),
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;
                }
                ArchivedResource::AddressBook(book) => {
                    let mut new_book = book
                        .deserialize::<AddressBook>()
                        .caused_by(trc::location!())?;
                    new_book.acls = grants;
                    new_book
                        .update(
                            access_token,
                            book,
                            account_id,
                            resource.document_id(),
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;
                }
                ArchivedResource::FileNode(node) => {
                    let mut new_node =
                        node.deserialize::<FileNode>().caused_by(trc::location!())?;
                    new_node.acls = grants;
                    new_node
                        .update(
                            access_token,
                            node,
                            account_id,
                            resource.document_id(),
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;
                }
                _ => unreachable!(),
            }

            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::OK))
    }

    async fn handle_acl_prop_set(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut request: AclPrincipalPropSet,
    ) -> crate::Result<HttpResponse> {
        let uri = self
            .validate_uri(access_token, headers.uri)
            .await
            .and_then(|uri| uri.into_owned_uri())?;
        let uri = self
            .map_uri_resource(access_token, uri)
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
            .get_archive(uri.account_id, uri.collection, uri.resource)
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

    async fn resolve_ace(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        grants: &ArchivedVec<ArchivedAclGrant>,
        expand: Option<&PropFind>,
    ) -> crate::Result<Vec<Ace>> {
        let mut aces = Vec::with_capacity(grants.len());
        if access_token.is_member(account_id)
            || grants.effective_acl(access_token).contains(Acl::Administer)
        {
            for grant in grants.iter() {
                let grant_account_id = u32::from(grant.account_id);
                let principal = if let Some(expand) = expand {
                    self.expand_principal(access_token, grant_account_id, expand)
                        .await?
                        .map(Principal::Response)
                        .unwrap_or_else(|| {
                            Principal::Href(Href(format!(
                                "{}/_{grant_account_id}/",
                                DavResourceName::Principal.base_path(),
                            )))
                        })
                } else {
                    let grant_account_name = self
                        .store()
                        .get_principal_name(grant_account_id)
                        .await
                        .caused_by(trc::location!())?
                        .unwrap_or_else(|| format!("_{grant_account_id}"));

                    Principal::Href(Href(format!(
                        "{}/{}/",
                        DavResourceName::Principal.base_path(),
                        percent_encoding::utf8_percent_encode(&grant_account_name, RFC_3986),
                    )))
                };

                aces.push(Ace::new(
                    principal,
                    GrantDeny::grant(current_user_privilege_set(Bitmap::<Acl>::from(
                        &grant.grants,
                    ))),
                ));
            }
        }

        Ok(aces)
    }
}

impl ResourceAcl for DavResources {
    fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        is_member: bool,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<u32> {
        match parent_id {
            Some(parent_id) => {
                if is_member || self.has_access_to_container(access_token, parent_id, check_acls) {
                    Ok(parent_id + 1)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
            None => {
                if is_member {
                    Ok(0)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
        }
    }
}

pub(crate) trait Privileges {
    fn current_privilege_set(
        &self,
        account_id: u32,
        grants: &ArchivedVec<ArchivedAclGrant>,
        is_calendar: bool,
    ) -> Vec<Privilege>;
}

impl Privileges for AccessToken {
    fn current_privilege_set(
        &self,
        account_id: u32,
        grants: &ArchivedVec<ArchivedAclGrant>,
        is_calendar: bool,
    ) -> Vec<Privilege> {
        if self.is_member(account_id) {
            Privilege::all(is_calendar)
        } else {
            current_user_privilege_set(grants.effective_acl(self))
        }
    }
}

pub(crate) fn current_user_privilege_set(acl_bitmap: Bitmap<Acl>) -> Vec<Privilege> {
    let mut acls = AHashSet::with_capacity(16);
    for grant in acl_bitmap {
        match grant {
            Acl::Read | Acl::ReadItems => {
                acls.insert(Privilege::Read);
                acls.insert(Privilege::ReadCurrentUserPrivilegeSet);
            }
            Acl::Modify => {
                acls.insert(Privilege::WriteProperties);
            }
            Acl::ModifyItems => {
                acls.insert(Privilege::WriteContent);
            }
            Acl::Delete | Acl::RemoveItems => {
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
