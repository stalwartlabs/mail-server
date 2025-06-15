/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError,
    common::uri::{OwnedUri, UriResource},
};
use common::{DavResourcePath, DavResources};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use hyper::StatusCode;

pub mod copy_move;
pub mod delete;
pub mod get;
pub mod mkcol;
pub mod proppatch;
pub mod update;

pub(crate) static FILE_CONTAINER_PROPS: [DavProperty; 19] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes),
    DavProperty::WebDav(WebDavProperty::QuotaUsedBytes),
];

pub(crate) static FILE_ITEM_PROPS: [DavProperty; 19] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
];

pub(crate) trait FromDavResource {
    fn from_dav_resource(item: DavResourcePath<'_>) -> Self;
}

pub(crate) struct FileItemId {
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
}

pub(crate) trait DavFileResource {
    fn map_resource<T: FromDavResource>(
        &self,
        resource: &OwnedUri<'_>,
    ) -> crate::Result<UriResource<u32, T>>;

    fn map_parent<'x>(&self, resource: &'x str) -> Option<(Option<DavResourcePath<'_>>, &'x str)>;

    #[allow(clippy::type_complexity)]
    fn map_parent_resource<'x, T: FromDavResource>(
        &self,
        resource: &OwnedUri<'x>,
    ) -> crate::Result<UriResource<u32, (Option<T>, &'x str)>>;
}

impl DavFileResource for DavResources {
    fn map_resource<T: FromDavResource>(
        &self,
        resource: &OwnedUri<'_>,
    ) -> crate::Result<UriResource<u32, T>> {
        resource
            .resource
            .and_then(|r| self.by_path(r))
            .map(|r| UriResource {
                collection: resource.collection,
                account_id: resource.account_id,
                resource: T::from_dav_resource(r),
            })
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))
    }

    fn map_parent<'x>(&self, resource: &'x str) -> Option<(Option<DavResourcePath<'_>>, &'x str)> {
        let (parent, child) = if let Some((parent, child)) = resource.rsplit_once('/') {
            (Some(self.by_path(parent)?), child)
        } else {
            (None, resource)
        };

        Some((parent, child))
    }

    fn map_parent_resource<'x, T: FromDavResource>(
        &self,
        resource: &OwnedUri<'x>,
    ) -> crate::Result<UriResource<u32, (Option<T>, &'x str)>> {
        if let Some(r) = resource.resource {
            if self.by_path(r).is_none() {
                self.map_parent(r)
                    .map(|(parent, child)| UriResource {
                        collection: resource.collection,
                        account_id: resource.account_id,
                        resource: (parent.map(T::from_dav_resource), child),
                    })
                    .ok_or(DavError::Code(StatusCode::CONFLICT))
            } else {
                Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
            }
        } else {
            Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
        }
    }
}

impl FromDavResource for u32 {
    fn from_dav_resource(item: DavResourcePath) -> Self {
        item.document_id()
    }
}

impl FromDavResource for FileItemId {
    fn from_dav_resource(item: DavResourcePath) -> Self {
        FileItemId {
            document_id: item.document_id(),
            parent_id: item.parent_id(),
            is_container: item.is_container(),
        }
    }
}
