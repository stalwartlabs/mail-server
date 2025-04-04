/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DavResource, DavResources, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use groupware::file::{ArchivedFileNode, FileNode};
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::write::{Archive, BatchBuilder, now};

use crate::{
    DavError,
    common::{
        ExtractETag,
        uri::{OwnedUri, UriResource},
    },
};

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

pub(crate) static FILE_ALL_PROPS: [DavProperty; 17] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
];

pub(crate) trait FromDavResource {
    fn from_dav_resource(item: &DavResource) -> Self;
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

    fn map_parent<'x>(&self, resource: &'x str) -> Option<(Option<&DavResource>, &'x str)>;

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
            .and_then(|r| self.paths.by_name(r))
            .map(|r| UriResource {
                collection: resource.collection,
                account_id: resource.account_id,
                resource: T::from_dav_resource(r),
            })
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))
    }

    fn map_parent<'x>(&self, resource: &'x str) -> Option<(Option<&DavResource>, &'x str)> {
        let (parent, child) = if let Some((parent, child)) = resource.rsplit_once('/') {
            (Some(self.paths.by_name(parent)?), child)
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
            if self.paths.by_name(r).is_none() {
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
    fn from_dav_resource(item: &DavResource) -> Self {
        item.document_id
    }
}

impl FromDavResource for FileItemId {
    fn from_dav_resource(item: &DavResource) -> Self {
        FileItemId {
            document_id: item.document_id,
            parent_id: item.parent_id,
            is_container: item.is_container,
        }
    }
}

pub(crate) fn update_file_node(
    access_token: &AccessToken,
    node: Archive<&ArchivedFileNode>,
    mut new_node: FileNode,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
    batch: &mut BatchBuilder,
) -> trc::Result<Option<String>> {
    // Build node
    new_node.modified = now() as i64;
    batch
        .with_account_id(account_id)
        .with_collection(Collection::FileNode)
        .update_document(document_id)
        .custom(
            ObjectIndexBuilder::new()
                .with_current(node)
                .with_changes(new_node)
                .with_tenant_id(access_token),
        )?
        .commit_point();

    Ok(if with_etag { batch.etag() } else { None })
}

pub(crate) fn insert_file_node(
    access_token: &AccessToken,
    mut node: FileNode,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
    batch: &mut BatchBuilder,
) -> trc::Result<Option<String>> {
    // Build node
    let now = now() as i64;
    node.modified = now;
    node.created = now;

    // Prepare write batch
    batch
        .with_account_id(account_id)
        .with_collection(Collection::FileNode)
        .create_document(document_id)
        .custom(
            ObjectIndexBuilder::<(), _>::new()
                .with_changes(node)
                .with_tenant_id(access_token),
        )?
        .commit_point();

    Ok(if with_etag { batch.etag() } else { None })
}

pub(crate) fn delete_file_node(
    access_token: &AccessToken,
    node: Archive<&ArchivedFileNode>,
    account_id: u32,
    document_id: u32,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    // Prepare write batch
    batch
        .with_account_id(account_id)
        .with_collection(Collection::FileNode)
        .delete_document(document_id)
        .custom(
            ObjectIndexBuilder::<_, ()>::new()
                .with_current(node)
                .with_tenant_id(access_token),
        )?
        .commit_point();
    Ok(())
}
