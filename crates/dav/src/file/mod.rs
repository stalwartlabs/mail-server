/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    DavResource, DavResources, Server, auth::AccessToken, storage::index::ObjectIndexBuilder,
};
use groupware::file::{ArchivedFileNode, FileNode};
use hyper::StatusCode;
use jmap_proto::types::{collection::Collection, type_state::DataType};
use store::write::{
    Archive, BatchBuilder,
    log::{Changes, LogInsert},
    now,
};

use crate::{
    DavError,
    common::{
        ExtractETag,
        uri::{OwnedUri, UriResource},
    },
};

pub mod acl;
pub mod copy_move;
pub mod delete;
pub mod get;
pub mod mkcol;
pub mod propfind;
pub mod proppatch;
pub mod update;

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

    fn map_parent<'x, T: FromDavResource>(&self, resource: &'x str)
    -> Option<(Option<T>, &'x str)>;

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
            .and_then(|r| self.files.by_name(r))
            .map(|r| UriResource {
                collection: resource.collection,
                account_id: resource.account_id,
                resource: T::from_dav_resource(r),
            })
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))
    }

    fn map_parent<'x, T: FromDavResource>(
        &self,
        resource: &'x str,
    ) -> Option<(Option<T>, &'x str)> {
        let (parent, child) = if let Some((parent, child)) = resource.rsplit_once('/') {
            (
                Some(self.files.by_name(parent).map(T::from_dav_resource)?),
                child,
            )
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
            if self.files.by_name(r).is_none() {
                self.map_parent(r)
                    .map(|r| UriResource {
                        collection: resource.collection,
                        account_id: resource.account_id,
                        resource: r,
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

pub(crate) async fn update_file_node(
    server: &Server,
    access_token: &AccessToken,
    node: Archive<&ArchivedFileNode>,
    mut new_node: FileNode,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
) -> trc::Result<Option<String>> {
    // Build node
    new_node.modified = now() as i64;
    let change_id = server.generate_snowflake_id()?;

    // Prepare write batch
    let mut batch = BatchBuilder::new();
    batch
        .with_change_id(change_id)
        .with_account_id(account_id)
        .with_collection(Collection::FileNode)
        .update_document(document_id)
        .log(Changes::update([document_id]))
        .custom(
            ObjectIndexBuilder::new()
                .with_current(node)
                .with_changes(new_node)
                .with_tenant_id(access_token),
        )?;
    let etag = if with_etag { batch.etag() } else { None };
    server.store().write(batch).await?;

    // Broadcast state change
    server
        .broadcast_single_state_change(account_id, change_id, DataType::FileNode)
        .await;

    Ok(etag)
}

pub(crate) async fn insert_file_node(
    server: &Server,
    access_token: &AccessToken,
    mut node: FileNode,
    account_id: u32,
    with_etag: bool,
) -> trc::Result<Option<String>> {
    // Build node
    let now = now() as i64;
    node.modified = now;
    node.created = now;

    // Prepare write batch
    let mut batch = BatchBuilder::new();
    let change_id = server.generate_snowflake_id()?;
    batch
        .with_change_id(change_id)
        .with_account_id(account_id)
        .with_collection(Collection::FileNode)
        .create_document()
        .log(LogInsert())
        .custom(
            ObjectIndexBuilder::<(), _>::new()
                .with_changes(node)
                .with_tenant_id(access_token),
        )?;
    let etag = if with_etag { batch.etag() } else { None };

    server.store().write(batch).await?;

    // Broadcast state change
    server
        .broadcast_single_state_change(account_id, change_id, DataType::FileNode)
        .await;

    Ok(etag)
}

pub(crate) async fn delete_file_node(
    server: &Server,
    access_token: &AccessToken,
    node: Archive<&ArchivedFileNode>,
    account_id: u32,
    document_id: u32,
) -> trc::Result<()> {
    // Prepare write batch
    let mut batch = BatchBuilder::new();
    let change_id = server.generate_snowflake_id()?;
    batch
        .with_change_id(change_id)
        .with_account_id(account_id)
        .with_collection(Collection::FileNode)
        .delete_document(document_id)
        .log(Changes::delete([document_id]))
        .custom(
            ObjectIndexBuilder::<_, ()>::new()
                .with_current(node)
                .with_tenant_id(access_token),
        )?;
    server.store().write(batch).await?;

    // Broadcast state change
    server
        .broadcast_single_state_change(account_id, change_id, DataType::FileNode)
        .await;
    Ok(())
}
