/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Files, Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::{Depth, RequestHeaders};
use groupware::file::{FileNode, hierarchy::FileHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl, collection::Collection, property::Property, type_state::DataType,
};
use store::{
    ahash::AHashMap,
    write::{Archive, BatchBuilder, assert::HashedValue, log::ChangeLogBuilder, now},
};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{
    DavError, DavMethod,
    common::{
        acl::DavAclHandler,
        lock::{LockRequestHandler, ResourceState},
        uri::{DavUriResource, UriResource},
    },
    file::{DavFileResource, FileItemId, insert_file_node, update_file_node},
};

use super::{FromFileItem, delete_file_node};

pub(crate) trait FileCopyMoveRequestHandler: Sync + Send {
    fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileCopyMoveRequestHandler for Server {
    async fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource_ = self.validate_uri(access_token, headers.uri).await?;
        let from_account_id = from_resource_.account_id()?;
        let from_files = self
            .fetch_file_hierarchy(from_account_id)
            .await
            .caused_by(trc::location!())?;
        let from_resource = from_files.map_resource::<FileItemId>(&from_resource_)?;

        // Validate source ACLs
        let mut child_acl = Bitmap::new();
        let mut parent_acl = Bitmap::new();
        match (from_resource.resource.is_container, is_move) {
            (true, true) => {
                child_acl.insert(Acl::Delete);
                child_acl.insert(Acl::RemoveItems);
                parent_acl.insert(Acl::RemoveItems);
            }
            (true, false) => {
                child_acl.insert(Acl::Read);
                child_acl.insert(Acl::ReadItems);
                parent_acl.insert(Acl::ReadItems);
            }
            (false, true) => {
                child_acl.insert(Acl::Delete);
                parent_acl.insert(Acl::RemoveItems);
            }
            (false, false) => {
                child_acl.insert(Acl::Read);
                parent_acl.insert(Acl::ReadItems);
            }
        }
        self.validate_child_or_parent_acl(
            access_token,
            from_account_id,
            Collection::FileNode,
            from_resource.resource.document_id,
            from_resource.resource.parent_id,
            child_acl,
            parent_acl,
        )
        .await?;

        // Validate destination
        let destination = self
            .validate_uri(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
            )
            .await?;
        if destination.collection != Collection::FileNode {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let to_account_id = destination
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let to_files = if to_account_id == from_account_id {
            from_files.clone()
        } else {
            self.fetch_file_hierarchy(to_account_id)
                .await
                .caused_by(trc::location!())?
        };

        // Map file item
        let mut destination_resource_name = "";
        let mut destination = if let Some(resource) = destination.resource {
            destination_resource_name = resource;

            // Check if the resource exists
            if let Some(destination) = to_files
                .files
                .by_name(resource)
                .map(Destination::from_file_item)
            {
                destination
            } else if let Some((destination, new_name)) =
                to_files.map_parent::<Destination>(resource)
            {
                let mut destination = destination.unwrap_or_default();
                destination.new_name = Some(new_name.into_owned());
                destination
            } else {
                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
            }
        } else {
            Destination::default()
        };
        destination.account_id = to_account_id;

        if from_account_id == destination.account_id {
            if Some(from_resource.resource.document_id) == destination.document_id {
                // Move or copy to the same location
                return Ok(HttpResponse::new(StatusCode::BAD_GATEWAY));
            } else if from_resource.resource.parent_id == destination.parent_id
                && destination.new_name.is_some()
            {
                // Rename
                self.validate_child_or_parent_acl(
                    access_token,
                    from_account_id,
                    Collection::FileNode,
                    from_resource.resource.document_id,
                    from_resource.resource.parent_id,
                    Acl::Modify,
                    Acl::ModifyItems,
                )
                .await?;
                return rename_item(self, access_token, from_resource, destination).await;
            }
        }

        // Validate destination ACLs
        if let Some(document_id) = destination.document_id {
            let mut child_acl = Bitmap::new();

            if destination.is_container {
                child_acl.insert(Acl::AddItems);
            } else {
                child_acl.insert(Acl::Modify);
            }

            self.validate_child_or_parent_acl(
                access_token,
                to_account_id,
                Collection::FileNode,
                document_id,
                destination.parent_id,
                child_acl,
                Acl::AddItems,
            )
            .await?;
        } else if !access_token.is_member(to_account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate headers
        self.validate_headers(
            access_token,
            &headers,
            vec![
                ResourceState {
                    account_id: from_account_id,
                    collection: Collection::FileNode,
                    document_id: Some(from_resource.resource.document_id),
                    etag: None,
                    lock_token: None,
                    path: from_resource_.resource.unwrap(),
                },
                ResourceState {
                    account_id: to_account_id,
                    collection: Collection::FileNode,
                    document_id: Some(destination.document_id.unwrap_or(u32::MAX)),
                    etag: None,
                    lock_token: None,
                    path: destination_resource_name,
                },
            ],
            Default::default(),
            DavMethod::MOVE,
        )
        .await?;

        // Validate quota
        if !is_move || from_account_id != to_account_id {
            let res = from_files
                .files
                .by_id(from_resource.resource.document_id)
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let space_needed = from_files
                .subtree(&res.name)
                .map(|a| a.size as u64)
                .sum::<u64>();
            self.has_available_quota(
                &self.get_resource_token(access_token, to_account_id).await?,
                space_needed,
            )
            .await?;
        }

        match (
            from_resource.resource.is_container,
            destination.is_container,
            is_move,
        ) {
            (true, true, true) => {
                move_container(
                    self,
                    access_token,
                    from_files,
                    to_files,
                    from_resource,
                    destination,
                    headers.depth,
                )
                .await
            }
            (true, true, false) => {
                copy_container(
                    self,
                    access_token,
                    from_files,
                    from_resource,
                    destination,
                    headers.depth,
                    false,
                )
                .await
            }
            (false, false, true) => {
                overwrite_and_delete_item(self, access_token, from_resource, destination).await
            }
            (false, false, false) => {
                overwrite_item(self, access_token, from_resource, destination).await
            }
            (false, true, true) => move_item(self, access_token, from_resource, destination).await,
            (false, true, false) => copy_item(self, access_token, from_resource, destination).await,
            _ => Err(DavError::Code(StatusCode::BAD_GATEWAY)),
        }
    }
}

pub(crate) struct Destination {
    pub account_id: u32,
    pub new_name: Option<String>,
    pub document_id: Option<u32>,
    pub parent_id: Option<u32>,
    pub is_container: bool,
}

impl Default for Destination {
    fn default() -> Self {
        Self {
            account_id: Default::default(),
            document_id: Default::default(),
            parent_id: Default::default(),
            new_name: Default::default(),
            is_container: true,
        }
    }
}

// Moves a container under an existing container
async fn move_container(
    server: &Server,
    access_token: &AccessToken,
    from_files: Arc<Files>,
    to_files: Arc<Files>,
    from_resource: UriResource<FileItemId>,
    destination: Destination,
    depth: Depth,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id.unwrap();
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    if from_account_id == to_account_id {
        if parent_id != 0 && to_files.is_ancestor_of(from_document_id, parent_id - 1) {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let node = server
            .get_property::<HashedValue<Archive>>(
                from_account_id,
                Collection::FileNode,
                from_document_id,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
            .into_deserialized::<FileNode>()
            .caused_by(trc::location!())?;
        let mut new_node = node.inner.clone();
        new_node.parent_id = parent_id;
        if let Some(new_name) = destination.new_name {
            new_node.name = new_name;
        }
        let etag = update_file_node(
            server,
            access_token,
            node,
            new_node,
            from_account_id,
            from_document_id,
            true,
        )
        .await
        .caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
    } else {
        copy_container(
            server,
            access_token,
            from_files,
            from_resource,
            destination,
            depth,
            true,
        )
        .await
    }
}

async fn copy_container(
    server: &Server,
    access_token: &AccessToken,
    from_files: Arc<Files>,
    from_resource: UriResource<FileItemId>,
    mut destination: Destination,
    depth: Depth,
    delete_source: bool,
) -> crate::Result<HttpResponse> {
    let infinity_copy = match depth {
        Depth::Zero => {
            return copy_item(server, access_token, from_resource, destination).await;
        }
        Depth::One => false,
        _ => true,
    };

    let from_account_id = from_resource.account_id.unwrap();
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    // Obtain files to copy
    let res = from_files
        .files
        .by_id(from_document_id)
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let mut copy_files = if infinity_copy {
        from_files
            .subtree(&res.name)
            .map(|r| (r.document_id, r.hierarchy_sequence))
            .collect::<Vec<_>>()
    } else {
        from_files
            .subtree_with_depth(&res.name, 1)
            .map(|r| (r.document_id, r.hierarchy_sequence))
            .collect::<Vec<_>>()
    };

    // Top-down copy
    let mut id_map = AHashMap::with_capacity(copy_files.len());
    let mut delete_files = if delete_source {
        Vec::with_capacity(copy_files.len())
    } else {
        Vec::new()
    };
    copy_files.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    let change_id = server.generate_snowflake_id()?;
    let mut changes = ChangeLogBuilder::with_change_id(change_id);
    let now = now() as i64;
    for (document_id, _) in copy_files.into_iter() {
        let node_ = server
            .get_property::<HashedValue<Archive>>(
                from_account_id,
                Collection::FileNode,
                document_id,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
            .into_deserialized::<FileNode>()
            .caused_by(trc::location!())?;

        // Build node
        let mut node = if !delete_source {
            node_.inner
        } else {
            let node = node_.inner.clone();
            delete_files.push((document_id, node_));
            node
        };
        node.modified = now;
        node.created = now;
        if let Some(new_name) = destination.new_name.take() {
            node.name = new_name;
        }
        node.parent_id = if let Some(&prev_document_id) = id_map.get(&node.parent_id) {
            prev_document_id
        } else {
            parent_id
        };

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        batch
            .with_change_id(change_id)
            .with_account_id(to_account_id)
            .with_collection(Collection::FileNode)
            .create_document()
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(node)
                    .with_tenant_id(access_token),
            )
            .caused_by(trc::location!())?;
        let new_document_id = server
            .store()
            .write(batch)
            .await
            .caused_by(trc::location!())?
            .last_document_id()
            .caused_by(trc::location!())?;
        changes.log_insert(Collection::FileNode, new_document_id);
        id_map.insert(document_id + 1, new_document_id + 1);
    }

    // Write changes
    if !changes.is_empty() {
        server
            .commit_changes(to_account_id, changes)
            .await
            .caused_by(trc::location!())?;
        server
            .broadcast_single_state_change(to_account_id, change_id, DataType::FileNode)
            .await;
    }

    // Delete nodes
    if !delete_files.is_empty() {
        let mut changes = ChangeLogBuilder::with_change_id(change_id);
        for (document_id, node) in delete_files.into_iter().rev() {
            // Delete record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(from_account_id)
                .with_collection(Collection::FileNode)
                .delete_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_tenant_id(access_token)
                        .with_current(node),
                )
                .caused_by(trc::location!())?;
            server
                .store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;
            changes.log_delete(Collection::FileNode, document_id);
        }

        // Write changes
        if !changes.is_empty() {
            server
                .commit_changes(from_account_id, changes)
                .await
                .caused_by(trc::location!())?;
            server
                .broadcast_single_state_change(from_account_id, change_id, DataType::FileNode)
                .await;
        }
    }

    Ok(HttpResponse::new(StatusCode::CREATED))
}

// Overwrites the contents of one file with another, then deletes the original
async fn overwrite_and_delete_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id.unwrap();
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let to_document_id = destination.document_id.unwrap();

    // dest_node is the current file at the destination
    let dest_node = server
        .get_property::<HashedValue<Archive>>(
            to_account_id,
            Collection::FileNode,
            to_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .into_deserialized::<FileNode>()
        .caused_by(trc::location!())?;

    // source_node is the file to be copied
    let source_node_ = server
        .get_property::<HashedValue<Archive>>(
            from_account_id,
            Collection::FileNode,
            from_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .into_deserialized::<FileNode>()
        .caused_by(trc::location!())?;
    let mut source_node = source_node_.inner.clone();
    source_node.name = if let Some(new_name) = destination.new_name {
        new_name
    } else {
        dest_node.inner.name.clone()
    };
    source_node.parent_id = dest_node.inner.parent_id;

    let etag = update_file_node(
        server,
        access_token,
        dest_node,
        source_node,
        to_account_id,
        to_document_id,
        true,
    )
    .await
    .caused_by(trc::location!())?;

    delete_file_node(
        server,
        access_token,
        source_node_,
        from_account_id,
        from_document_id,
    )
    .await
    .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Overwrites the contents of one file with another
async fn overwrite_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id.unwrap();
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let to_document_id = destination.document_id.unwrap();

    // dest_node is the current file at the destination
    let dest_node = server
        .get_property::<HashedValue<Archive>>(
            to_account_id,
            Collection::FileNode,
            to_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .into_deserialized::<FileNode>()
        .caused_by(trc::location!())?;

    // source_node is the file to be copied
    let mut source_node = server
        .get_property::<Archive>(
            from_account_id,
            Collection::FileNode,
            from_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    source_node.name = if let Some(new_name) = destination.new_name {
        new_name
    } else {
        dest_node.inner.name.clone()
    };
    source_node.parent_id = dest_node.inner.parent_id;

    let etag = update_file_node(
        server,
        access_token,
        dest_node,
        source_node,
        to_account_id,
        to_document_id,
        true,
    )
    .await
    .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Moves an item under an existing container
async fn move_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id.unwrap();
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    let node = server
        .get_property::<HashedValue<Archive>>(
            from_account_id,
            Collection::FileNode,
            from_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .into_deserialized::<FileNode>()
        .caused_by(trc::location!())?;
    let mut new_node = node.inner.clone();
    new_node.parent_id = parent_id;
    if let Some(new_name) = destination.new_name {
        new_node.name = new_name;
    }

    let etag = if from_account_id == to_account_id {
        // Destination is in the same account: just update the parent id
        update_file_node(
            server,
            access_token,
            node,
            new_node,
            from_account_id,
            from_document_id,
            true,
        )
        .await
        .caused_by(trc::location!())?
    } else {
        // Destination is in a different account: insert a new node, then delete the old one
        let etag = insert_file_node(server, access_token, new_node, to_account_id, true)
            .await
            .caused_by(trc::location!())?;
        delete_file_node(
            server,
            access_token,
            node,
            from_account_id,
            from_document_id,
        )
        .await
        .caused_by(trc::location!())?;
        etag
    };

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Copies an item under an existing container
async fn copy_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id.unwrap();
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    let mut node = server
        .get_property::<Archive>(
            from_account_id,
            Collection::FileNode,
            from_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    node.parent_id = parent_id;
    if let Some(new_name) = destination.new_name {
        node.name = new_name;
    }
    let etag = insert_file_node(server, access_token, node, to_account_id, true)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Renames an item
async fn rename_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id.unwrap();
    let from_document_id = from_resource.resource.document_id;

    let node = server
        .get_property::<HashedValue<Archive>>(
            from_account_id,
            Collection::FileNode,
            from_document_id,
            Property::Value,
        )
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .into_deserialized::<FileNode>()
        .caused_by(trc::location!())?;
    let mut new_node = node.inner.clone();
    if let Some(new_name) = destination.new_name {
        new_node.name = new_name;
    }
    let etag = update_file_node(
        server,
        access_token,
        node,
        new_node,
        from_account_id,
        from_document_id,
        true,
    )
    .await
    .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

impl FromFileItem for Destination {
    fn from_file_item(item: &common::FileItem) -> Self {
        Destination {
            account_id: u32::MAX,
            document_id: Some(item.document_id),
            parent_id: item.parent_id,
            is_container: item.is_container,
            new_name: None,
        }
    }
}
