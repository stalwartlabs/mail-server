/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::FromDavResource;
use crate::{
    DavError, DavMethod,
    common::{
        ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::{DavUriResource, UriResource},
    },
    file::{DavFileResource, FileItemId},
};
use common::{
    DavResourcePath, DavResources, Server, auth::AccessToken, storage::index::ObjectIndexBuilder,
};
use dav_proto::{Depth, RequestHeaders};
use groupware::{DestroyArchive, cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection, VanishedCollection},
};
use std::sync::Arc;
use store::{
    ahash::AHashMap,
    write::{BatchBuilder, now},
};
use trc::AddContext;

pub(crate) trait FileCopyMoveRequestHandler: Sync + Send {
    fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileCopyMoveRequestHandler for Server {
    async fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let from_account_id = from_resource_.account_id;
        let from_resources = self
            .fetch_dav_resources(access_token, from_account_id, SyncCollection::FileNode)
            .await
            .caused_by(trc::location!())?;
        let from_resource = from_resources.map_resource::<FileItemId>(&from_resource_)?;
        let from_resource_name = from_resource_.resource.unwrap();

        // Validate source ACLs
        if !access_token.is_member(from_account_id) {
            let shared = from_resources.shared_containers(
                access_token,
                if is_move {
                    [Acl::Read, Acl::Delete].as_slice().iter().copied()
                } else {
                    [Acl::Read].as_slice().iter().copied()
                },
                false,
            );

            for resource in from_resources.subtree(from_resource_.resource.unwrap()) {
                if !shared.contains(resource.document_id()) {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }
            }
        }

        // Validate destination
        let destination = self
            .validate_uri_with_status(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
                StatusCode::BAD_GATEWAY,
            )
            .await?;
        if destination.collection != Collection::FileNode {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let to_account_id = destination
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let to_resources = if to_account_id == from_account_id {
            from_resources.clone()
        } else {
            self.fetch_dav_resources(access_token, to_account_id, SyncCollection::FileNode)
                .await
                .caused_by(trc::location!())?
        };

        // Map file item
        let destination_resource_name = destination
            .resource
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        if from_account_id == to_account_id
            && (from_resource_name == destination_resource_name
                || from_resource_name
                    .strip_prefix(destination_resource_name)
                    .is_some_and(|v| v.is_empty() || v.starts_with('/')))
        {
            return Ok(HttpResponse::new(StatusCode::BAD_GATEWAY));
        }

        // Check if the resource exists
        let mut delete_destination = None;
        let mut destination = if let Some((destination, new_name)) =
            to_resources.map_parent(destination_resource_name)
        {
            if let Some(mut existing_destination) = to_resources
                .by_path(destination_resource_name)
                .map(Destination::from_dav_resource)
            {
                if !headers.overwrite_fail {
                    existing_destination.account_id = to_account_id;
                    delete_destination = Some(existing_destination);
                } else {
                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED));
                }
            }

            let mut destination = destination
                .map(Destination::from_dav_resource)
                .unwrap_or_default();
            destination.new_name = Some(new_name.to_string());
            destination
        } else {
            return Err(DavError::Code(StatusCode::CONFLICT));
        };
        destination.account_id = to_account_id;

        // Validate destination ACLs
        if let Some(document_id) = destination.document_id {
            if let Some(delete_destination) = &delete_destination {
                if !access_token.is_member(to_account_id)
                    && !from_resources.has_access_to_container(
                        access_token,
                        delete_destination.document_id.unwrap(),
                        Acl::Delete,
                    )
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }
            }

            if !access_token.is_member(to_account_id)
                && !from_resources.has_access_to_container(access_token, document_id, Acl::Modify)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        } else if !access_token.is_member(to_account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![
                ResourceState {
                    account_id: from_account_id,
                    collection: Collection::FileNode,
                    document_id: Some(from_resource.resource.document_id),
                    path: from_resource_name,
                    ..Default::default()
                },
                ResourceState {
                    account_id: to_account_id,
                    collection: Collection::FileNode,
                    document_id: Some(
                        delete_destination
                            .as_ref()
                            .and_then(|d| d.document_id)
                            .unwrap_or(u32::MAX),
                    ),
                    path: destination_resource_name,
                    ..Default::default()
                },
            ],
            Default::default(),
            if is_move {
                DavMethod::MOVE
            } else {
                DavMethod::COPY
            },
        )
        .await?;

        if delete_destination.is_none()
            && from_account_id == destination.account_id
            && from_resource.resource.parent_id == destination.document_id
            && destination.new_name.is_some()
            && is_move
        {
            // Rename
            let from_resource_path = if from_resource.resource.is_container {
                from_resources.format_collection(from_resource_name)
            } else {
                from_resources.format_item(from_resource_name)
            };
            return rename_item(
                self,
                access_token,
                from_resource,
                from_resource_path,
                destination,
            )
            .await;
        }

        // Validate quota
        if !is_move || from_account_id != to_account_id {
            let space_needed = from_resources
                .subtree(from_resource_name)
                .map(|a| a.size() as u64)
                .sum::<u64>();
            self.has_available_quota(
                &self.get_resource_token(access_token, to_account_id).await?,
                space_needed,
            )
            .await?;
        }

        // Delete collection
        let is_overwrite = delete_destination
            .as_ref()
            .is_some_and(|d| d.is_container || from_resource.resource.is_container);
        if is_overwrite {
            delete_destination = None;
            // Find ids to delete
            let mut ids = to_resources
                .subtree(destination_resource_name)
                .collect::<Vec<_>>();
            if !ids.is_empty() {
                ids.sort_unstable_by_key(|b| std::cmp::Reverse(b.hierarchy_seq()));
                let mut sorted_ids = Vec::with_capacity(ids.len());
                sorted_ids.extend(ids.into_iter().map(|a| a.document_id()));
                DestroyArchive(sorted_ids)
                    .delete(self, access_token, destination.account_id, None)
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        match (from_resource.resource.is_container, is_move) {
            (true, true) => {
                move_container(
                    self,
                    access_token,
                    from_resources,
                    from_resource,
                    from_resource_name,
                    destination,
                    headers.depth,
                )
                .await
            }
            (true, false) => {
                copy_container(
                    self,
                    access_token,
                    from_resources,
                    from_resource,
                    from_resource_name,
                    destination,
                    headers.depth,
                    false,
                )
                .await
            }
            (false, true) => {
                if let Some(delete_destination) = delete_destination {
                    overwrite_and_delete_item(
                        self,
                        access_token,
                        from_resource,
                        from_resources.format_item(from_resource_name),
                        delete_destination,
                    )
                    .await
                } else {
                    move_item(
                        self,
                        access_token,
                        from_resource,
                        from_resources.format_item(from_resource_name),
                        destination,
                    )
                    .await
                }
            }

            (false, false) => {
                if let Some(delete_destination) = delete_destination {
                    overwrite_item(self, access_token, from_resource, delete_destination).await
                } else {
                    copy_item(self, access_token, from_resource, destination).await
                }
            }
        }
        .map(|r| {
            if is_overwrite && r.status() == StatusCode::CREATED {
                r.with_status_code(StatusCode::NO_CONTENT)
            } else {
                r
            }
        })
    }
}

#[derive(Debug)]
pub(crate) struct Destination {
    pub account_id: u32,
    pub new_name: Option<String>,
    pub document_id: Option<u32>,
    pub is_container: bool,
}

impl Default for Destination {
    fn default() -> Self {
        Self {
            account_id: Default::default(),
            document_id: Default::default(),
            new_name: Default::default(),
            is_container: true,
        }
    }
}

// Moves a container under an existing container
async fn move_container(
    server: &Server,
    access_token: &AccessToken,
    from_resources: Arc<DavResources>,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_name: &str,
    destination: Destination,
    depth: Depth,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    if from_account_id == to_account_id {
        let node_ = server
            .get_archive(from_account_id, Collection::FileNode, from_document_id)
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_
            .to_unarchived::<FileNode>()
            .caused_by(trc::location!())?;
        let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
        new_node.parent_id = parent_id;
        if let Some(new_name) = destination.new_name {
            new_node.name = new_name;
        }
        let mut batch = BatchBuilder::new();
        let etag = new_node
            .update(
                access_token,
                node,
                from_account_id,
                from_document_id,
                &mut batch,
            )
            .caused_by(trc::location!())?
            .etag();
        batch.with_account_id(from_account_id).log_vanished_item(
            VanishedCollection::FileNode,
            from_resources.format_collection(from_resource_name),
        );
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
    } else {
        copy_container(
            server,
            access_token,
            from_resources,
            from_resource,
            from_resource_name,
            destination,
            depth,
            true,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn copy_container(
    server: &Server,
    access_token: &AccessToken,
    from_resources: Arc<DavResources>,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_name: &str,
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

    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    // Obtain files to copy
    let mut copy_files = if infinity_copy {
        from_resources
            .subtree(from_resource_name)
            .map(|r| (r.document_id(), r.hierarchy_seq()))
            .collect::<Vec<_>>()
    } else {
        from_resources
            .subtree_with_depth(from_resource_name, 1)
            .map(|r| (r.document_id(), r.hierarchy_seq()))
            .collect::<Vec<_>>()
    };

    // Top-down copy
    let mut batch = BatchBuilder::new();
    let mut id_map = AHashMap::with_capacity(copy_files.len());
    let mut delete_files = if delete_source {
        Vec::with_capacity(copy_files.len())
    } else {
        Vec::new()
    };
    copy_files.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    let now = now() as i64;
    let mut next_document_id = server
        .store()
        .assign_document_ids(to_account_id, Collection::FileNode, copy_files.len() as u64)
        .await
        .caused_by(trc::location!())?;
    for (document_id, _) in copy_files.into_iter() {
        let node_ = server
            .get_archive(from_account_id, Collection::FileNode, document_id)
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
        let new_document_id = next_document_id;
        next_document_id -= 1;
        batch
            .with_account_id(to_account_id)
            .with_collection(Collection::FileNode)
            .create_document(new_document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(node)
                    .with_tenant_id(access_token),
            )
            .caused_by(trc::location!())?
            .commit_point();
        id_map.insert(document_id + 1, new_document_id + 1);
    }

    // Delete nodes
    if !delete_files.is_empty() {
        for (document_id, node) in delete_files.into_iter().rev() {
            // Delete record
            batch
                .with_account_id(from_account_id)
                .with_collection(Collection::FileNode)
                .delete_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_tenant_id(access_token)
                        .with_current(node),
                )
                .caused_by(trc::location!())?
                .commit_point();
        }
        batch.with_account_id(from_account_id).log_vanished_item(
            VanishedCollection::FileNode,
            from_resources.format_collection(from_resource_name),
        );
    }

    // Write changes
    if !batch.is_empty() {
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(HttpResponse::new(StatusCode::CREATED))
}

// Overwrites the contents of one file with another, then deletes the original
async fn overwrite_and_delete_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_path: String,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let to_document_id = destination.document_id.unwrap();

    // dest_node is the current file at the destination
    let dest_node_ = server
        .get_archive(to_account_id, Collection::FileNode, to_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

    let dest_node = dest_node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;

    // source_node is the file to be copied
    let source_node__ = server
        .get_archive(from_account_id, Collection::FileNode, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let source_node_ = source_node__
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut source_node = source_node_
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    source_node.name = if let Some(new_name) = destination.new_name {
        new_name
    } else {
        dest_node.inner.name.to_string()
    };
    source_node.parent_id = dest_node.inner.parent_id.into();

    let mut batch = BatchBuilder::new();
    let etag = source_node
        .update(
            access_token,
            dest_node,
            to_account_id,
            to_document_id,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    DestroyArchive(source_node_)
        .delete(
            access_token,
            from_account_id,
            from_document_id,
            &mut batch,
            from_resource_path,
        )
        .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
}

// Overwrites the contents of one file with another
async fn overwrite_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let to_document_id = destination.document_id.unwrap();

    // dest_node is the current file at the destination
    let dest_node_ = server
        .get_archive(to_account_id, Collection::FileNode, to_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

    let dest_node = dest_node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;

    // source_node is the file to be copied
    let mut source_node = server
        .get_archive(from_account_id, Collection::FileNode, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    source_node.name = if let Some(new_name) = destination.new_name {
        new_name
    } else {
        dest_node.inner.name.to_string()
    };
    source_node.parent_id = dest_node.inner.parent_id.into();
    let mut batch = BatchBuilder::new();
    let etag = source_node
        .update(
            access_token,
            dest_node,
            to_account_id,
            to_document_id,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
}

// Moves an item under an existing container
async fn move_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_path: String,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    let node_ = server
        .get_archive(from_account_id, Collection::FileNode, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let node = node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
    new_node.parent_id = parent_id;
    if let Some(new_name) = destination.new_name {
        new_node.name = new_name;
    }

    let mut batch = BatchBuilder::new();
    let etag = if from_account_id == to_account_id {
        // Destination is in the same account: just update the parent id
        batch.log_vanished_item(VanishedCollection::FileNode, from_resource_path);
        new_node
            .update(
                access_token,
                node,
                from_account_id,
                from_document_id,
                &mut batch,
            )
            .caused_by(trc::location!())?
            .etag()
    } else {
        // Destination is in a different account: insert a new node, then delete the old one
        let to_document_id = server
            .store()
            .assign_document_ids(to_account_id, Collection::FileNode, 1)
            .await
            .caused_by(trc::location!())?;
        let etag = new_node
            .insert(access_token, to_account_id, to_document_id, &mut batch)
            .caused_by(trc::location!())?
            .etag();
        DestroyArchive(node)
            .delete(
                access_token,
                from_account_id,
                from_document_id,
                &mut batch,
                from_resource_path,
            )
            .caused_by(trc::location!())?;
        etag
    };
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Copies an item under an existing container
async fn copy_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    let mut node = server
        .get_archive(from_account_id, Collection::FileNode, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    node.parent_id = parent_id;
    if let Some(new_name) = destination.new_name {
        node.name = new_name;
    }
    let mut batch = BatchBuilder::new();
    let to_document_id = server
        .store()
        .assign_document_ids(to_account_id, Collection::FileNode, 1)
        .await
        .caused_by(trc::location!())?;
    let etag = node
        .insert(access_token, to_account_id, to_document_id, &mut batch)
        .caused_by(trc::location!())?
        .etag();
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Renames an item
async fn rename_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_path: String,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let from_document_id = from_resource.resource.document_id;

    let node_ = server
        .get_archive(from_account_id, Collection::FileNode, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let node = node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
    if let Some(new_name) = destination.new_name {
        new_node.name = new_name;
    }
    let mut batch = BatchBuilder::new();
    let etag = new_node
        .update(
            access_token,
            node,
            from_account_id,
            from_document_id,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    batch.log_vanished_item(VanishedCollection::FileNode, from_resource_path);
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

impl FromDavResource for Destination {
    fn from_dav_resource(item: DavResourcePath<'_>) -> Self {
        Destination {
            account_id: u32::MAX,
            document_id: Some(item.document_id()),
            is_container: item.is_container(),
            new_name: None,
        }
    }
}
