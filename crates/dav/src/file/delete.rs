/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::RequestHeaders;
use groupware::{file::FileNode, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl, collection::Collection, property::Property, type_state::DataType,
};
use store::write::{AlignedBytes, Archive, BatchBuilder, log::ChangeLogBuilder};
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

pub(crate) trait FileDeleteRequestHandler: Sync + Send {
    fn handle_file_delete_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileDeleteRequestHandler for Server {
    async fn handle_file_delete_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let delete_path = resource
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let files = self
            .fetch_dav_resources(account_id, Collection::FileNode)
            .await
            .caused_by(trc::location!())?;

        // Find ids to delete
        let mut ids = files.subtree(delete_path).collect::<Vec<_>>();
        if ids.is_empty() {
            return Err(DavError::Code(StatusCode::NOT_FOUND));
        }

        // Sort ids descending from the deepest to the root
        ids.sort_unstable_by(|a, b| b.hierarchy_sequence.cmp(&a.hierarchy_sequence));
        let document_id = ids.last().map(|a| a.document_id).unwrap();
        let mut sorted_ids = Vec::with_capacity(ids.len());
        sorted_ids.extend(ids.into_iter().map(|a| a.document_id));

        // Validate ACLs
        if !access_token.is_member(account_id) {
            let permissions = self
                .shared_containers(access_token, account_id, Collection::FileNode, Acl::Delete)
                .await
                .caused_by(trc::location!())?;
            if permissions.len() != sorted_ids.len() as u64
                || sorted_ids.iter().all(|id| permissions.contains(*id))
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Validate headers
        self.validate_headers(
            access_token,
            &headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: document_id.into(),
                path: delete_path,
                ..Default::default()
            }],
            Default::default(),
            DavMethod::DELETE,
        )
        .await?;

        delete_files(self, access_token, account_id, sorted_ids).await?;

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}

pub(crate) async fn delete_files(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    ids: Vec<u32>,
) -> trc::Result<()> {
    // Process deletions
    let mut changes = ChangeLogBuilder::new();

    for document_id in ids {
        if let Some(node) = server
            .get_property::<Archive<AlignedBytes>>(
                account_id,
                Collection::FileNode,
                document_id,
                Property::Value,
            )
            .await?
        {
            // Delete record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .delete_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_tenant_id(access_token)
                        .with_current(
                            node.to_unarchived::<FileNode>()
                                .caused_by(trc::location!())?,
                        ),
                )
                .caused_by(trc::location!())?;
            server
                .store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;
            changes.log_delete(Collection::FileNode, document_id);
        }
    }

    // Write changes
    if !changes.is_empty() {
        let change_id = server
            .commit_changes(account_id, changes)
            .await
            .caused_by(trc::location!())?;
        server
            .broadcast_single_state_change(account_id, change_id, DataType::FileNode)
            .await;
    }

    Ok(())
}
