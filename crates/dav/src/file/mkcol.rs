/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::{
    RequestHeaders, Return,
    schema::{Namespace, request::MkCol, response::MkColResponse},
};
use groupware::{file::FileNode, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::{BatchBuilder, now};
use trc::AddContext;

use crate::{
    DavMethod,
    common::{
        acl::DavAclHandler,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};

use super::proppatch::FilePropPatchRequestHandler;

pub(crate) trait FileMkColRequestHandler: Sync + Send {
    fn handle_file_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileMkColRequestHandler for Server {
    async fn handle_file_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let files = self
            .fetch_dav_resources(access_token, account_id, Collection::FileNode)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_parent_resource(&resource_)?;

        // Validate and map parent ACL
        let parent_id = self
            .validate_and_map_parent_acl(
                access_token,
                account_id,
                Collection::FileNode,
                resource.resource.0,
                Acl::AddItems,
            )
            .await?;

        // Validate headers
        self.validate_headers(
            access_token,
            &headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: Some(u32::MAX),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::MKCOL,
        )
        .await?;

        // Build file container
        let now = now();
        let mut node = FileNode {
            parent_id,
            name: resource.resource.1.to_string(),
            display_name: None,
            file: None,
            created: now as i64,
            modified: now as i64,
            dead_properties: Default::default(),
            acls: Default::default(),
        };

        // Apply MKCOL properties
        let mut return_prop_stat = None;
        if let Some(mkcol) = request {
            let mut prop_stat = Vec::new();
            if !self.apply_file_properties(&mut node, false, mkcol.props, &mut prop_stat) {
                return Ok(HttpResponse::new(StatusCode::FORBIDDEN).with_xml_body(
                    MkColResponse::new(prop_stat)
                        .with_namespace(Namespace::Dav)
                        .to_string(),
                ));
            }
            if headers.ret != Return::Minimal {
                return_prop_stat = Some(prop_stat);
            }
        }

        // Prepare write batch
        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::FileNode, 1)
            .await
            .caused_by(trc::location!())?;
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .create_document(document_id)
            .custom(ObjectIndexBuilder::<(), _>::new().with_changes(node))
            .caused_by(trc::location!())?;
        self.commit_batch(batch).await.caused_by(trc::location!())?;

        if let Some(prop_stat) = return_prop_stat {
            Ok(HttpResponse::new(StatusCode::CREATED).with_xml_body(
                MkColResponse::new(prop_stat)
                    .with_namespace(Namespace::Dav)
                    .to_string(),
            ))
        } else {
            Ok(HttpResponse::new(StatusCode::CREATED))
        }
    }
}
