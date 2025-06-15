/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        property::{DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, MultiStatus, Response},
    },
};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavMethod, PropStatBuilder,
    common::{
        ETag, ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};

pub(crate) trait FilePropPatchRequestHandler: Sync + Send {
    fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_file_properties(
        &self,
        file: &mut FileNode,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool;
}

impl FilePropPatchRequestHandler for Server {
    async fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let uri = headers.uri;
        let account_id = resource_.account_id;
        let files = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::FileNode)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(&resource_)?;

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Fetch node
        let node_ = self
            .get_archive(account_id, Collection::FileNode, resource.resource)
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_
            .to_unarchived::<FileNode>()
            .caused_by(trc::location!())?;

        // Validate ACL
        if !access_token.is_member(account_id)
            && !node
                .inner
                .acls
                .effective_acl(access_token)
                .contains(Acl::Modify)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: resource.resource.into(),
                etag: node_.etag().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::PROPPATCH,
        )
        .await?;

        // Deserialize
        let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;

        // Remove properties
        let mut items = PropStatBuilder::default();
        if !request.set_first && !request.remove.is_empty() {
            remove_file_properties(
                &mut new_node,
                std::mem::take(&mut request.remove),
                &mut items,
            );
        }

        // Set properties
        let is_success = self.apply_file_properties(&mut new_node, true, request.set, &mut items);

        // Remove properties
        if is_success && !request.remove.is_empty() {
            remove_file_properties(&mut new_node, request.remove, &mut items);
        }

        let etag = if is_success {
            let mut batch = BatchBuilder::new();
            let etag = new_node
                .update(
                    access_token,
                    node,
                    account_id,
                    resource.resource,
                    &mut batch,
                )
                .caused_by(trc::location!())?
                .etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;
            etag
        } else {
            node_.etag().into()
        };

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(uri, items.build())]).to_string(),
                )
                .with_etag_opt(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        }
    }

    fn apply_file_properties(
        &self,
        file: &mut FileNode,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        file.display_name = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );

                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    file.created = dt;
                    items.insert_ok(property.property);
                }
                (DavProperty::WebDav(WebDavProperty::GetContentType), DavValue::String(name))
                    if file.file.is_some() =>
                {
                    if name.len() <= self.core.groupware.live_property_size {
                        file.file.as_mut().unwrap().media_type = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) if file.file.is_none() => {
                    if types.0.len() != 1 || types.0.first() != Some(&ResourceType::Collection) {
                        items.insert_precondition_failed(
                            property.property,
                            StatusCode::FORBIDDEN,
                            BaseCondition::ValidResourceType,
                        );
                        has_errors = true;
                    } else {
                        items.insert_ok(property.property);
                    }
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.groupware.dead_property_size.is_some() =>
                {
                    if is_update {
                        file.dead_properties.remove_element(dead);
                    }

                    if file.dead_properties.size() + values.size() + dead.size()
                        < self.core.groupware.dead_property_size.unwrap()
                    {
                        file.dead_properties.add_element(dead.clone(), values.0);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
                    );
                    has_errors = true;
                }
            }
        }

        !has_errors
    }
}

fn remove_file_properties(
    node: &mut FileNode,
    properties: Vec<DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                node.display_name = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::WebDav(WebDavProperty::GetContentType) if node.file.is_some() => {
                node.file.as_mut().unwrap().media_type = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::DeadProperty(dead) => {
                node.dead_properties.remove_element(dead);
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}
