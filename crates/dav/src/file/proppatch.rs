/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        property::{DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, MultiStatus, PropStat, Response},
    },
};
use groupware::{file::FileNode, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};

use super::update_file_node;

pub(crate) trait FilePropPatchRequestHandler: Sync + Send {
    fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_file_properties(
        &self,
        file: &mut FileNode,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut Vec<PropStat>,
    ) -> bool;
}

impl FilePropPatchRequestHandler for Server {
    async fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
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
            .fetch_dav_resources(account_id, Collection::FileNode)
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
            &headers,
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
        let mut new_node = node.deserialize().caused_by(trc::location!())?;

        // Remove properties
        let mut items = Vec::with_capacity(request.remove.len() + request.set.len());
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
            let etag = update_file_node(
                access_token,
                node,
                new_node,
                account_id,
                resource.resource,
                true,
                &mut batch,
            )
            .caused_by(trc::location!())?;
            self.commit_batch(batch).await.caused_by(trc::location!())?;
            etag
        } else {
            node_.etag().into()
        };

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(uri, items)]).to_string(),
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
        items: &mut Vec<PropStat>,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.dav.live_property_size {
                        file.display_name = Some(name);
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                                .with_status(StatusCode::OK),
                        );
                    } else {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                                .with_status(StatusCode::INSUFFICIENT_STORAGE)
                                .with_response_description("Display name too long"),
                        );
                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    file.created = dt;
                }
                (DavProperty::WebDav(WebDavProperty::GetContentType), DavValue::String(name))
                    if file.file.is_some() =>
                {
                    if name.len() <= self.core.dav.live_property_size {
                        file.file.as_mut().unwrap().media_type = Some(name);
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::GetContentType))
                                .with_status(StatusCode::OK),
                        );
                    } else {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::GetContentType))
                                .with_status(StatusCode::INSUFFICIENT_STORAGE)
                                .with_response_description("Content-type is too long"),
                        );
                        has_errors = true;
                    }
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) if file.file.is_none() => {
                    if types.0.len() != 1 || types.0.first() != Some(&ResourceType::Collection) {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::ResourceType))
                                .with_status(StatusCode::FORBIDDEN)
                                .with_error(BaseCondition::ValidResourceType),
                        );
                        has_errors = true;
                    } else {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::ResourceType))
                                .with_status(StatusCode::OK),
                        );
                    }
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.dav.dead_property_size.is_some() =>
                {
                    if is_update {
                        file.dead_properties.remove_element(&dead);
                    }

                    if file.dead_properties.size() + values.size() + dead.size()
                        < self.core.dav.dead_property_size.unwrap()
                    {
                        file.dead_properties.add_element(dead.clone(), values.0);
                        items.push(
                            PropStat::new(DavProperty::DeadProperty(dead))
                                .with_status(StatusCode::OK),
                        );
                    } else {
                        items.push(
                            PropStat::new(DavProperty::DeadProperty(dead))
                                .with_status(StatusCode::INSUFFICIENT_STORAGE)
                                .with_response_description("Dead property is too large."),
                        );
                        has_errors = true;
                    }
                }
                (property, _) => {
                    items.push(
                        PropStat::new(property)
                            .with_status(StatusCode::CONFLICT)
                            .with_response_description("Property cannot be modified"),
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
    items: &mut Vec<PropStat>,
) {
    for property in properties {
        match property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                node.display_name = None;
                items.push(
                    PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                        .with_status(StatusCode::OK),
                );
            }
            DavProperty::WebDav(WebDavProperty::GetContentType) if node.file.is_some() => {
                node.file.as_mut().unwrap().media_type = None;
                items.push(
                    PropStat::new(DavProperty::WebDav(WebDavProperty::GetContentType))
                        .with_status(StatusCode::OK),
                );
            }
            DavProperty::DeadProperty(dead) => {
                node.dead_properties.remove_element(&dead);
                items.push(
                    PropStat::new(DavProperty::DeadProperty(dead)).with_status(StatusCode::OK),
                );
            }
            property => {
                items.push(
                    PropStat::new(property)
                        .with_status(StatusCode::CONFLICT)
                        .with_response_description("Property cannot be modified"),
                );
            }
        }
    }
}
