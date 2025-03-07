/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::{
    RequestHeaders,
    schema::{
        property::{DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, MultiStatus, PropStat, Response},
    },
};
use groupware::file::{FileNode, hierarchy::FileHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl, collection::Collection, property::Property, type_state::DataType,
};
use store::write::{Archive, BatchBuilder, assert::HashedValue, log::Changes, now};
use trc::AddContext;

use crate::{
    DavError,
    common::uri::DavUriResource,
    file::{DavFileResource, acl::FileAclRequestHandler},
};

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
        request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self.validate_uri(access_token, headers.uri).await?;
        let uri = headers.uri;
        let account_id = resource.account_id()?;
        let files = self
            .fetch_file_hierarchy(account_id)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(resource)?;

        // Fetch node
        let node_ = self
            .get_property::<HashedValue<Archive>>(
                account_id,
                Collection::FileNode,
                resource.resource,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_
            .to_unarchived::<FileNode>()
            .caused_by(trc::location!())?;

        // Validate ACL
        self.validate_file_acl(
            access_token,
            account_id,
            node.inner,
            Acl::Modify,
            Acl::ModifyItems,
        )
        .await?;
        let node = node.into_deserialized().caused_by(trc::location!())?;
        let mut new_node = node.inner.clone();

        // Remove properties
        let mut items = Vec::with_capacity(request.remove.len() + request.set.len());
        for property in request.remove {
            match property {
                DavProperty::WebDav(WebDavProperty::DisplayName) => {
                    new_node.display_name = None;
                    items.push(
                        PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                            .with_status(StatusCode::OK),
                    );
                }
                DavProperty::WebDav(WebDavProperty::GetContentType) if new_node.file.is_some() => {
                    new_node.file.as_mut().unwrap().media_type = None;
                    items.push(
                        PropStat::new(DavProperty::WebDav(WebDavProperty::GetContentType))
                            .with_status(StatusCode::OK),
                    );
                }
                DavProperty::DeadProperty(dead) => {
                    new_node.dead_properties.remove_element(&dead);
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

        // Set properties
        self.apply_file_properties(&mut new_node, true, request.set, &mut items);

        if new_node != node.inner {
            // Build node
            new_node.modified = now() as i64;
            new_node.change_id = self.generate_snowflake_id().caused_by(trc::location!())?;

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let change_id = new_node.change_id;
            batch
                .with_change_id(change_id)
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .update_document(resource.resource)
                .log(Changes::update([resource.resource]))
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(node)
                        .with_changes(new_node)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            self.store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;

            // Broadcast state change
            self.broadcast_single_state_change(account_id, change_id, DataType::FileNode)
                .await;
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
            .with_xml_body(MultiStatus::new(vec![Response::new_propstat(uri, items)]).to_string()))
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
