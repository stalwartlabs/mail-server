/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::schema::{
    property::{DavProperty, WebDavProperty},
    request::{DavPropertyValue, PropFind},
    response::{MultiStatus, PropStat, Response},
};
use groupware::file::{FileNode, hierarchy::FileHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection, property::Property};
use store::{
    ahash::AHashMap,
    dispatch::DocumentSet,
    query::log::Query,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{
    common::DavQuery,
    principal::propfind::{PrincipalPropFind, PrincipalResource},
};

pub(crate) trait HandleFilePropFindRequest: Sync + Send {
    fn handle_file_propfind_request(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl HandleFilePropFindRequest for Server {
    async fn handle_file_propfind_request(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
    ) -> crate::Result<HttpResponse> {
        let account_id = query.resource.account_id;
        let files = self
            .fetch_file_hierarchy(account_id)
            .await
            .caused_by(trc::location!())?;

        // Obtain document ids
        let mut document_ids = if !access_token.is_member(account_id) {
            let todo = "query children acls";
            self.shared_containers(
                access_token,
                account_id,
                Collection::FileNode,
                Bitmap::<Acl>::from_iter([Acl::ReadItems, Acl::Read]),
            )
            .await
            .caused_by(trc::location!())?
            .into()
        } else {
            None
        };

        // Filter by changelog
        let mut last_change_id = None;
        if let Some(change_id) = query.from_change_id {
            let changelog = self
                .store()
                .changes(account_id, Collection::FileNode, Query::Since(change_id))
                .await
                .caused_by(trc::location!())?;
            let limit = std::cmp::min(
                query.limit.unwrap_or(u32::MAX) as usize,
                self.core.dav.max_changes,
            );
            if changelog.to_change_id != 0 {
                last_change_id = Some(changelog.to_change_id);
            }
            let mut changes =
                RoaringBitmap::from_iter(changelog.changes.iter().map(|change| change.id() as u32));
            if changes.len() as usize > limit {
                changes = RoaringBitmap::from_sorted_iter(changes.into_iter().take(limit)).unwrap();
            }
            if let Some(document_ids) = &mut document_ids {
                *document_ids &= changes;
            } else {
                document_ids = Some(changes);
            }
        }

        let mut response = MultiStatus::new(Vec::with_capacity(16));
        let mut paths = if let Some(resource) = query.resource.resource {
            files
                .subtree_with_depth(resource, query.depth)
                .filter(|item| {
                    document_ids
                        .as_ref()
                        .is_none_or(|d| d.contains(item.document_id))
                })
                .map(|item| {
                    (
                        item.document_id,
                        (query.format_to_base_uri(&item.name), item.is_container),
                    )
                })
                .collect::<AHashMap<_, _>>()
        } else {
            if !query.depth_no_root || query.from_change_id.is_none() {
                self.prepare_principal_propfind_response(
                    access_token,
                    PrincipalResource::Id(account_id),
                    &query.propfind,
                    &mut response,
                )
                .await?;

                if query.depth == 0 {
                    return Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()));
                }
            }
            files
                .tree_with_depth(query.depth - 1)
                .filter(|item| {
                    document_ids
                        .as_ref()
                        .is_none_or(|d| d.contains(item.document_id))
                })
                .map(|item| {
                    (
                        item.document_id,
                        (query.format_to_base_uri(&item.name), item.is_container),
                    )
                })
                .collect::<AHashMap<_, _>>()
        };

        if paths.is_empty() && query.from_change_id.is_none() {
            response.add_response(Response::new_status(
                [query.format_to_base_uri(query.resource.resource.unwrap_or_default())],
                StatusCode::NOT_FOUND,
            ));

            return Ok(
                HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string())
            );
        }

        let todo = "prefer minimal";

        // Prepare response
        let (fields, is_all_prop) = match query.propfind {
            PropFind::PropName => {
                for (_, (path, is_container)) in paths {
                    response.add_response(Response::new_propstat(
                        path,
                        vec![PropStat::new_list(all_properties(is_container))],
                    ));
                }

                return Ok(
                    HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string())
                );
            }
            PropFind::AllProp(items) => (
                items
                    .into_iter()
                    .filter(|v| matches!(v, DavProperty::DeadProperty(_)))
                    .map(DavPropertyValue::empty)
                    .collect::<Vec<_>>(),
                true,
            ),
            PropFind::Prop(items) => (
                items
                    .into_iter()
                    .map(DavPropertyValue::empty)
                    .collect::<Vec<_>>(),
                false,
            ),
        };

        for (document_id, node_) in self
            .get_properties::<Archive<AlignedBytes>, _>(
                account_id,
                Collection::FileNode,
                &Paths(&paths),
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
        {
            let node = node_.unarchive::<FileNode>().caused_by(trc::location!())?;
            let (node_path, _) = paths.remove(&document_id).unwrap();
            let is_container = node.file.is_none();
            let mut fields = if is_all_prop {
                let mut all_fields = all_properties(is_container);
                if !fields.is_empty() {
                    all_fields.extend(fields.iter().cloned());
                }
                all_fields
            } else {
                fields.clone()
            };

            // Fill properties
            for fields in &mut fields {}

            // Add response
            response.add_response(Response::new_propstat(
                node_path,
                vec![PropStat::new_list(fields)],
            ));
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }
}

fn all_properties(is_container: bool) -> Vec<DavPropertyValue> {
    let mut props = vec![
        DavPropertyValue::empty(WebDavProperty::CreationDate),
        DavPropertyValue::empty(WebDavProperty::DisplayName),
        DavPropertyValue::empty(WebDavProperty::GetETag),
        DavPropertyValue::empty(WebDavProperty::GetLastModified),
        DavPropertyValue::empty(WebDavProperty::ResourceType),
        DavPropertyValue::empty(WebDavProperty::LockDiscovery),
        DavPropertyValue::empty(WebDavProperty::SupportedLock),
        DavPropertyValue::empty(WebDavProperty::CurrentUserPrincipal),
        DavPropertyValue::empty(WebDavProperty::SyncToken),
        DavPropertyValue::empty(WebDavProperty::Owner),
        DavPropertyValue::empty(WebDavProperty::SupportedPrivilegeSet),
        DavPropertyValue::empty(WebDavProperty::CurrentUserPrivilegeSet),
        DavPropertyValue::empty(WebDavProperty::Acl),
        DavPropertyValue::empty(WebDavProperty::AclRestrictions),
        DavPropertyValue::empty(WebDavProperty::InheritedAclSet),
        DavPropertyValue::empty(WebDavProperty::PrincipalCollectionSet),
    ];

    if is_container {
        props.extend([
            DavPropertyValue::empty(WebDavProperty::SupportedReportSet),
            DavPropertyValue::empty(WebDavProperty::QuotaAvailableBytes),
            DavPropertyValue::empty(WebDavProperty::QuotaUsedBytes),
        ]);
    } else {
        props.extend([
            DavPropertyValue::empty(WebDavProperty::GetContentLanguage),
            DavPropertyValue::empty(WebDavProperty::GetContentLength),
            DavPropertyValue::empty(WebDavProperty::GetContentType),
        ]);
    }

    props
}

struct Paths<'x>(&'x AHashMap<u32, (String, bool)>);

impl DocumentSet for Paths<'_> {
    fn min(&self) -> u32 {
        unimplemented!()
    }

    fn max(&self) -> u32 {
        unimplemented!()
    }

    fn contains(&self, id: u32) -> bool {
        self.0.contains_key(&id)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.0.keys().copied()
    }
}
