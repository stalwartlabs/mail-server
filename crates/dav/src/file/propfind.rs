/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::schema::{
    property::{
        DavProperty, DavValue, Privilege, ReportSet, ResourceType, Rfc1123DateTime, SupportedLock,
        WebDavProperty,
    },
    request::{DavPropertyValue, PropFind},
    response::{
        AclRestrictions, BaseCondition, Href, MultiStatus, PropStat, Response, ResponseType,
        SupportedPrivilege,
    },
};
use groupware::{file::FileNode, hierarchy::DavHierarchy};
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
    DavError, DavErrorCondition, DavResource,
    common::{
        DavQuery, ETag,
        acl::{DavAclHandler, Privileges},
        lock::LockData,
        propfind::PropFindRequestHandler,
        uri::Urn,
    },
    principal::{CurrentUserPrincipal, propfind::PrincipalPropFind},
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
            .fetch_dav_hierarchy(account_id, Collection::FileNode)
            .await
            .caused_by(trc::location!())?;

        // Obtain document ids
        let mut document_ids = if !access_token.is_member(account_id) {
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
        let mut sync_token = None;
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
                sync_token = Some(Urn::Sync(changelog.to_change_id).to_string());
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
        let paths = if let Some(resource) = query.resource.resource {
            Paths::new(
                files
                    .subtree_with_depth(resource, query.depth)
                    .filter(|item| {
                        document_ids
                            .as_ref()
                            .is_none_or(|d| d.contains(item.document_id))
                    }),
            )
        } else {
            if !query.depth_no_root || query.from_change_id.is_none() {
                self.prepare_principal_propfind_response(
                    access_token,
                    Collection::FileNode,
                    [account_id].into_iter(),
                    &query.propfind,
                    &mut response,
                )
                .await?;

                if query.depth == 0 {
                    return Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()));
                }
            }
            Paths::new(files.tree_with_depth(query.depth - 1).filter(|item| {
                document_ids
                    .as_ref()
                    .is_none_or(|d| d.contains(item.document_id))
            }))
        };

        if paths.is_empty() && query.from_change_id.is_none() {
            response.add_response(Response::new_status(
                [query.format_to_base_uri(query.resource.resource.unwrap_or_default())],
                StatusCode::NOT_FOUND,
            ));

            return Ok(
                HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string())
            );
        } else if query.depth == usize::MAX && paths.len() > self.core.dav.max_match_results {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                BaseCondition::NumberOfMatchesWithinLimit,
            )));
        }

        // Prepare response
        let (fields, is_all_prop) = match &query.propfind {
            PropFind::PropName => {
                for (_, item) in paths.items {
                    let props = if item.is_container {
                        FOLDER_PROPS
                            .iter()
                            .cloned()
                            .map(DavPropertyValue::empty)
                            .collect::<Vec<_>>()
                    } else {
                        FILE_PROPS
                            .iter()
                            .cloned()
                            .map(DavPropertyValue::empty)
                            .collect::<Vec<_>>()
                    };

                    response.add_response(Response::new_propstat(
                        query.format_to_base_uri(&item.name),
                        vec![PropStat::new_list(props)],
                    ));
                }

                return Ok(
                    HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string())
                );
            }
            PropFind::AllProp(items) => (items, true),
            PropFind::Prop(items) => (items, false),
        };

        // Fetch sync token
        if sync_token.is_none()
            && (is_all_prop
                || query.from_change_id.is_some()
                || fields
                    .iter()
                    .any(|field| matches!(field, DavProperty::WebDav(WebDavProperty::SyncToken))))
        {
            let id = self
                .store()
                .get_last_change_id(account_id, Collection::FileNode)
                .await
                .caused_by(trc::location!())?
                .unwrap_or_default();
            sync_token = Some(Urn::Sync(id).to_string())
        }

        // Add sync token
        if query.from_change_id.is_some() {
            response = response.with_sync_token(sync_token.clone().unwrap());
        }

        // Fetch locks
        #[allow(unused_assignments)]
        let mut locks_ = None;
        let mut locks = None;
        if is_all_prop
            || fields
                .iter()
                .any(|field| matches!(field, DavProperty::WebDav(WebDavProperty::LockDiscovery)))
        {
            if let Some(lock_archive) = self
                .in_memory_store()
                .key_get::<Archive<AlignedBytes>>(query.resource.lock_key().as_slice())
                .await
                .caused_by(trc::location!())?
            {
                locks_ = Some(lock_archive);
                locks = Some(
                    locks_
                        .as_ref()
                        .unwrap()
                        .unarchive::<LockData>()
                        .caused_by(trc::location!())?,
                );
            }
        }

        // Fetch quota
        let (quota_used, quota_available) = if fields.iter().any(|field| {
            matches!(
                field,
                DavProperty::WebDav(
                    WebDavProperty::QuotaAvailableBytes | WebDavProperty::QuotaUsedBytes
                )
            )
        }) {
            self.dav_quota(access_token, account_id)
                .await
                .caused_by(trc::location!())?
        } else {
            (0, 0)
        };

        // Fetch owner
        let mut owner = None;
        if fields
            .iter()
            .any(|field| matches!(field, DavProperty::WebDav(WebDavProperty::Owner)))
        {
            owner = self
                .owner_href(access_token, account_id)
                .await
                .caused_by(trc::location!())?
                .into();
        }

        let mut aces = Vec::new();
        self.get_archives(
            account_id,
            Collection::FileNode,
            &paths,
            Property::Value,
            |document_id, node_| {
                let node = node_.unarchive::<FileNode>().caused_by(trc::location!())?;
                let item = paths.items.get(&document_id).unwrap();
                let properties: Box<dyn Iterator<Item = &DavProperty>> = if is_all_prop {
                    Box::new(
                        ALL_PROPS
                            .iter()
                            .chain(fields.iter().filter(|field| !field.is_all_prop())),
                    )
                } else {
                    Box::new(fields.iter())
                };

                // Fill properties
                let mut fields = Vec::with_capacity(19);
                let mut fields_not_found = Vec::new();
                for property in properties {
                    match property {
                        DavProperty::WebDav(dav_property) => match dav_property {
                            WebDavProperty::CreationDate => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::Timestamp(node.created.into()),
                                ));
                            }
                            WebDavProperty::DisplayName => {
                                if let Some(name) = node.display_name.as_ref() {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        DavValue::String(name.to_string()),
                                    ));
                                } else if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::GetContentLanguage => {
                                if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::GetContentLength => {
                                if let Some(value) = node.file.as_ref() {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        DavValue::Uint64(u32::from(value.size) as u64),
                                    ));
                                } else if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::GetContentType => {
                                if let Some(value) =
                                    node.file.as_ref().and_then(|file| file.media_type.as_ref())
                                {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        DavValue::String(value.to_string()),
                                    ));
                                } else if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::GetETag => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(node_.etag()),
                                ));
                            }
                            WebDavProperty::GetLastModified => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::Rfc1123Date(Rfc1123DateTime::new(
                                        node.modified.into(),
                                    )),
                                ));
                            }
                            WebDavProperty::ResourceType => {
                                if node.file.is_none() {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        vec![ResourceType::Collection],
                                    ));
                                } else {
                                    fields.push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::LockDiscovery => {
                                if let Some(locks) = locks.as_ref() {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        locks
                                            .find_locks(&item.name, false)
                                            .iter()
                                            .map(|(path, lock)| {
                                                lock.to_active_lock(query.format_to_base_uri(path))
                                            })
                                            .collect::<Vec<_>>(),
                                    ));
                                } else {
                                    fields.push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::SupportedLock => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    SupportedLock::default(),
                                ));
                            }
                            WebDavProperty::SupportedReportSet => {
                                if node.file.is_none() {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        vec![
                                            ReportSet::SyncCollection,
                                            ReportSet::AclPrincipalPropSet,
                                            ReportSet::PrincipalMatch,
                                        ],
                                    ));
                                } else if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::SyncToken => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    sync_token.clone().unwrap(),
                                ));
                            }
                            WebDavProperty::CurrentUserPrincipal => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![access_token.current_user_principal()],
                                ));
                            }
                            WebDavProperty::QuotaAvailableBytes => {
                                if node.file.is_none() {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        quota_available,
                                    ));
                                } else if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::QuotaUsedBytes => {
                                if node.file.is_none() {
                                    fields
                                        .push(DavPropertyValue::new(property.clone(), quota_used));
                                } else if !is_all_prop {
                                    fields_not_found
                                        .push(DavPropertyValue::empty(property.clone()));
                                }
                            }
                            WebDavProperty::Owner => {
                                if let Some(owner) = owner.take() {
                                    fields
                                        .push(DavPropertyValue::new(property.clone(), vec![owner]));
                                }
                            }
                            WebDavProperty::Group => {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                            WebDavProperty::SupportedPrivilegeSet => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![
                                        SupportedPrivilege::new(Privilege::All, "Any operation")
                                            .with_abstract()
                                            .with_supported_privilege(
                                                SupportedPrivilege::new(
                                                    Privilege::Read,
                                                    "Read objects",
                                                )
                                                .with_supported_privilege(SupportedPrivilege::new(
                                                    Privilege::ReadCurrentUserPrivilegeSet,
                                                    "Read current user privileges",
                                                )),
                                            )
                                            .with_supported_privilege(
                                                SupportedPrivilege::new(
                                                    Privilege::Write,
                                                    "Write objects",
                                                )
                                                .with_supported_privilege(SupportedPrivilege::new(
                                                    Privilege::WriteProperties,
                                                    "Write properties",
                                                ))
                                                .with_supported_privilege(SupportedPrivilege::new(
                                                    Privilege::WriteContent,
                                                    "Write object contents",
                                                ))
                                                .with_supported_privilege(SupportedPrivilege::new(
                                                    Privilege::Bind,
                                                    "Add resources to a collection",
                                                ))
                                                .with_supported_privilege(SupportedPrivilege::new(
                                                    Privilege::Unbind,
                                                    "Add resources to a collection",
                                                ))
                                                .with_supported_privilege(SupportedPrivilege::new(
                                                    Privilege::Unlock,
                                                    "Unlock resources",
                                                )),
                                            )
                                            .with_supported_privilege(SupportedPrivilege::new(
                                                Privilege::ReadAcl,
                                                "Read ACL",
                                            ))
                                            .with_supported_privilege(SupportedPrivilege::new(
                                                Privilege::WriteAcl,
                                                "Write ACL",
                                            )),
                                    ],
                                ));
                            }
                            WebDavProperty::CurrentUserPrivilegeSet => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    access_token.current_privilege_set(account_id, &node.acls),
                                ));
                            }
                            WebDavProperty::Acl => {
                                aces.push(access_token.ace(account_id, &node.acls));
                            }
                            WebDavProperty::AclRestrictions => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    AclRestrictions::default()
                                        .with_no_invert()
                                        .with_grant_only(),
                                ));
                            }
                            WebDavProperty::InheritedAclSet => {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                            WebDavProperty::PrincipalCollectionSet => {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![Href(DavResource::Principal.base_path().to_string())],
                                ));
                            }
                            WebDavProperty::AlternateURISet
                            | WebDavProperty::PrincipalURL
                            | WebDavProperty::GroupMemberSet
                            | WebDavProperty::GroupMembership => {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        },
                        DavProperty::DeadProperty(tag) => {
                            if let Some(value) = node.dead_properties.find_tag(&tag.name) {
                                fields.push(DavPropertyValue::new(property.clone(), value));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        property => {
                            if !is_all_prop {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                    }
                }

                // Add dead properties
                if is_all_prop && !node.dead_properties.0.is_empty() {
                    node.dead_properties.to_dav_values(&mut fields);
                }

                // Add response
                let mut prop_stat = Vec::with_capacity(2);
                if !fields.is_empty() || !aces.is_empty() {
                    prop_stat.push(PropStat::new_list(fields));
                }
                if !fields_not_found.is_empty() && !query.is_minimal() {
                    prop_stat.push(
                        PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND),
                    );
                }
                if prop_stat.is_empty() {
                    prop_stat.push(PropStat::new_list(vec![]));
                }
                response.add_response(Response::new_propstat(
                    query.format_to_base_uri(&item.name),
                    prop_stat,
                ));

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        // Resolve ACEs
        if !aces.is_empty() {
            for (ace, response) in aces.into_iter().zip(response.response.0.iter_mut()) {
                let ace = self.resolve_ace(ace).await.caused_by(trc::location!())?;
                if let ResponseType::PropStat(list) = &mut response.typ {
                    list.0
                        .first_mut()
                        .unwrap()
                        .prop
                        .0
                        .0
                        .push(DavPropertyValue::new(
                            DavProperty::WebDav(WebDavProperty::Acl),
                            ace,
                        ));
                }
            }
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }
}

static FOLDER_PROPS: [DavProperty; 19] = [
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

static FILE_PROPS: [DavProperty; 19] = [
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

static ALL_PROPS: [DavProperty; 17] = [
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

struct Paths<'x> {
    min: u32,
    max: u32,
    items: AHashMap<u32, &'x common::DavResource>,
}

impl<'x> Paths<'x> {
    pub fn new(iter: impl Iterator<Item = &'x common::DavResource>) -> Self {
        let mut paths = Paths {
            min: u32::MAX,
            max: 0,
            items: AHashMap::with_capacity(16),
        };

        for item in iter {
            if item.document_id < paths.min {
                paths.min = item.document_id;
            }

            if item.document_id > paths.max {
                paths.max = item.document_id;
            }

            paths.items.insert(item.document_id, item);
        }
        paths
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl DocumentSet for Paths<'_> {
    fn min(&self) -> u32 {
        self.min
    }

    fn max(&self) -> u32 {
        self.max
    }

    fn contains(&self, id: u32) -> bool {
        self.items.contains_key(&id)
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.items.keys().copied()
    }
}
