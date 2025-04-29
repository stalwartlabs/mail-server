/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavErrorCondition,
    calendar::{
        CALENDAR_CONTAINER_PROPS, CALENDAR_ITEM_PROPS,
        query::{CalendarQueryHandler, try_parse_tz},
    },
    card::{
        CARD_CONTAINER_PROPS, CARD_ITEM_PROPS,
        query::{serialize_vcard_with_props, vcard_query},
    },
    common::{DavQueryResource, uri::DavUriResource},
    file::{FILE_CONTAINER_PROPS, FILE_ITEM_PROPS},
    principal::{CurrentUserPrincipal, propfind::PrincipalPropFind},
};
use calcard::common::timezone::Tz;
use common::{
    DavResource, DavResources, Server,
    auth::{AccessToken, AsTenantId},
};
use dav_proto::{
    Depth, RequestHeaders,
    parser::header::dav_base_uri,
    schema::{
        Collation, Namespace,
        property::{
            ActiveLock, CalDavProperty, CardDavProperty, DavProperty, DavValue, PrincipalProperty,
            Privilege, ReportSet, ResourceType, Rfc1123DateTime, SupportedCollation, SupportedLock,
            WebDavProperty,
        },
        request::{DavPropertyValue, PropFind},
        response::{
            AclRestrictions, BaseCondition, Href, List, MultiStatus, PropStat, Response,
            SupportedPrivilege,
        },
    },
};
use directory::{Type, backend::internal::manage::ManageDirectory};
use groupware::{
    DavCalendarResource, DavResourceName, calendar::ArchivedTimezone, hierarchy::DavHierarchy,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use percent_encoding::NON_ALPHANUMERIC;
use std::sync::Arc;
use store::{
    ahash::AHashMap,
    query::log::Query,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;

use super::{
    ArchivedResource, DavCollection, DavQuery, DavQueryFilter, ETag,
    acl::{DavAclHandler, Privileges},
    lock::{LockData, build_lock_key},
    uri::{UriResource, Urn},
};

pub(crate) trait PropFindRequestHandler: Sync + Send {
    fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_dav_query(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn dav_quota(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<PropFindAccountQuota>> + Send;
}

pub(crate) struct PropFindData {
    pub accounts: AHashMap<u32, PropFindAccountData>,
}

#[derive(Default)]
pub(crate) struct PropFindAccountData {
    pub sync_token: Option<String>,
    pub quota: Option<PropFindAccountQuota>,
    pub owner: Option<Href>,
    pub locks: Option<Archive<AlignedBytes>>,
    pub locks_not_found: bool,
}

#[derive(Clone, Default)]
pub(crate) struct PropFindAccountQuota {
    pub used: u64,
    pub available: u64,
}

#[derive(Debug)]
pub(crate) struct PropFindItem {
    pub name: String,
    pub account_id: u32,
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
}

impl PropFindRequestHandler for Server {
    async fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self.validate_uri(access_token, headers.uri).await?;

        // Reject Infinity depth for certain queries
        let return_children = match headers.depth {
            Depth::One | Depth::None => true,
            Depth::Zero => false,
            Depth::Infinity => {
                if resource.account_id.is_none()
                    || matches!(resource.collection, Collection::FileNode)
                {
                    return Err(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::PropFindFiniteDepth,
                    )
                    .into());
                }
                true
            }
        };

        // List shared resources
        if let Some(account_id) = resource.account_id {
            match resource.collection {
                Collection::FileNode | Collection::Calendar | Collection::AddressBook => {
                    self.handle_dav_query(
                        access_token,
                        DavQuery::propfind(
                            UriResource::new_owned(
                                resource.collection,
                                account_id,
                                resource.resource,
                            ),
                            request,
                            headers,
                        ),
                    )
                    .await
                }
                Collection::Principal => {
                    let mut response = MultiStatus::new(Vec::with_capacity(16));

                    if let Some(resource) = resource.resource {
                        response.add_response(Response::new_status(
                            [format!(
                                "{}/{}",
                                headers.base_uri().unwrap_or_default(),
                                resource
                            )],
                            StatusCode::NOT_FOUND,
                        ));
                    } else {
                        self.prepare_principal_propfind_response(
                            access_token,
                            Collection::Principal,
                            [account_id].into_iter(),
                            &request,
                            &mut response,
                        )
                        .await?;
                    }

                    Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()))
                }
                _ => unreachable!(),
            }
        } else {
            let mut response = MultiStatus::new(Vec::with_capacity(16));

            // Add container info
            if !headers.depth_no_root {
                let properties = match &request {
                    PropFind::PropName => {
                        response.add_response(Response::new_propstat(
                            resource.collection_path(),
                            vec![PropStat::new_list(vec![
                                DavPropertyValue::empty(DavProperty::WebDav(
                                    WebDavProperty::ResourceType,
                                )),
                                DavPropertyValue::empty(DavProperty::WebDav(
                                    WebDavProperty::CurrentUserPrincipal,
                                )),
                                DavPropertyValue::empty(DavProperty::WebDav(
                                    WebDavProperty::SupportedReportSet,
                                )),
                            ])],
                        ));
                        &[]
                    }
                    PropFind::AllProp(_) => [
                        DavProperty::WebDav(WebDavProperty::ResourceType),
                        DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
                        DavProperty::WebDav(WebDavProperty::SupportedReportSet),
                    ]
                    .as_slice(),
                    PropFind::Prop(items) => items,
                };

                if !matches!(request, PropFind::PropName) {
                    let mut fields = Vec::with_capacity(properties.len());
                    let mut fields_not_found = Vec::new();

                    for prop in properties {
                        match &prop {
                            DavProperty::WebDav(WebDavProperty::ResourceType) => {
                                fields.push(DavPropertyValue::new(
                                    prop.clone(),
                                    vec![ResourceType::Collection],
                                ));
                            }
                            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal) => {
                                fields.push(DavPropertyValue::new(
                                    prop.clone(),
                                    vec![access_token.current_user_principal()],
                                ));
                            }
                            DavProperty::Principal(PrincipalProperty::CalendarHomeSet) => {
                                fields.push(DavPropertyValue::new(
                                    prop.clone(),
                                    vec![Href(format!(
                                        "{}/{}/",
                                        DavResourceName::Cal.base_path(),
                                        percent_encoding::utf8_percent_encode(
                                            &access_token.name,
                                            NON_ALPHANUMERIC
                                        ),
                                    ))],
                                ));
                                response.set_namespace(Namespace::CalDav);
                            }
                            DavProperty::Principal(PrincipalProperty::AddressbookHomeSet) => {
                                fields.push(DavPropertyValue::new(
                                    prop.clone(),
                                    vec![Href(format!(
                                        "{}/{}/",
                                        DavResourceName::Card.base_path(),
                                        percent_encoding::utf8_percent_encode(
                                            &access_token.name,
                                            NON_ALPHANUMERIC
                                        ),
                                    ))],
                                ));
                                response.set_namespace(Namespace::CardDav);
                            }
                            DavProperty::WebDav(WebDavProperty::SupportedReportSet) => {
                                let reports = match resource.collection {
                                    Collection::Principal => ReportSet::principal(),
                                    Collection::Calendar | Collection::CalendarEvent => {
                                        ReportSet::calendar()
                                    }
                                    Collection::AddressBook | Collection::ContactCard => {
                                        ReportSet::addressbook()
                                    }
                                    _ => ReportSet::file(),
                                };

                                fields.push(DavPropertyValue::new(prop.clone(), reports));
                            }
                            _ => {
                                fields_not_found.push(DavPropertyValue::empty(prop.clone()));
                            }
                        }
                    }

                    let mut prop_stat = Vec::with_capacity(2);

                    if !fields.is_empty() {
                        prop_stat.push(PropStat::new_list(fields));
                    }

                    if !fields_not_found.is_empty() {
                        prop_stat.push(
                            PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND),
                        );
                    }

                    response.add_response(Response::new_propstat(
                        resource.collection_path(),
                        prop_stat,
                    ));
                }
            }

            if return_children {
                let ids = if !matches!(resource.collection, Collection::Principal) {
                    RoaringBitmap::from_iter(access_token.all_ids())
                } else {
                    // Return all principals
                    let principals = self
                        .store()
                        .list_principals(
                            None,
                            access_token.tenant_id(),
                            &[Type::Individual, Type::Group],
                            false,
                            0,
                            0,
                        )
                        .await
                        .caused_by(trc::location!())?;

                    RoaringBitmap::from_iter(principals.items.into_iter().map(|p| p.id()))
                };

                self.prepare_principal_propfind_response(
                    access_token,
                    resource.collection,
                    ids.into_iter(),
                    &request,
                    &mut response,
                )
                .await?;
            }

            Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
        }
    }

    async fn handle_dav_query(
        &self,
        access_token: &AccessToken,
        mut query: DavQuery<'_>,
    ) -> crate::Result<HttpResponse> {
        let mut response = MultiStatus::new(Vec::with_capacity(16));
        let mut data = PropFindData::new();
        let collection_container;
        let collection_children;
        let mut ctag = None;
        let mut paths;
        let mut query_filter = None;

        //let c = println!("handling DAV query {query:#?}");

        match std::mem::take(&mut query.resource) {
            DavQueryResource::Uri(resource) => {
                let account_id = resource.account_id;
                collection_container = resource.collection;
                collection_children = collection_container.child_collection().unwrap();
                let resources = self
                    .fetch_dav_resources(access_token, account_id, collection_container)
                    .await
                    .caused_by(trc::location!())?;
                response.set_namespace(collection_container.namespace());
                ctag = Some(resources.modseq.unwrap_or_default());

                // Obtain document ids
                let mut document_ids = if !access_token.is_member(account_id) {
                    self.shared_containers(
                        access_token,
                        account_id,
                        collection_container,
                        [Acl::ReadItems],
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?
                    .into()
                } else {
                    None
                };

                // Filter by changelog
                if let Some(change_id) = query.from_change_id {
                    let changelog = self
                        .store()
                        .changes(account_id, collection_children, Query::Since(change_id))
                        .await
                        .caused_by(trc::location!())?;
                    let limit = std::cmp::min(
                        query.limit.unwrap_or(u32::MAX) as usize,
                        self.core.groupware.max_changes,
                    );

                    // Set sync token
                    let sync_token = if changelog.to_change_id != 0 {
                        let sync_token = Urn::Sync(changelog.to_change_id).to_string();
                        data.accounts.entry(account_id).or_default().sync_token =
                            sync_token.clone().into();
                        sync_token
                    } else {
                        data.sync_token(self, account_id, collection_children)
                            .await
                            .caused_by(trc::location!())?
                    };
                    response.set_sync_token(sync_token);

                    let mut changes = RoaringBitmap::from_iter(
                        changelog.changes.iter().map(|change| change.id() as u32),
                    );
                    if changes.len() as usize > limit {
                        changes = RoaringBitmap::from_sorted_iter(changes.into_iter().take(limit))
                            .unwrap();
                    }
                    if let Some(document_ids) = &mut document_ids {
                        *document_ids &= changes;
                    } else {
                        document_ids = Some(changes);
                    }
                }

                paths = if let Some(resource) = resource.resource {
                    resources
                        .subtree_with_depth(resource, query.depth)
                        .filter(|item| {
                            document_ids
                                .as_ref()
                                .is_none_or(|d| d.contains(item.document_id))
                        })
                        .map(|item| {
                            PropFindItem::new(resources.format_resource(item), account_id, item)
                        })
                        .collect::<Vec<_>>()
                } else {
                    if !query.depth_no_root || query.from_change_id.is_none() {
                        self.prepare_principal_propfind_response(
                            access_token,
                            collection_container,
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

                    resources
                        .tree_with_depth(query.depth - 1)
                        .filter(|item| {
                            document_ids
                                .as_ref()
                                .is_none_or(|d| d.contains(item.document_id))
                        })
                        .map(|item| {
                            PropFindItem::new(resources.format_resource(item), account_id, item)
                        })
                        .collect::<Vec<_>>()
                };

                if paths.is_empty() && query.from_change_id.is_none() {
                    if let Some(resource) = resource.resource {
                        response.add_response(Response::new_status(
                            [resources.format_item(resource)],
                            StatusCode::NOT_FOUND,
                        ));
                    }

                    return Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()));
                }
            }
            DavQueryResource::Multiget {
                hrefs,
                parent_collection,
            } => {
                paths = Vec::with_capacity(hrefs.len());
                let mut resources_by_account: AHashMap<
                    u32,
                    (Arc<DavResources>, Arc<Option<RoaringBitmap>>),
                > = AHashMap::with_capacity(3);
                collection_container = parent_collection;
                collection_children = collection_container.child_collection().unwrap();
                response.set_namespace(collection_container.namespace());

                for item in hrefs {
                    let resource = match self
                        .validate_uri(access_token, &item)
                        .await
                        .and_then(|r| r.into_owned_uri())
                    {
                        Ok(resource) => resource,
                        Err(DavError::Code(code)) => {
                            response.add_response(Response::new_status([item], code));
                            continue;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    };

                    let account_id = resource.account_id;
                    let (resources, document_ids) =
                        if let Some(resources) = resources_by_account.get(&account_id) {
                            resources.clone()
                        } else {
                            let resources = self
                                .fetch_dav_resources(access_token, account_id, collection_container)
                                .await
                                .caused_by(trc::location!())?;
                            let document_ids = Arc::new(if !access_token.is_member(account_id) {
                                self.shared_containers(
                                    access_token,
                                    account_id,
                                    collection_container,
                                    [Acl::ReadItems],
                                    false,
                                )
                                .await
                                .caused_by(trc::location!())?
                                .into()
                            } else {
                                None
                            });
                            resources_by_account
                                .insert(account_id, (resources.clone(), document_ids.clone()));
                            (resources, document_ids)
                        };

                    /*let c = println!(
                        "resources: {:?} resource: {resource:?}",
                        resources
                            .paths
                            .iter()
                            .map(|r| r.name.to_string())
                            .collect::<Vec<_>>()
                    );*/

                    if let Some(resource) = resource
                        .resource
                        .and_then(|name| resources.paths.by_name(name))
                    {
                        if !resource.is_container() {
                            if document_ids
                                .as_ref()
                                .as_ref()
                                .is_none_or(|docs| docs.contains(resource.document_id))
                            {
                                paths.push(PropFindItem::new(
                                    resources.format_resource(resource),
                                    account_id,
                                    resource,
                                ));
                            } else {
                                response.add_response(
                                    Response::new_status([item], StatusCode::FORBIDDEN)
                                        .with_response_description(
                                            "Not enough permissions to access this shared resource",
                                        ),
                                );
                            }
                        } else {
                            response.add_response(
                                Response::new_status([item], StatusCode::FORBIDDEN)
                                    .with_response_description(
                                        "Multiget not allowed for collections",
                                    ),
                            );
                        }
                    } else {
                        response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
                    }
                }
            }
            DavQueryResource::Query {
                filter,
                parent_collection,
                items,
            } => {
                paths = items;
                query_filter = Some(filter);
                collection_container = parent_collection;
                collection_children = collection_container.child_collection().unwrap();
                response.set_namespace(collection_container.namespace());
            }
            DavQueryResource::None => unreachable!(),
        }

        if query.depth == usize::MAX && paths.len() > self.core.groupware.max_match_results {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                BaseCondition::NumberOfMatchesWithinLimit,
            )));
        }

        let mut skip_not_found = query.expand;
        let properties = match &query.propfind {
            PropFind::PropName => {
                let (container_props, children_props) = match collection_container {
                    Collection::FileNode => {
                        (FILE_CONTAINER_PROPS.as_slice(), FILE_ITEM_PROPS.as_slice())
                    }
                    Collection::Calendar => (
                        CALENDAR_CONTAINER_PROPS.as_slice(),
                        CALENDAR_ITEM_PROPS.as_slice(),
                    ),
                    Collection::AddressBook => {
                        (CARD_CONTAINER_PROPS.as_slice(), CARD_ITEM_PROPS.as_slice())
                    }
                    _ => unreachable!(),
                };

                for item in paths {
                    let props = if item.is_container {
                        container_props
                            .iter()
                            .cloned()
                            .map(DavPropertyValue::empty)
                            .collect::<Vec<_>>()
                    } else {
                        children_props
                            .iter()
                            .cloned()
                            .map(DavPropertyValue::empty)
                            .collect::<Vec<_>>()
                    };

                    response.add_response(Response::new_propstat(
                        item.name,
                        vec![PropStat::new_list(props)],
                    ));
                }

                return Ok(
                    HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string())
                );
            }
            PropFind::AllProp(items) => {
                skip_not_found = true;
                let mut result = Vec::with_capacity(items.len() + DavProperty::ALL_PROPS.len());
                result.extend(DavProperty::ALL_PROPS);
                result.extend(items.iter().filter(|field| !field.is_all_prop()).cloned());
                result
            }
            PropFind::Prop(items) => items.clone(),
        };

        let view_as_id = access_token.primary_id();
        for item in paths {
            let account_id = item.account_id;
            let document_id = item.document_id;
            let collection = if item.is_container {
                collection_container
            } else {
                collection_children
            };
            let archive_ = if let Some(archive_) = self
                .get_archive(account_id, collection, document_id)
                .await
                .caused_by(trc::location!())?
            {
                archive_
            } else {
                response.add_response(Response::new_status([item.name], StatusCode::NOT_FOUND));
                continue;
            };
            let archive = ArchivedResource::from_archive(&archive_, collection)
                .caused_by(trc::location!())?;

            // Filter
            let mut calendar_filter = None;
            if let Some(query_filter) = &query_filter {
                match (query_filter, &archive) {
                    (DavQueryFilter::Addressbook(filter), ArchivedResource::ContactCard(card)) => {
                        if !vcard_query(&card.inner.card, filter) {
                            continue;
                        }
                    }
                    (
                        DavQueryFilter::Calendar {
                            filter,
                            timezone,
                            max_time_range,
                        },
                        ArchivedResource::CalendarEvent(event),
                    ) => {
                        let mut query_handler = CalendarQueryHandler::new(
                            event.inner,
                            *max_time_range,
                            try_parse_tz(timezone)
                                .or_else(|| {
                                    item.parent_id.and_then(|calendar_id| {
                                        self.cached_dav_resources(account_id, Collection::Calendar)
                                            .and_then(|r| r.calendar_default_tz(calendar_id))
                                    })
                                })
                                .unwrap_or(Tz::UTC),
                        );
                        if !query_handler.filter(event.inner, filter) {
                            continue;
                        }
                        calendar_filter = Some(query_handler);
                    }
                    _ => (),
                }
            }

            // Fill properties
            let dead_properties = archive.dead_properties();
            let mut fields = Vec::with_capacity(properties.len());
            let mut fields_not_found = Vec::new();
            for property in &properties {
                match property {
                    DavProperty::WebDav(dav_property) => match dav_property {
                        WebDavProperty::CreationDate => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Timestamp(archive.created()),
                            ));
                        }
                        WebDavProperty::DisplayName => {
                            if let Some(name) = archive.display_name(view_as_id) {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(name.to_string()),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetContentLanguage => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetContentLength => {
                            if let Some(value) = archive.content_length() {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::Uint64(value as u64),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetContentType => {
                            if let Some(value) = archive.content_type() {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(value.to_string()),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetETag => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::String(archive_.etag()),
                            ));
                        }
                        WebDavProperty::GetCTag => {
                            if item.is_container {
                                let ctag = if let Some(ctag) = ctag {
                                    ctag
                                } else {
                                    self.store()
                                        .get_last_change_id(account_id, collection)
                                        .await?
                                        .unwrap_or_default()
                                };
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(format!("\"{ctag}\"")),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                            response.set_namespace(Namespace::CalendarServer);
                        }
                        WebDavProperty::GetLastModified => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Rfc1123Date(Rfc1123DateTime::new(archive.modified())),
                            ));
                        }
                        WebDavProperty::ResourceType => {
                            if let Some(resource_type) = archive.resource_type() {
                                fields.push(DavPropertyValue::new(property.clone(), resource_type));
                            } else {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::LockDiscovery => {
                            if let Some(locks) = data
                                .locks(self, account_id, collection_container, &item)
                                .await
                                .caused_by(trc::location!())?
                            {
                                fields.push(DavPropertyValue::new(property.clone(), locks));
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
                            if let Some(report_set) = archive.supported_report_set() {
                                fields.push(DavPropertyValue::new(property.clone(), report_set));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::SyncToken => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                data.sync_token(self, account_id, collection_children)
                                    .await
                                    .caused_by(trc::location!())?,
                            ));
                        }
                        WebDavProperty::CurrentUserPrincipal => {
                            if !query.expand {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![access_token.current_user_principal()],
                                ));
                            } else {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    self.expand_principal(
                                        access_token,
                                        access_token.primary_id(),
                                        &query.propfind,
                                    )
                                    .await?
                                    .map(DavValue::Response)
                                    .unwrap_or(DavValue::Null),
                                ));
                            }
                        }
                        WebDavProperty::QuotaAvailableBytes => {
                            if item.is_container {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    data.quota(self, access_token, account_id)
                                        .await
                                        .caused_by(trc::location!())?
                                        .available,
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::QuotaUsedBytes => {
                            if item.is_container {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    data.quota(self, access_token, account_id)
                                        .await
                                        .caused_by(trc::location!())?
                                        .used,
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::Owner => {
                            if !query.expand {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![
                                        data.owner(self, access_token, account_id)
                                            .await
                                            .caused_by(trc::location!())?,
                                    ],
                                ));
                            } else {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    self.expand_principal(
                                        access_token,
                                        account_id,
                                        &query.propfind,
                                    )
                                    .await?
                                    .map(DavValue::Response)
                                    .unwrap_or(DavValue::Null),
                                ));
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
                                        ))
                                        .with_opt_supported_privilege(
                                            (collection_container == Collection::Calendar).then(
                                                || {
                                                    SupportedPrivilege::new(
                                                        Privilege::ReadFreeBusy,
                                                        "Read free/busy information",
                                                    )
                                                },
                                            ),
                                        ),
                                ],
                            ));
                        }
                        WebDavProperty::CurrentUserPrivilegeSet => {
                            if let Some(acls) = archive.acls() {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    access_token.current_privilege_set(
                                        account_id,
                                        acls,
                                        collection_container == Collection::Calendar,
                                    ),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::Acl => {
                            if let Some(acls) = archive.acls() {
                                let aces = self
                                    .resolve_ace(
                                        access_token,
                                        account_id,
                                        acls,
                                        query.expand.then_some(&query.propfind),
                                    )
                                    .await?;

                                fields.push(DavPropertyValue::new(property.clone(), aces));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
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
                                vec![Href(
                                    DavResourceName::Principal.collection_path().to_string(),
                                )],
                            ));
                        }
                    },
                    DavProperty::DeadProperty(tag) => {
                        if let Some(value) = dead_properties.find_tag(&tag.name) {
                            fields.push(DavPropertyValue::new(property.clone(), value));
                        } else {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    }
                    DavProperty::CardDav(card_property) => match (card_property, &archive) {
                        (
                            CardDavProperty::AddressbookDescription,
                            ArchivedResource::AddressBook(book),
                        ) if book.inner.description.is_some() => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                book.inner.description.as_ref().unwrap().to_string(),
                            ));
                        }
                        (
                            CardDavProperty::SupportedAddressData,
                            ArchivedResource::AddressBook(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::SupportedAddressData,
                            ));
                        }
                        (
                            CardDavProperty::SupportedCollationSet,
                            ArchivedResource::AddressBook(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Collations(List(vec![
                                    SupportedCollation {
                                        collation: Collation::AsciiCasemap,
                                        namespace: Namespace::CardDav,
                                    },
                                    SupportedCollation {
                                        collation: Collation::UnicodeCasemap,
                                        namespace: Namespace::CardDav,
                                    },
                                ])),
                            ));
                        }
                        (CardDavProperty::MaxResourceSize, ArchivedResource::AddressBook(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_vcard_size as u64,
                            ));
                        }
                        (
                            CardDavProperty::AddressData(items),
                            ArchivedResource::ContactCard(card),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::CData(serialize_vcard_with_props(
                                    &card.inner.card,
                                    items,
                                )),
                            ));
                        }
                        _ => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                    },
                    DavProperty::CalDav(cal_property) => match (cal_property, &archive) {
                        (
                            CalDavProperty::CalendarDescription,
                            ArchivedResource::Calendar(calendar),
                        ) => {
                            if let Some(desc) = calendar
                                .inner
                                .preferences(account_id)
                                .description
                                .as_deref()
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    desc.to_string(),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (
                            CalDavProperty::CalendarTimezone,
                            ArchivedResource::Calendar(calendar),
                        ) => {
                            if let ArchivedTimezone::Custom(tz) =
                                &calendar.inner.preferences(account_id).time_zone
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::CData(tz.to_string()),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (CalDavProperty::TimezoneId, ArchivedResource::Calendar(calendar)) => {
                            if let ArchivedTimezone::IANA(tz) =
                                &calendar.inner.preferences(account_id).time_zone
                            {
                                fields
                                    .push(DavPropertyValue::new(property.clone(), tz.to_string()));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (
                            CalDavProperty::SupportedCalendarComponentSet,
                            ArchivedResource::Calendar(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::SupportedCalendarComponentSet,
                            ));
                        }
                        (CalDavProperty::SupportedCalendarData, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::SupportedCalendarData,
                            ));
                        }
                        (CalDavProperty::SupportedCollationSet, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Collations(List(vec![
                                    SupportedCollation {
                                        collation: Collation::AsciiCasemap,
                                        namespace: Namespace::CalDav,
                                    },
                                    SupportedCollation {
                                        collation: Collation::UnicodeCasemap,
                                        namespace: Namespace::CalDav,
                                    },
                                ])),
                            ));
                        }
                        (CalDavProperty::MaxResourceSize, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_ical_size as u64,
                            ));
                        }
                        (CalDavProperty::MinDateTime, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Timestamp(i64::MIN),
                            ));
                        }
                        (CalDavProperty::MaxDateTime, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Timestamp(32531605200),
                            ));
                        }
                        (CalDavProperty::MaxInstances, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_ical_instances as u64,
                            ));
                        }
                        (
                            CalDavProperty::MaxAttendeesPerInstance,
                            ArchivedResource::Calendar(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_ical_attendees_per_instance as u64,
                            ));
                        }
                        (
                            CalDavProperty::CalendarData(data),
                            ArchivedResource::CalendarEvent(event),
                        ) => {
                            let ical = if calendar_filter.is_some() || !data.properties.is_empty() {
                                calendar_filter
                                    .get_or_insert_with(|| {
                                        CalendarQueryHandler::new(event.inner, None, Tz::UTC)
                                    })
                                    .serialize_ical(event.inner, data)
                            } else {
                                event.inner.data.event.to_string()
                            };

                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::CData(ical),
                            ));
                        }

                        _ => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                    },

                    property => {
                        if !skip_not_found {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    }
                }
            }

            // Add dead properties
            if skip_not_found && !dead_properties.0.is_empty() {
                dead_properties.to_dav_values(&mut fields);
            }

            // Add response
            let mut prop_stat = Vec::with_capacity(2);
            if !fields.is_empty() {
                prop_stat.push(PropStat::new_list(fields));
            }
            if !fields_not_found.is_empty() && !query.is_minimal() {
                prop_stat
                    .push(PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND));
            }
            if prop_stat.is_empty() {
                prop_stat.push(PropStat::new_list(vec![]));
            }
            response.add_response(Response::new_propstat(item.name, prop_stat));
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }

    async fn dav_quota(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<PropFindAccountQuota> {
        let resource_token = self
            .get_resource_token(access_token, account_id)
            .await
            .caused_by(trc::location!())?;
        let quota = if resource_token.quota > 0 {
            resource_token.quota
        } else if let Some(tenant) = resource_token.tenant.filter(|t| t.quota > 0) {
            tenant.quota
        } else {
            u32::MAX as u64
        };
        let used = self
            .get_used_quota(account_id)
            .await
            .caused_by(trc::location!())? as u64;

        Ok(PropFindAccountQuota {
            used,
            available: quota.saturating_sub(used),
        })
    }
}

impl PropFindItem {
    pub fn new(name: String, account_id: u32, resource: &DavResource) -> Self {
        Self {
            name,
            account_id,
            document_id: resource.document_id,
            parent_id: resource.parent_id,
            is_container: resource.is_container(),
        }
    }
}

impl PropFindData {
    pub fn new() -> Self {
        Self {
            accounts: AHashMap::with_capacity(2),
        }
    }

    pub async fn quota(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<PropFindAccountQuota> {
        let data = self.accounts.entry(account_id).or_default();

        if data.quota.is_none() {
            data.quota = server.dav_quota(access_token, account_id).await?.into();
        }

        Ok(data.quota.clone().unwrap())
    }

    pub async fn owner(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Href> {
        let data = self.accounts.entry(account_id).or_default();

        if data.owner.is_none() {
            data.owner = server
                .owner_href(access_token, account_id)
                .await
                .caused_by(trc::location!())?
                .into();
        }

        Ok(data.owner.clone().unwrap())
    }

    pub async fn sync_token(
        &mut self,
        server: &Server,
        account_id: u32,
        collection_children: Collection,
    ) -> trc::Result<String> {
        let data = self.accounts.entry(account_id).or_default();

        if data.sync_token.is_none() {
            let id = server
                .store()
                .get_last_change_id(account_id, collection_children)
                .await
                .caused_by(trc::location!())?
                .unwrap_or_default();
            data.sync_token = Urn::Sync(id).to_string().into();
        }

        Ok(data.sync_token.clone().unwrap())
    }

    pub async fn locks(
        &mut self,
        server: &Server,
        account_id: u32,
        collection_container: Collection,
        item: &PropFindItem,
    ) -> trc::Result<Option<Vec<ActiveLock>>> {
        let data = self.accounts.entry(account_id).or_default();

        if data.locks.is_none() && !data.locks_not_found {
            data.locks = server
                .in_memory_store()
                .key_get::<Archive<AlignedBytes>>(
                    build_lock_key(account_id, collection_container).as_slice(),
                )
                .await
                .caused_by(trc::location!())?;
            if data.locks.is_none() {
                data.locks_not_found = true;
            }
        }

        if let Some(lock_data) = &data.locks {
            let base_uri = dav_base_uri(&item.name).unwrap_or_default();
            lock_data.unarchive::<LockData>().map(|locks| {
                locks
                    .find_locks(&item.name.strip_prefix(base_uri).unwrap()[1..], false)
                    .iter()
                    .map(|(path, lock)| lock.to_active_lock(format!("{base_uri}/{path}")))
                    .collect::<Vec<_>>()
                    .into()
            })
        } else {
            Ok(None)
        }
    }
}
