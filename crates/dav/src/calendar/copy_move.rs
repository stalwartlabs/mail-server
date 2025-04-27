/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{Depth, RequestHeaders, schema::response::CalCondition};
use groupware::{
    DavName, DestroyArchive,
    calendar::{Calendar, CalendarEvent, CalendarPreferences, Timezone},
    hierarchy::DavHierarchy,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{DavError, DavErrorCondition, common::uri::DavUriResource, file::DavFileResource};

use super::assert_is_unique_uid;

pub(crate) trait CalendarCopyMoveRequestHandler: Sync + Send {
    fn handle_calendar_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarCopyMoveRequestHandler for Server {
    async fn handle_calendar_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let from_account_id = from_resource_.account_id;
        let from_resources = self
            .fetch_dav_resources(access_token, from_account_id, Collection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let from_resource_name = from_resource_
            .resource
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let from_resource = from_resources
            .paths
            .by_name(from_resource_name)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        // Validate ACL
        if !access_token.is_member(from_account_id)
            && !self
                .has_access_to_document(
                    access_token,
                    from_account_id,
                    Collection::Calendar,
                    if from_resource.is_container() {
                        from_resource.document_id
                    } else {
                        from_resource.parent_id.unwrap()
                    },
                    Acl::ReadItems,
                )
                .await
                .caused_by(trc::location!())?
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate destination
        let destination = self
            .validate_uri(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
            )
            .await?;
        if destination.collection != Collection::Calendar {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let to_account_id = destination
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let to_resources = if to_account_id == from_account_id {
            from_resources.clone()
        } else {
            self.fetch_dav_resources(access_token, to_account_id, Collection::Calendar)
                .await
                .caused_by(trc::location!())?
        };

        // Map destination
        let destination_resource_name = destination
            .resource
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        if let Some(to_resource) = to_resources.paths.by_name(destination_resource_name) {
            if from_resource.name == to_resource.name {
                // Same resource
                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
            }
            let new_name = destination_resource_name
                .rsplit_once('/')
                .map(|(_, name)| name)
                .unwrap_or(destination_resource_name);

            match (from_resource.is_container(), to_resource.is_container()) {
                (true, true) => {
                    let from_children_ids = from_resources
                        .subtree(from_resource_name)
                        .filter(|r| !r.is_container())
                        .map(|r| r.document_id)
                        .collect::<Vec<_>>();
                    let to_document_ids = to_resources
                        .subtree(destination_resource_name)
                        .filter(|r| !r.is_container())
                        .map(|r| r.document_id)
                        .collect::<Vec<_>>();

                    // Validate ACLs
                    if !access_token.is_member(to_account_id)
                        || (!access_token.is_member(from_account_id)
                            && !self
                                .has_access_to_document(
                                    access_token,
                                    from_account_id,
                                    Collection::Calendar,
                                    from_resource.document_id,
                                    if is_move {
                                        Acl::RemoveItems
                                    } else {
                                        Acl::ReadItems
                                    },
                                )
                                .await
                                .caused_by(trc::location!())?)
                    {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }

                    // Overwrite container
                    copy_container(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id,
                        from_children_ids,
                        to_account_id,
                        to_resource.document_id.into(),
                        to_document_ids,
                        new_name,
                        is_move,
                    )
                    .await
                }
                (false, false) => {
                    // Overwrite event
                    let from_calendar_id = from_resource.parent_id.unwrap();
                    let to_calendar_id = to_resource.parent_id.unwrap();

                    // Validate ACL
                    if (!access_token.is_member(from_account_id)
                        && !self
                            .has_access_to_document(
                                access_token,
                                from_account_id,
                                Collection::Calendar,
                                from_calendar_id,
                                if is_move {
                                    Acl::RemoveItems
                                } else {
                                    Acl::ReadItems
                                },
                            )
                            .await
                            .caused_by(trc::location!())?)
                        || (!access_token.is_member(to_account_id)
                            && !self
                                .has_access_to_document(
                                    access_token,
                                    to_account_id,
                                    Collection::Calendar,
                                    to_calendar_id,
                                    Acl::RemoveItems,
                                )
                                .await
                                .caused_by(trc::location!())?)
                    {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }

                    let to_base_path = to_resources
                        .format_resource(to_resource)
                        .rsplit_once('/')
                        .unwrap()
                        .0
                        .to_string();
                    if is_move {
                        move_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            from_calendar_id,
                            to_account_id,
                            to_resource.document_id.into(),
                            to_calendar_id,
                            to_base_path,
                            new_name,
                        )
                        .await
                    } else {
                        copy_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            to_account_id,
                            to_resource.document_id.into(),
                            to_calendar_id,
                            to_base_path,
                            new_name,
                        )
                        .await
                    }
                }
                _ => Err(DavError::Code(StatusCode::BAD_GATEWAY)),
            }
        } else if let Some((parent_resource, new_name)) =
            to_resources.map_parent(destination_resource_name)
        {
            if let Some(parent_resource) = parent_resource {
                // Creating items under a event is not allowed
                // Copying/moving containers under a container is not allowed
                if !parent_resource.is_container() || from_resource.is_container() {
                    return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                }

                // Validate ACL
                let from_calendar_id = from_resource.parent_id.unwrap();
                let to_calendar_id = parent_resource.document_id;
                if (!access_token.is_member(from_account_id)
                    && !self
                        .has_access_to_document(
                            access_token,
                            from_account_id,
                            Collection::Calendar,
                            from_calendar_id,
                            if is_move {
                                Acl::RemoveItems
                            } else {
                                Acl::ReadItems
                            },
                        )
                        .await
                        .caused_by(trc::location!())?)
                    || (!access_token.is_member(to_account_id)
                        && !self
                            .has_access_to_document(
                                access_token,
                                to_account_id,
                                Collection::Calendar,
                                to_calendar_id,
                                Acl::AddItems,
                            )
                            .await
                            .caused_by(trc::location!())?)
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Copy/move event
                if is_move {
                    if from_account_id != to_account_id
                        || parent_resource.document_id != from_calendar_id
                    {
                        move_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            from_calendar_id,
                            to_account_id,
                            None,
                            to_calendar_id,
                            to_resources.format_resource(parent_resource),
                            new_name,
                        )
                        .await
                    } else {
                        rename_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            from_calendar_id,
                            new_name,
                        )
                        .await
                    }
                } else {
                    copy_event(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id,
                        from_calendar_id,
                        None,
                        to_calendar_id,
                        to_resources.format_resource(parent_resource),
                        new_name,
                    )
                    .await
                }
            } else {
                // Copying/moving events to the root is not allowed
                if !from_resource.is_container() {
                    return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                }

                // Shared users cannot create containers
                if !access_token.is_member(to_account_id) {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Validate ACLs
                if !access_token.is_member(from_account_id)
                    && !self
                        .has_access_to_document(
                            access_token,
                            from_account_id,
                            Collection::Calendar,
                            from_resource.document_id,
                            if is_move {
                                Acl::RemoveItems
                            } else {
                                Acl::ReadItems
                            },
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Copy/move container
                let from_children_ids = from_resources
                    .subtree(from_resource_name)
                    .filter(|r| !r.is_container())
                    .map(|r| r.document_id)
                    .collect::<Vec<_>>();
                if is_move {
                    if from_account_id != to_account_id {
                        copy_container(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            if headers.depth != Depth::Zero {
                                from_children_ids
                            } else {
                                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                            },
                            to_account_id,
                            None,
                            vec![],
                            new_name,
                            true,
                        )
                        .await
                    } else {
                        rename_container(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            new_name,
                        )
                        .await
                    }
                } else {
                    copy_container(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id,
                        if headers.depth != Depth::Zero {
                            from_children_ids
                        } else {
                            vec![]
                        },
                        to_account_id,
                        None,
                        vec![],
                        new_name,
                        false,
                    )
                    .await
                }
            }
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn copy_event(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_calendar_id: u32,
    to_base_path: String,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch event
    let event_ = server
        .get_archive(from_account_id, Collection::CalendarEvent, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let event = event_
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();

    if from_account_id == to_account_id {
        if let Some(name) = event
            .inner
            .names
            .iter()
            .find(|n| n.parent_id == to_calendar_id)
        {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::NoUidConflict(format!("{}{}", to_base_path, name.name).into()),
            )));
        }
        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names.push(DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        });
        new_event
            .update(
                access_token,
                event,
                from_account_id,
                from_document_id,
                &mut batch,
            )
            .caused_by(trc::location!())?;
    } else {
        // Validate UID
        assert_is_unique_uid(
            server,
            server
                .fetch_dav_resources(access_token, to_account_id, Collection::Calendar)
                .await
                .caused_by(trc::location!())?
                .as_ref(),
            to_account_id,
            to_calendar_id,
            event.inner.data.event.uids().next().unwrap_or_default(),
        )
        .await?;

        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names = vec![DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        }];
        let to_document_id = server
            .store()
            .assign_document_ids(to_account_id, Collection::CalendarEvent, 1)
            .await
            .caused_by(trc::location!())?;
        new_event
            .insert(access_token, to_account_id, to_document_id, &mut batch)
            .caused_by(trc::location!())?;
    }

    let response = if let Some(to_document_id) = to_document_id {
        // Overwrite event on destination
        let event_ = server
            .get_archive(to_account_id, Collection::CalendarEvent, to_document_id)
            .await
            .caused_by(trc::location!())?;
        if let Some(event_) = event_ {
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;

            DestroyArchive(event)
                .delete(
                    access_token,
                    to_account_id,
                    to_document_id,
                    to_calendar_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    } else {
        Ok(HttpResponse::new(StatusCode::CREATED))
    };

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    response
}

#[allow(clippy::too_many_arguments)]
async fn move_event(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    from_calendar_id: u32,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_calendar_id: u32,
    to_base_path: String,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch event
    let event_ = server
        .get_archive(from_account_id, Collection::CalendarEvent, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let event = event_
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    if from_account_id == to_account_id {
        let mut name_idx = None;
        for (idx, name) in event.inner.names.iter().enumerate() {
            if name.parent_id == to_calendar_id {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::NoUidConflict(format!("{}{}", to_base_path, name.name).into()),
                )));
            } else if name.parent_id == from_calendar_id {
                name_idx = Some(idx);
                break;
            }
        }

        let name_idx = if let Some(name_idx) = name_idx {
            name_idx
        } else {
            return Err(DavError::Code(StatusCode::NOT_FOUND));
        };

        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names.swap_remove(name_idx);
        new_event.names.push(DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        });
        new_event
            .update(
                access_token,
                event.clone(),
                from_account_id,
                from_document_id,
                &mut batch,
            )
            .caused_by(trc::location!())?;
    } else {
        // Validate UID
        assert_is_unique_uid(
            server,
            server
                .fetch_dav_resources(access_token, to_account_id, Collection::Calendar)
                .await
                .caused_by(trc::location!())?
                .as_ref(),
            to_account_id,
            to_calendar_id,
            event.inner.data.event.uids().next().unwrap_or_default(),
        )
        .await?;

        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names = vec![DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        }];

        DestroyArchive(event)
            .delete(
                access_token,
                from_account_id,
                from_document_id,
                from_calendar_id,
                &mut batch,
            )
            .caused_by(trc::location!())?;

        let to_document_id = server
            .store()
            .assign_document_ids(to_account_id, Collection::CalendarEvent, 1)
            .await
            .caused_by(trc::location!())?;
        new_event
            .insert(access_token, to_account_id, to_document_id, &mut batch)
            .caused_by(trc::location!())?;
    }

    let response = if let Some(to_document_id) = to_document_id {
        // Overwrite event on destination
        let event_ = server
            .get_archive(to_account_id, Collection::CalendarEvent, to_document_id)
            .await
            .caused_by(trc::location!())?;
        if let Some(event_) = event_ {
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;

            DestroyArchive(event)
                .delete(
                    access_token,
                    to_account_id,
                    to_document_id,
                    to_calendar_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    } else {
        Ok(HttpResponse::new(StatusCode::CREATED))
    };

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    response
}

#[allow(clippy::too_many_arguments)]
async fn rename_event(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    calendar_id: u32,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch event
    let event_ = server
        .get_archive(account_id, Collection::CalendarEvent, document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let event = event_
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;

    let name_idx = event
        .inner
        .names
        .iter()
        .position(|n| n.parent_id == calendar_id)
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let mut new_event = event
        .deserialize::<CalendarEvent>()
        .caused_by(trc::location!())?;
    new_event.names[name_idx].name = new_name.to_string();

    let mut batch = BatchBuilder::new();
    new_event
        .update(access_token, event, account_id, document_id, &mut batch)
        .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED))
}

#[allow(clippy::too_many_arguments)]
async fn copy_container(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    from_children_ids: Vec<u32>,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_children_ids: Vec<u32>,
    new_name: &str,
    remove_source: bool,
) -> crate::Result<HttpResponse> {
    // Fetch calendar
    let calendar_ = server
        .get_archive(from_account_id, Collection::Calendar, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let old_calendar = calendar_
        .to_unarchived::<Calendar>()
        .caused_by(trc::location!())?;
    let mut calendar = old_calendar
        .deserialize::<Calendar>()
        .caused_by(trc::location!())?;

    // Prepare write batch
    let mut batch = BatchBuilder::new();

    if remove_source {
        DestroyArchive(old_calendar)
            .delete(access_token, from_account_id, from_document_id, &mut batch)
            .caused_by(trc::location!())?;
    }

    let preference = calendar.preferences.into_iter().next().unwrap();
    calendar.name = new_name.to_string();
    calendar.default_alerts.clear();
    calendar.acls.clear();
    calendar.preferences = vec![CalendarPreferences {
        account_id: to_account_id,
        name: preference.name,
        description: preference.description,
        sort_order: 0,
        color: preference.color,
        flags: 0,
        time_zone: Timezone::Default,
    }];

    let is_overwrite = to_document_id.is_some();
    let to_document_id = if let Some(to_document_id) = to_document_id {
        // Overwrite destination
        let calendar_ = server
            .get_archive(to_account_id, Collection::Calendar, to_document_id)
            .await
            .caused_by(trc::location!())?;
        if let Some(calendar_) = calendar_ {
            let calendar = calendar_
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;

            DestroyArchive(calendar)
                .delete_with_events(
                    server,
                    access_token,
                    to_account_id,
                    to_document_id,
                    to_children_ids,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }

        to_document_id
    } else {
        server
            .store()
            .assign_document_ids(to_account_id, Collection::Calendar, 1)
            .await
            .caused_by(trc::location!())?
    };
    calendar
        .insert(access_token, to_account_id, to_document_id, &mut batch)
        .caused_by(trc::location!())?;

    // Copy children
    let mut required_space = 0;
    for from_child_document_id in from_children_ids {
        if let Some(event_) = server
            .get_archive(
                from_account_id,
                Collection::CalendarEvent,
                from_child_document_id,
            )
            .await?
        {
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_name = None;

            for name in event.inner.names.iter() {
                if name.parent_id == to_document_id {
                    continue;
                } else if name.parent_id == from_document_id {
                    new_name = Some(name.name.to_string());
                }
            }
            let new_name = if let Some(new_name) = new_name {
                DavName {
                    name: new_name,
                    parent_id: to_document_id,
                }
            } else {
                continue;
            };
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_event = event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            if from_account_id == to_account_id {
                if remove_source {
                    new_event
                        .names
                        .retain(|name| name.parent_id != from_document_id);
                }

                new_event.names.push(new_name);
                new_event
                    .update(
                        access_token,
                        event,
                        from_account_id,
                        from_document_id,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
            } else {
                if remove_source {
                    DestroyArchive(event)
                        .delete(
                            access_token,
                            from_account_id,
                            from_child_document_id,
                            from_document_id,
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;
                }

                let to_document_id = server
                    .store()
                    .assign_document_ids(to_account_id, Collection::CalendarEvent, 1)
                    .await
                    .caused_by(trc::location!())?;
                new_event.names = vec![new_name];
                required_space += new_event.size as u64;
                new_event
                    .insert(access_token, to_account_id, to_document_id, &mut batch)
                    .caused_by(trc::location!())?;
            }
        }
    }

    if from_account_id != to_account_id && required_space > 0 {
        server
            .has_available_quota(
                &server
                    .get_resource_token(access_token, to_account_id)
                    .await?,
                required_space,
            )
            .await?;
    }

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    if !is_overwrite {
        Ok(HttpResponse::new(StatusCode::CREATED))
    } else {
        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}

#[allow(clippy::too_many_arguments)]
async fn rename_container(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch calendar
    let calendar_ = server
        .get_archive(account_id, Collection::Calendar, document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let calendar = calendar_
        .to_unarchived::<Calendar>()
        .caused_by(trc::location!())?;
    let mut new_calendar = calendar
        .deserialize::<Calendar>()
        .caused_by(trc::location!())?;
    new_calendar.name = new_name.to_string();

    let mut batch = BatchBuilder::new();
    new_calendar
        .update(access_token, calendar, account_id, document_id, &mut batch)
        .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED))
}
