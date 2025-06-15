/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

pub(crate) trait CalendarGetRequestHandler: Sync + Send {
    fn handle_calendar_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarGetRequestHandler for Server {
    async fn handle_calendar_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let resource = resources
            .by_path(
                resource_
                    .resource
                    .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
            )
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate ACL
        if !access_token.is_member(account_id)
            && !resources.has_access_to_container(
                access_token,
                resource.parent_id().unwrap(),
                Acl::ReadItems,
            )
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Fetch event
        let event_ = self
            .get_archive(
                account_id,
                Collection::CalendarEvent,
                resource.document_id(),
            )
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let event = event_
            .unarchive::<CalendarEvent>()
            .caused_by(trc::location!())?;

        // Validate headers
        let etag = event_.etag();
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: Collection::CalendarEvent,
                document_id: resource.document_id().into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::GET,
        )
        .await?;

        let response = HttpResponse::new(StatusCode::OK)
            .with_content_type("text/calendar; charset=utf-8")
            .with_etag(etag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(event.modified)).to_string());

        let ical = event.data.event.to_string();

        if !is_head {
            Ok(response.with_binary_body(ical))
        } else {
            Ok(response.with_content_length(ical.len()))
        }
    }
}
