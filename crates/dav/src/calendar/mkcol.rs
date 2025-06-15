/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{Namespace, request::MkCol, response::MkColResponse},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{Calendar, CalendarPreferences},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::{Collection, SyncCollection};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavMethod, PropStatBuilder,
    common::{
        ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

use super::proppatch::CalendarPropPatchRequestHandler;

pub(crate) trait CalendarMkColRequestHandler: Sync + Send {
    fn handle_calendar_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarMkColRequestHandler for Server {
    async fn handle_calendar_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        if !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        } else if name.contains('/')
            || self
                .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
                .await
                .caused_by(trc::location!())?
                .by_path(name)
                .is_some()
        {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: Some(u32::MAX),
                path: name,
                ..Default::default()
            }],
            Default::default(),
            DavMethod::MKCOL,
        )
        .await?;

        // Build file container
        let mut calendar = Calendar {
            name: name.to_string(),
            preferences: vec![CalendarPreferences {
                account_id,
                name: name.to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        // Apply MKCOL properties
        let mut return_prop_stat = None;
        let mut is_mkcalendar = false;
        if let Some(mkcol) = request {
            let mut prop_stat = PropStatBuilder::default();
            is_mkcalendar = mkcol.is_mkcalendar;
            if !self.apply_calendar_properties(
                account_id,
                &mut calendar,
                false,
                mkcol.props,
                &mut prop_stat,
            ) {
                return Ok(HttpResponse::new(StatusCode::FORBIDDEN).with_xml_body(
                    MkColResponse::new(prop_stat.build())
                        .with_namespace(Namespace::CalDav)
                        .with_mkcalendar(is_mkcalendar)
                        .to_string(),
                ));
            }
            if headers.ret != Return::Minimal {
                return_prop_stat = Some(prop_stat);
            }
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::Calendar, 1)
            .await
            .caused_by(trc::location!())?;
        calendar
            .insert(access_token, account_id, document_id, &mut batch)
            .caused_by(trc::location!())?;
        let etag = batch.etag();
        self.commit_batch(batch).await.caused_by(trc::location!())?;

        if let Some(prop_stat) = return_prop_stat {
            Ok(HttpResponse::new(StatusCode::CREATED)
                .with_xml_body(
                    MkColResponse::new(prop_stat.build())
                        .with_namespace(Namespace::CalDav)
                        .with_mkcalendar(is_mkcalendar)
                        .to_string(),
                )
                .with_etag_opt(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        }
    }
}
