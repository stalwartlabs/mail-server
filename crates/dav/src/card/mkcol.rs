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
use groupware::{contact::AddressBook, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{collection::Collection, type_state::DataType};
use store::write::{BatchBuilder, log::LogInsert, now};
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

use super::proppatch::CardPropPatchRequestHandler;

pub(crate) trait CardMkColRequestHandler: Sync + Send {
    fn handle_card_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardMkColRequestHandler for Server {
    async fn handle_card_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
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
        if name.contains('/') || !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        } else if self
            .fetch_dav_resources(account_id, Collection::AddressBook)
            .await
            .caused_by(trc::location!())?
            .paths
            .by_name(name)
            .is_some()
        {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate headers
        self.validate_headers(
            access_token,
            &headers,
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
        let change_id = self.generate_snowflake_id().caused_by(trc::location!())?;
        let now = now();
        let mut book = AddressBook {
            name: name.to_string(),
            created: now as i64,
            modified: now as i64,
            ..Default::default()
        };

        // Apply MKCOL properties
        let mut return_prop_stat = None;
        if let Some(mkcol) = request {
            let mut prop_stat = Vec::new();
            if !self.apply_addressbook_properties(&mut book, false, mkcol.props, &mut prop_stat) {
                return Ok(HttpResponse::new(StatusCode::FORBIDDEN).with_xml_body(
                    MkColResponse::new(prop_stat)
                        .with_namespace(Namespace::CardDav)
                        .to_string(),
                ));
            }
            if headers.ret != Return::Minimal {
                return_prop_stat = Some(prop_stat);
            }
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        batch
            .with_change_id(change_id)
            .with_account_id(account_id)
            .with_collection(Collection::AddressBook)
            .create_document()
            .log(LogInsert())
            .custom(ObjectIndexBuilder::<(), _>::new().with_changes(book))
            .caused_by(trc::location!())?;
        self.store()
            .write(batch)
            .await
            .caused_by(trc::location!())?;

        // Broadcast state change
        self.broadcast_single_state_change(account_id, change_id, DataType::AddressBook)
            .await;
        if let Some(prop_stat) = return_prop_stat {
            Ok(HttpResponse::new(StatusCode::CREATED).with_xml_body(
                MkColResponse::new(prop_stat)
                    .with_namespace(Namespace::CardDav)
                    .to_string(),
            ))
        } else {
            Ok(HttpResponse::new(StatusCode::CREATED))
        }
    }
}
