/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{Entry, Parser};
use common::{DavName, Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CardCondition},
};
use groupware::{cache::GroupwareCache, contact::ContactCard};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavErrorCondition, DavMethod,
    common::{
        ETag, ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
    fix_percent_encoding,
};

use super::assert_is_unique_uid;

pub(crate) trait CardUpdateRequestHandler: Sync + Send {
    fn handle_card_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardUpdateRequestHandler for Server {
    async fn handle_card_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        _is_patch: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let resource_name = fix_percent_encoding(
            resource
                .resource
                .ok_or(DavError::Code(StatusCode::CONFLICT))?,
        );

        if bytes.len() > self.core.groupware.max_vcard_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CardCondition::MaxResourceSize(self.core.groupware.max_vcard_size as u32),
            )));
        }
        let vcard_raw = std::str::from_utf8(&bytes).map_err(|_| {
            DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CardCondition::SupportedAddressData,
            ))
        })?;

        let vcard = match Parser::new(vcard_raw).strict().entry() {
            Entry::VCard(vcard) => vcard,
            _ => {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CardCondition::SupportedAddressData,
                )));
            }
        };

        if let Some(resource) = resources.by_path(resource_name.as_ref()) {
            if resource.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            let parent_id = resource.parent_id().unwrap();
            let document_id = resource.document_id();
            if !access_token.is_member(account_id)
                && !resources.has_access_to_container(access_token, parent_id, Acl::ModifyItems)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Update
            let card_ = self
                .get_archive(account_id, Collection::ContactCard, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let card = card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;

            // Validate headers
            match self
                .validate_headers(
                    access_token,
                    headers,
                    vec![ResourceState {
                        account_id,
                        collection: Collection::ContactCard,
                        document_id: Some(document_id),
                        etag: card.etag().into(),
                        path: resource_name.as_ref(),
                        ..Default::default()
                    }],
                    Default::default(),
                    DavMethod::PUT,
                )
                .await
            {
                Ok(_) => {}
                Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
                    if headers.ret == Return::Representation =>
                {
                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type("text/vcard; charset=utf-8")
                        .with_etag(card.etag())
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(card.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(card.inner.card.to_string()));
                }
                Err(e) => return Err(e),
            }

            // Validate quota
            let extra_bytes =
                (bytes.len() as u64).saturating_sub(u32::from(card.inner.size) as u64);
            if extra_bytes > 0 {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    extra_bytes,
                )
                .await?;
            }

            // Validate UID
            match (card.inner.card.uid(), vcard.uid()) {
                (Some(old_uid), Some(new_uid)) if old_uid == new_uid => {}
                (None, None) | (None, Some(_)) => {}
                _ => {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CardCondition::NoUidConflict(resources.format_resource(resource).into()),
                    )));
                }
            }

            // Build node
            let mut new_card = card
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;
            new_card.size = bytes.len() as u32;
            new_card.card = vcard;

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let etag = new_card
                .update(access_token, card, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?
                .etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name.as_ref()) {
            if !parent.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            if !access_token.is_member(account_id)
                && !resources.has_access_to_container(
                    access_token,
                    parent.document_id(),
                    Acl::AddItems,
                )
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
                    document_id: Some(u32::MAX),
                    path: resource_name.as_ref(),
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            // Validate quota
            if !bytes.is_empty() {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    bytes.len() as u64,
                )
                .await?;
            }

            // Validate UID
            assert_is_unique_uid(
                self,
                &resources,
                account_id,
                parent.document_id(),
                vcard.uid(),
            )
            .await?;

            // Build node
            let card = ContactCard {
                names: vec![DavName {
                    name: name.to_string(),
                    parent_id: parent.document_id(),
                }],
                card: vcard,
                size: bytes.len() as u32,
                ..Default::default()
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::ContactCard, 1)
                .await
                .caused_by(trc::location!())?;
            let etag = card
                .insert(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?
                .etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}
