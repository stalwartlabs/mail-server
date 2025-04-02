/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{Entry, Parser};
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CardCondition},
};
use groupware::{DavName, IDX_CARD_UID, contact::ContactCard, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::{
    query::Filter,
    write::{BatchBuilder, now},
};
use trc::AddContext;

use crate::{
    DavError, DavErrorCondition, DavMethod,
    common::{
        ETag, ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};

pub(crate) trait CardUpdateRequestHandler: Sync + Send {
    fn handle_card_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardUpdateRequestHandler for Server {
    async fn handle_card_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
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
            .fetch_dav_resources(account_id, Collection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let resource_name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;

        if bytes.len() > self.core.dav.max_vcard_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CardCondition::MaxResourceSize(self.core.dav.max_vcard_size as u32),
            )));
        }
        let vcard_raw = std::str::from_utf8(&bytes).map_err(|_| {
            DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CardCondition::SupportedAddressData,
            ))
        })?;

        let vcard = match Parser::new(vcard_raw).entry() {
            Entry::VCard(vcard) => vcard,
            _ => {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CardCondition::SupportedAddressData,
                )));
            }
        };

        if let Some(resource) = resources.paths.by_name(resource_name) {
            if resource.is_container {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            let parent_id = resource.parent_id.unwrap();
            let document_id = resource.document_id;
            if !access_token.is_member(account_id)
                && !self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        Collection::AddressBook,
                        parent_id,
                        Acl::ModifyItems,
                    )
                    .await
                    .caused_by(trc::location!())?
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Update
            let card_ = self
                .get_archive(account_id, Collection::FileNode, document_id)
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
                    &headers,
                    vec![ResourceState {
                        account_id,
                        collection: Collection::ContactCard,
                        document_id: Some(document_id),
                        etag: card.etag().into(),
                        path: resource_name,
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
                        CardCondition::NoUidConflict(
                            headers.format_to_base_uri(resource_name).into(),
                        ),
                    )));
                }
            }

            // Build node
            let mut new_card = card
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;
            new_card.size = bytes.len() as u32;
            new_card.modified = now() as i64;
            new_card.card = vcard;

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::ContactCard)
                .update_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(card)
                        .with_changes(new_card)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name) {
            if !parent.is_container {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            if !access_token.is_member(account_id)
                && !self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        Collection::AddressBook,
                        parent.document_id,
                        Acl::AddItems,
                    )
                    .await
                    .caused_by(trc::location!())?
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
                    document_id: Some(u32::MAX),
                    path: resource_name,
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
            if let Some(uid) = vcard.uid() {
                let hits = self
                    .store()
                    .filter(
                        account_id,
                        Collection::ContactCard,
                        vec![Filter::eq(IDX_CARD_UID, uid.as_bytes().to_vec())],
                    )
                    .await
                    .caused_by(trc::location!())?;
                if !hits.results.is_empty() {
                    for path in resources.paths.iter() {
                        if !path.is_container
                            && hits.results.contains(path.document_id)
                            && path.parent_id.unwrap() == parent.document_id
                        {
                            return Err(DavError::Condition(DavErrorCondition::new(
                                StatusCode::PRECONDITION_FAILED,
                                CardCondition::NoUidConflict(
                                    headers.format_to_base_uri(&path.name).into(),
                                ),
                            )));
                        }
                    }
                }
            }

            // Build node
            let now = now();
            let card = ContactCard {
                names: vec![DavName {
                    name: name.to_string(),
                    parent_id: parent.document_id,
                }],
                card: vcard,
                created: now as i64,
                modified: now as i64,
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
            batch
                .with_account_id(account_id)
                .with_collection(Collection::ContactCard)
                .create_document(document_id)
                .custom(
                    ObjectIndexBuilder::<(), _>::new()
                        .with_changes(card)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}
