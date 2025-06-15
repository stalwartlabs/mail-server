/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    contact::{AddressBook, ContactCard},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

pub(crate) trait CardDeleteRequestHandler: Sync + Send {
    fn handle_card_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardDeleteRequestHandler for Server {
    async fn handle_card_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let delete_path = resource
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;

        // Check resource type
        let delete_resource = resources
            .by_path(delete_path)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = delete_resource.document_id();

        // Fetch entry
        let mut batch = BatchBuilder::new();
        if delete_resource.is_container() {
            let book_ = self
                .get_archive(account_id, Collection::AddressBook, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            let book = book_
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;

            // Validate ACL
            if !access_token.is_member(account_id)
                && !book
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains_all([Acl::Delete, Acl::RemoveItems].into_iter())
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::AddressBook,
                    document_id: document_id.into(),
                    etag: book.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Delete addressbook and cards
            DestroyArchive(book)
                .delete_with_cards(
                    self,
                    access_token,
                    account_id,
                    document_id,
                    resources
                        .subtree(delete_path)
                        .filter(|r| !r.is_container())
                        .map(|r| r.document_id())
                        .collect::<Vec<_>>(),
                    resources.format_resource(delete_resource).into(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        } else {
            // Validate ACL
            let addressbook_id = delete_resource.parent_id().unwrap();
            if !access_token.is_member(account_id)
                && !resources.has_access_to_container(
                    access_token,
                    addressbook_id,
                    Acl::RemoveItems,
                )
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            let card_ = self
                .get_archive(account_id, Collection::ContactCard, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::ContactCard,
                    document_id: document_id.into(),
                    etag: card_.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Delete card
            DestroyArchive(
                card_
                    .to_unarchived::<ContactCard>()
                    .caused_by(trc::location!())?,
            )
            .delete(
                access_token,
                account_id,
                document_id,
                addressbook_id,
                resources.format_resource(delete_resource).into(),
                &mut batch,
            )
            .caused_by(trc::location!())?;
        }

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}
