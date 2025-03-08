/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::DavError;

pub(crate) trait DavAclHandler: Sync + Send {
    fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = crate::Result<u32>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn validate_child_or_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        parent_id: Option<u32>,
        child_acl: impl Into<Bitmap<Acl>> + Send,
        parent_acl: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = crate::Result<()>> + Send;
}

impl DavAclHandler for Server {
    async fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<u32> {
        match parent_id {
            Some(parent_id) => {
                if access_token.is_member(account_id)
                    || self
                        .has_access_to_document(
                            access_token,
                            account_id,
                            collection,
                            parent_id,
                            check_acls,
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    Ok(parent_id + 1)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
            None => {
                if access_token.is_member(account_id) {
                    Ok(0)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
        }
    }

    async fn validate_child_or_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        parent_id: Option<u32>,
        child_acl: impl Into<Bitmap<Acl>> + Send,
        parent_acl: impl Into<Bitmap<Acl>> + Send,
    ) -> crate::Result<()> {
        if access_token.is_member(account_id)
            || self
                .has_access_to_document(
                    access_token,
                    account_id,
                    collection,
                    document_id,
                    child_acl,
                )
                .await
                .caused_by(trc::location!())?
            || (parent_id.is_some()
                && self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        collection,
                        parent_id.unwrap(),
                        parent_acl,
                    )
                    .await
                    .caused_by(trc::location!())?)
        {
            Ok(())
        } else {
            Err(DavError::Code(StatusCode::FORBIDDEN))
        }
    }
}
