/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use directory::QueryBy;
use jmap_proto::{
    error::request::RequestError,
    request::capability::{Capability, Session},
    types::{acl::Acl, collection::Collection, id::Id},
};

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn handle_session_resource(
        &self,
        base_url: String,
        access_token: Arc<AccessToken>,
    ) -> Result<Session, RequestError> {
        let mut session = Session::new(base_url, &self.core.jmap.capabilities);
        session.set_state(access_token.state());
        session.set_primary_account(
            access_token.primary_id().into(),
            access_token.name.clone(),
            access_token
                .description
                .clone()
                .unwrap_or_else(|| access_token.name.clone()),
            None,
            &self.core.jmap.capabilities.account,
        );

        // Add secondary accounts
        for id in access_token.secondary_ids() {
            let is_personal = !access_token.is_member(*id);
            let is_readonly = is_personal
                && self
                    .shared_documents(&access_token, *id, Collection::Mailbox, Acl::AddItems)
                    .await
                    .map_or(true, |ids| ids.is_empty());

            session.add_account(
                (*id).into(),
                self.core
                    .storage
                    .directory
                    .query(QueryBy::Id(*id), false)
                    .await
                    .unwrap_or_default()
                    .map(|p| p.name)
                    .unwrap_or_else(|| Id::from(*id).to_string()),
                is_personal,
                is_readonly,
                Some(&[Capability::Mail, Capability::Quota, Capability::Blob]),
                &self.core.jmap.capabilities.account,
            );
        }

        Ok(session)
    }
}
