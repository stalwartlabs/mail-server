/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
