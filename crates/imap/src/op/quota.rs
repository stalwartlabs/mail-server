/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::{
    core::{Session, SessionData},
    op::ImapContext,
    spawn_op,
};
use common::listener::SessionStream;
use directory::Permission;
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{
        ImapResponse,
        capability::QuotaResourceName,
        quota::{Arguments, QuotaItem, QuotaResource, Response},
    },
    receiver::Request,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_get_quota(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStatus)?;

        let data = self.state.session_data();

        spawn_op!(data, {
            match request.parse_get_quota() {
                Ok(argument) => match data.get_quota(argument).await {
                    Ok(response) => {
                        data.write_bytes(response).await?;
                    }
                    Err(error) => {
                        data.write_error(error).await?;
                    }
                },
                Err(err) => data.write_error(err).await?,
            }

            Ok(())
        })
    }

    pub async fn handle_get_quota_root(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStatus)?;

        let data = self.state.session_data();
        let version = self.version;

        spawn_op!(data, {
            match request.parse_get_quota_root(version) {
                Ok(argument) => match data.get_quota_root(argument).await {
                    Ok(response) => {
                        data.write_bytes(response).await?;
                    }
                    Err(error) => {
                        data.write_error(error).await?;
                    }
                },
                Err(err) => data.write_error(err).await?,
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn get_quota(&self, arguments: Arguments) -> trc::Result<Vec<u8>> {
        let op_start = Instant::now();

        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate quota root
        let account_id: u32 = arguments
            .name
            .strip_prefix("#")
            .and_then(|id| id.parse().ok())
            .filter(|id| self.access_token.is_member(*id))
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details("Invalid quota root parameter.")
                    .id(arguments.tag.to_string())
            })?;

        // Obtain access token for mailbox
        let access_token = self
            .server
            .get_access_token(account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        let used_quota = self
            .server
            .get_used_quota(account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        trc::event!(
            Imap(trc::ImapEvent::GetQuota),
            SpanId = self.session_id,
            Id = arguments.name.clone(),
            Details = vec![
                trc::Value::from(used_quota),
                trc::Value::from(access_token.quota)
            ],
            Elapsed = op_start.elapsed()
        );

        // Build response
        let response = Response {
            quota_root_items: vec![],
            quota_items: vec![QuotaItem {
                name: arguments.name,
                resources: vec![QuotaResource {
                    resource: QuotaResourceName::Storage,
                    total: access_token.quota,
                    used: used_quota as u64,
                }],
            }],
        };

        Ok(StatusResponse::ok("GETQUOTA successful.")
            .with_tag(arguments.tag)
            .serialize(response.serialize()))
    }

    pub async fn get_quota_root(&self, arguments: Arguments) -> trc::Result<Vec<u8>> {
        let op_start = Instant::now();

        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox
        let account_id = if let Some(mailbox) = self.get_mailbox_by_name(&arguments.name) {
            mailbox.account_id
        } else {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("Mailbox does not exist.")
                .code(ResponseCode::TryCreate)
                .id(arguments.tag));
        };

        // Obtain access token for mailbox
        let access_token = self
            .server
            .get_access_token(account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        let used_quota = self
            .server
            .get_used_quota(account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        trc::event!(
            Imap(trc::ImapEvent::GetQuota),
            SpanId = self.session_id,
            MailboxName = arguments.name.clone(),
            Details = vec![
                trc::Value::from(used_quota),
                trc::Value::from(access_token.quota)
            ],
            Elapsed = op_start.elapsed()
        );

        // Build response
        let response = Response {
            quota_root_items: vec![arguments.name, format!("#{account_id}")],
            quota_items: vec![QuotaItem {
                name: format!("#{account_id}"),
                resources: vec![QuotaResource {
                    resource: QuotaResourceName::Storage,
                    total: access_token.quota,
                    used: used_quota as u64,
                }],
            }],
        };

        Ok(StatusResponse::ok("GETQUOTAROOT successful.")
            .with_tag(arguments.tag)
            .serialize(response.serialize()))
    }
}
