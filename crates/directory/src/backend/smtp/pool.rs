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

use async_trait::async_trait;
use deadpool::managed;
use mail_send::{smtp::AssertReply, Error};

use super::{SmtpClient, SmtpConnectionManager};

#[async_trait]
impl managed::Manager for SmtpConnectionManager {
    type Type = SmtpClient;
    type Error = Error;

    async fn create(&self) -> Result<SmtpClient, Error> {
        let mut client = self.builder.connect_opts(false).await?;
        let capabilities = client
            .capabilities(&self.builder.local_host, self.builder.is_lmtp)
            .await?;

        Ok(SmtpClient {
            capabilities,
            client,
            max_auth_errors: self.max_auth_errors,
            max_rcpt: self.max_rcpt,
            num_rcpts: 0,
            num_auth_failures: 0,
            sent_mail_from: false,
        })
    }

    async fn recycle(
        &self,
        conn: &mut SmtpClient,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<Error> {
        if conn.num_auth_failures < conn.max_auth_errors {
            conn.client
                .cmd(b"NOOP\r\n")
                .await?
                .assert_positive_completion()
                .map(|_| ())
                .map_err(managed::RecycleError::Backend)
        } else {
            Err(managed::RecycleError::StaticMessage(
                "No longer valid: Too many authentication failures",
            ))
        }
    }
}
