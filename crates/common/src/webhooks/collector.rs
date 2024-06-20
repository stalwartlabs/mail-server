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

use crate::{Core, Ipc};

use super::{manager::WebhookEvent, WebhookPayload, WebhookType};

impl Core {
    #[inline(always)]
    pub fn has_webhook_subscribers(&self, event_type: WebhookType) -> bool {
        self.web_hooks.events.contains(&event_type)
    }
}

impl Ipc {
    pub async fn send_webhook(&self, event_type: WebhookType, payload: WebhookPayload) {
        if let Err(err) = self
            .webhook_tx
            .send(WebhookEvent::Send {
                typ: event_type,
                payload: Arc::new(payload),
            })
            .await
        {
            tracing::warn!("Failed to send webhook event: {:?}", err);
        }
    }
}
