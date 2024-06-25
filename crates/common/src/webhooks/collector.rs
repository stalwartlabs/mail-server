/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
