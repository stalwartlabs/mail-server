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

use store::{
    write::{BatchBuilder, QueueClass, ValueClass},
    ValueKey,
};

use crate::{
    config::QueueQuota,
    core::{ResolveVariable, SMTP},
};

use super::{Message, QuotaKey, SimpleEnvelope, Status};

impl SMTP {
    pub async fn has_quota(&self, message: &mut Message) -> bool {
        let mut quota_keys = Vec::new();

        if !self.queue.config.quota.sender.is_empty() {
            for quota in &self.queue.config.quota.sender {
                if !self
                    .check_quota(quota, message, message.size, 0, &mut quota_keys)
                    .await
                {
                    return false;
                }
            }
        }

        for quota in &self.queue.config.quota.rcpt_domain {
            for (pos, domain) in message.domains.iter().enumerate() {
                if !self
                    .check_quota(
                        quota,
                        &SimpleEnvelope::new(message, &domain.domain),
                        message.size,
                        ((pos + 1) << 32) as u64,
                        &mut quota_keys,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        for quota in &self.queue.config.quota.rcpt {
            for (pos, rcpt) in message.recipients.iter().enumerate() {
                if !self
                    .check_quota(
                        quota,
                        &SimpleEnvelope::new_rcpt(
                            message,
                            &message.domains[rcpt.domain_idx].domain,
                            &rcpt.address_lcase,
                        ),
                        message.size,
                        (pos + 1) as u64,
                        &mut quota_keys,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        message.quota_keys = quota_keys;

        true
    }

    async fn check_quota(
        &self,
        quota: &QueueQuota,
        envelope: &impl ResolveVariable,
        size: usize,
        id: u64,
        refs: &mut Vec<QuotaKey>,
    ) -> bool {
        if !quota.expr.is_empty()
            && self
                .eval_expr(&quota.expr, envelope, "check_quota")
                .await
                .unwrap_or(false)
        {
            let key = quota.new_key(envelope);
            if let Some(max_size) = quota.size {
                let used_size = self
                    .shared
                    .default_data_store
                    .get_counter(ValueKey::from(ValueClass::Queue(QueueClass::QuotaSize(
                        key.as_ref().to_vec(),
                    ))))
                    .await
                    .unwrap_or(0) as usize;
                if used_size + size > max_size {
                    return false;
                } else {
                    refs.push(QuotaKey::Size {
                        key: key.as_ref().to_vec(),
                        id,
                    });
                }
            }

            if let Some(max_messages) = quota.messages {
                let total_messages = self
                    .shared
                    .default_data_store
                    .get_counter(ValueKey::from(ValueClass::Queue(QueueClass::QuotaCount(
                        key.as_ref().to_vec(),
                    ))))
                    .await
                    .unwrap_or(0) as usize;
                if total_messages + 1 > max_messages {
                    return false;
                } else {
                    refs.push(QuotaKey::Count {
                        key: key.as_ref().to_vec(),
                        id,
                    });
                }
            }
        }
        true
    }
}

impl Message {
    pub fn release_quota(&mut self, batch: &mut BatchBuilder) {
        if self.quota_keys.is_empty() {
            return;
        }
        let mut quota_ids = Vec::with_capacity(self.domains.len() + self.recipients.len());
        for (pos, domain) in self.domains.iter().enumerate() {
            if matches!(
                &domain.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                quota_ids.push(((pos + 1) as u64) << 32);
            }
        }
        for (pos, rcpt) in self.recipients.iter().enumerate() {
            if matches!(
                &rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                quota_ids.push((pos + 1) as u64);
            }
        }

        if !quota_ids.is_empty() {
            let mut quota_keys = Vec::new();
            for quota_key in std::mem::take(&mut self.quota_keys) {
                match quota_key {
                    QuotaKey::Count { id, key } if quota_ids.contains(&id) => {
                        batch.add(ValueClass::Queue(QueueClass::QuotaCount(key)), -1);
                    }
                    QuotaKey::Size { id, key } if quota_ids.contains(&id) => {
                        batch.add(
                            ValueClass::Queue(QueueClass::QuotaSize(key)),
                            -(self.size as i64),
                        );
                    }
                    _ => {
                        quota_keys.push(quota_key);
                    }
                }
            }
            self.quota_keys = quota_keys;
        }
    }
}
