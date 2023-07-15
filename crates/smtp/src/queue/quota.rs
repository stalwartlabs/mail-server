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

use std::sync::{atomic::Ordering, Arc};

use dashmap::mapref::entry::Entry;

use crate::{
    config::QueueQuota,
    core::{Envelope, QueueCore},
};

use super::{Message, QuotaLimiter, SimpleEnvelope, Status, UsedQuota};

impl QueueCore {
    pub async fn has_quota(&self, message: &mut Message) -> bool {
        let mut queue_refs = Vec::new();

        if !self.config.quota.sender.is_empty() {
            for quota in &self.config.quota.sender {
                if !self
                    .reserve_quota(quota, message, message.size, 0, &mut queue_refs)
                    .await
                {
                    return false;
                }
            }
        }

        for quota in &self.config.quota.rcpt_domain {
            for (pos, domain) in message.domains.iter().enumerate() {
                if !self
                    .reserve_quota(
                        quota,
                        &SimpleEnvelope::new(message, &domain.domain),
                        message.size,
                        ((pos + 1) << 32) as u64,
                        &mut queue_refs,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        for quota in &self.config.quota.rcpt {
            for (pos, rcpt) in message.recipients.iter().enumerate() {
                if !self
                    .reserve_quota(
                        quota,
                        &SimpleEnvelope::new_rcpt(
                            message,
                            &message.domains[rcpt.domain_idx].domain,
                            &rcpt.address_lcase,
                        ),
                        message.size,
                        (pos + 1) as u64,
                        &mut queue_refs,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        message.queue_refs = queue_refs;

        true
    }

    async fn reserve_quota(
        &self,
        quota: &QueueQuota,
        envelope: &impl Envelope,
        size: usize,
        id: u64,
        refs: &mut Vec<UsedQuota>,
    ) -> bool {
        if !quota.conditions.conditions.is_empty() && quota.conditions.eval(envelope).await {
            match self.quota.entry(quota.new_key(envelope)) {
                Entry::Occupied(e) => {
                    if let Some(qref) = e.get().is_allowed(id, size) {
                        refs.push(qref);
                    } else {
                        return false;
                    }
                }
                Entry::Vacant(e) => {
                    let limiter = Arc::new(QuotaLimiter {
                        max_size: quota.size.unwrap_or(0),
                        max_messages: quota.messages.unwrap_or(0),
                        size: 0.into(),
                        messages: 0.into(),
                    });

                    if let Some(qref) = limiter.is_allowed(id, size) {
                        refs.push(qref);
                        e.insert(limiter);
                    } else {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl Message {
    pub fn release_quota(&mut self) {
        let mut quota_ids = Vec::with_capacity(self.domains.len() + self.recipients.len());
        for (pos, domain) in self.domains.iter().enumerate() {
            if matches!(
                &domain.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                quota_ids.push(((pos + 1) << 32) as u64);
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
            self.queue_refs.retain(|q| !quota_ids.contains(&q.id));
        }
    }
}

trait QuotaLimiterAllowed {
    fn is_allowed(&self, id: u64, size: usize) -> Option<UsedQuota>;
}

impl QuotaLimiterAllowed for Arc<QuotaLimiter> {
    fn is_allowed(&self, id: u64, size: usize) -> Option<UsedQuota> {
        if self.max_messages > 0 {
            if self.messages.load(Ordering::Relaxed) < self.max_messages {
                self.messages.fetch_add(1, Ordering::Relaxed);
            } else {
                return None;
            }
        }

        if self.max_size > 0 {
            if self.size.load(Ordering::Relaxed) + size < self.max_size {
                self.size.fetch_add(size, Ordering::Relaxed);
            } else {
                return None;
            }
        }

        Some(UsedQuota {
            id,
            size,
            limiter: self.clone(),
        })
    }
}

impl Drop for UsedQuota {
    fn drop(&mut self) {
        if self.limiter.max_messages > 0 {
            self.limiter.messages.fetch_sub(1, Ordering::Relaxed);
        }
        if self.limiter.max_size > 0 {
            self.limiter.size.fetch_sub(self.size, Ordering::Relaxed);
        }
    }
}
