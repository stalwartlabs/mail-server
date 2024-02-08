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

use dashmap::mapref::entry::Entry;
use store::write::now;
use utils::listener::limiter::{ConcurrencyLimiter, InFlight};

use crate::{
    config::Throttle,
    core::{ResolveVariable, SMTP},
};

use super::{Domain, Status};

#[derive(Debug)]
pub enum Error {
    Concurrency { limiter: ConcurrencyLimiter },
    Rate { retry_at: u64 },
}

impl SMTP {
    pub async fn is_allowed(
        &self,
        throttle: &Throttle,
        envelope: &impl ResolveVariable,
        in_flight: &mut Vec<InFlight>,
        span: &tracing::Span,
    ) -> Result<(), Error> {
        if throttle.expr.is_empty()
            || self
                .eval_expr(&throttle.expr, envelope, "throttle")
                .await
                .unwrap_or(false)
        {
            let key = throttle.new_key(envelope);

            if let Some(rate) = &throttle.rate {
                if let Ok(Some(next_refill)) = self
                    .shared
                    .default_lookup_store
                    .is_rate_allowed(key.as_ref(), rate, false)
                    .await
                {
                    tracing::info!(
                        parent: span,
                        context = "throttle",
                        event = "rate-limit-exceeded",
                        max_requests = rate.requests,
                        max_interval = rate.period.as_secs(),
                        "Queue rate limit exceeded."
                    );
                    return Err(Error::Rate {
                        retry_at: now() + next_refill,
                    });
                }
            }

            if let Some(concurrency) = &throttle.concurrency {
                match self.queue.throttle.entry(key) {
                    Entry::Occupied(mut e) => {
                        let limiter = e.get_mut();
                        if let Some(inflight) = limiter.is_allowed() {
                            in_flight.push(inflight);
                        } else {
                            tracing::info!(
                                parent: span,
                                context = "throttle",
                                event = "too-many-requests",
                                max_concurrent = limiter.max_concurrent,
                                "Queue concurrency limit exceeded."
                            );
                            return Err(Error::Concurrency {
                                limiter: limiter.clone(),
                            });
                        }
                    }
                    Entry::Vacant(e) => {
                        let limiter = ConcurrencyLimiter::new(*concurrency);
                        if let Some(inflight) = limiter.is_allowed() {
                            in_flight.push(inflight);
                        }
                        e.insert(limiter);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Domain {
    pub fn set_throttle_error(&mut self, err: Error, on_hold: &mut Vec<ConcurrencyLimiter>) {
        match err {
            Error::Concurrency { limiter } => {
                on_hold.push(limiter);
                self.status = Status::TemporaryFailure(super::Error::ConcurrencyLimited);
            }
            Error::Rate { retry_at } => {
                self.retry.due = retry_at;
                self.status = Status::TemporaryFailure(super::Error::RateLimited);
            }
        }
    }
}
