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

use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use utils::{
    config::KeyLookup,
    listener::limiter::{ConcurrencyLimiter, InFlight, RateLimiter},
};

use crate::{
    config::{EnvelopeKey, Throttle},
    core::{throttle::Limiter, QueueCore},
};

use super::{Domain, Status};

#[derive(Debug)]
pub enum Error {
    Concurrency { limiter: ConcurrencyLimiter },
    Rate { retry_at: Instant },
}

impl QueueCore {
    pub async fn is_allowed(
        &self,
        throttle: &Throttle,
        envelope: &impl KeyLookup<Key = EnvelopeKey>,
        in_flight: &mut Vec<InFlight>,
        span: &tracing::Span,
    ) -> Result<(), Error> {
        if throttle.conditions.conditions.is_empty() || throttle.conditions.eval(envelope).await {
            match self.throttle.entry(throttle.new_key(envelope)) {
                Entry::Occupied(mut e) => {
                    let limiter = e.get_mut();
                    if let Some(limiter) = &limiter.concurrency {
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
                    if let (Some(limiter), Some(rate)) = (&mut limiter.rate, &throttle.rate) {
                        if !limiter.is_allowed(rate) {
                            tracing::info!(
                                parent: span,
                                context = "throttle",
                                event = "rate-limit-exceeded",
                                max_requests = rate.requests,
                                max_interval = rate.period.as_secs(),
                                "Queue rate limit exceeded."
                            );
                            return Err(Error::Rate {
                                retry_at: Instant::now()
                                    + Duration::from_secs(limiter.secs_to_refill()),
                            });
                        }
                    }
                }
                Entry::Vacant(e) => {
                    let concurrency = throttle.concurrency.map(|concurrency| {
                        let limiter = ConcurrencyLimiter::new(concurrency);
                        if let Some(inflight) = limiter.is_allowed() {
                            in_flight.push(inflight);
                        }
                        limiter
                    });
                    let rate = throttle.rate.as_ref().map(|rate| {
                        let r = RateLimiter::new(rate);
                        r.is_allowed(rate);
                        r
                    });

                    e.insert(Limiter { rate, concurrency });
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
        self.changed = true;
    }
}
