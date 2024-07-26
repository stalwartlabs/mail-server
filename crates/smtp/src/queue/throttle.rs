/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::smtp::Throttle,
    expr::functions::ResolveVariable,
    listener::limiter::{ConcurrencyLimiter, InFlight},
};
use dashmap::mapref::entry::Entry;
use store::write::now;

use crate::core::{throttle::NewKey, SMTP};

use super::{Domain, Status};

#[derive(Debug)]
pub enum Error {
    Concurrency { limiter: ConcurrencyLimiter },
    Rate { retry_at: u64 },
}

impl SMTP {
    pub async fn is_allowed<'x>(
        &'x self,
        throttle: &'x Throttle,
        envelope: &impl ResolveVariable,
        in_flight: &mut Vec<InFlight>,
        session_id: u64,
    ) -> Result<(), Error> {
        if throttle.expr.is_empty()
            || self
                .core
                .eval_expr(&throttle.expr, envelope, "throttle", session_id)
                .await
                .unwrap_or(false)
        {
            let key = throttle.new_key(envelope);

            if let Some(rate) = &throttle.rate {
                if let Ok(Some(next_refill)) = self
                    .core
                    .storage
                    .lookup
                    .is_rate_allowed(key.as_ref(), rate, false)
                    .await
                {
                    trc::event!(
                        Queue(trc::QueueEvent::RateLimitExceeded),
                        SpanId = session_id,
                        Id = throttle.id.clone(),
                        Limit = rate.requests,
                        Interval = rate.period.as_secs()
                    );

                    return Err(Error::Rate {
                        retry_at: now() + next_refill,
                    });
                }
            }

            if let Some(concurrency) = &throttle.concurrency {
                match self.inner.queue_throttle.entry(key) {
                    Entry::Occupied(mut e) => {
                        let limiter = e.get_mut();
                        if let Some(inflight) = limiter.is_allowed() {
                            in_flight.push(inflight);
                        } else {
                            trc::event!(
                                Queue(trc::QueueEvent::ConcurrencyLimitExceeded),
                                SpanId = session_id,
                                Id = throttle.id.clone(),
                                Limit = limiter.max_concurrent,
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
