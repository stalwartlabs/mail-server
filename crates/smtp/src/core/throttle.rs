/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::smtp::{queue::QueueQuota, *},
    expr::{functions::ResolveVariable, *},
    listener::{limiter::ConcurrencyLimiter, SessionStream},
};
use dashmap::mapref::entry::Entry;
use utils::config::Rate;

use std::{
    hash::{BuildHasher, Hash, Hasher},
    sync::atomic::Ordering,
};

use super::{Session, SMTP};

#[derive(Debug, Clone, Eq)]
pub struct ThrottleKey {
    hash: [u8; 32],
}

impl PartialEq for ThrottleKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Hash for ThrottleKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl AsRef<[u8]> for ThrottleKey {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

#[derive(Default)]
pub struct ThrottleKeyHasher {
    hash: u64,
}

impl Hasher for ThrottleKeyHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        self.hash = u64::from_ne_bytes((&bytes[..std::mem::size_of::<u64>()]).try_into().unwrap());
    }
}

#[derive(Clone, Default)]
pub struct ThrottleKeyHasherBuilder {}

impl BuildHasher for ThrottleKeyHasherBuilder {
    type Hasher = ThrottleKeyHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ThrottleKeyHasher::default()
    }
}

pub trait NewKey: Sized {
    fn new_key(&self, e: &impl ResolveVariable) -> ThrottleKey;
}

impl NewKey for QueueQuota {
    fn new_key(&self, e: &impl ResolveVariable) -> ThrottleKey {
        let mut hasher = blake3::Hasher::new();

        if (self.keys & THROTTLE_RCPT) != 0 {
            hasher.update(e.resolve_variable(V_RECIPIENT).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_RCPT_DOMAIN) != 0 {
            hasher.update(
                e.resolve_variable(V_RECIPIENT_DOMAIN)
                    .to_string()
                    .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER) != 0 {
            let sender = e.resolve_variable(V_SENDER).into_string();
            hasher.update(
                if !sender.is_empty() {
                    sender.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER_DOMAIN) != 0 {
            let sender_domain = e.resolve_variable(V_SENDER_DOMAIN).into_string();
            hasher.update(
                if !sender_domain.is_empty() {
                    sender_domain.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }

        if let Some(messages) = &self.messages {
            hasher.update(&messages.to_ne_bytes()[..]);
        }

        if let Some(size) = &self.size {
            hasher.update(&size.to_ne_bytes()[..]);
        }

        ThrottleKey {
            hash: hasher.finalize().into(),
        }
    }
}

impl NewKey for Throttle {
    fn new_key(&self, e: &impl ResolveVariable) -> ThrottleKey {
        let mut hasher = blake3::Hasher::new();

        if (self.keys & THROTTLE_RCPT) != 0 {
            hasher.update(e.resolve_variable(V_RECIPIENT).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_RCPT_DOMAIN) != 0 {
            hasher.update(
                e.resolve_variable(V_RECIPIENT_DOMAIN)
                    .to_string()
                    .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER) != 0 {
            let sender = e.resolve_variable(V_SENDER).into_string();
            hasher.update(
                if !sender.is_empty() {
                    sender.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER_DOMAIN) != 0 {
            let sender_domain = e.resolve_variable(V_SENDER_DOMAIN).into_string();
            hasher.update(
                if !sender_domain.is_empty() {
                    sender_domain.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_HELO_DOMAIN) != 0 {
            hasher.update(e.resolve_variable(V_HELO_DOMAIN).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_AUTH_AS) != 0 {
            hasher.update(
                e.resolve_variable(V_AUTHENTICATED_AS)
                    .to_string()
                    .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_LISTENER) != 0 {
            hasher.update(e.resolve_variable(V_LISTENER).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_MX) != 0 {
            hasher.update(e.resolve_variable(V_MX).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_REMOTE_IP) != 0 {
            hasher.update(e.resolve_variable(V_REMOTE_IP).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_LOCAL_IP) != 0 {
            hasher.update(e.resolve_variable(V_LOCAL_IP).to_string().as_bytes());
        }
        if let Some(rate_limit) = &self.rate {
            hasher.update(&rate_limit.period.as_secs().to_ne_bytes()[..]);
            hasher.update(&rate_limit.requests.to_ne_bytes()[..]);
        }
        if let Some(concurrency) = &self.concurrency {
            hasher.update(&concurrency.to_ne_bytes()[..]);
        }

        ThrottleKey {
            hash: hasher.finalize().into(),
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn is_allowed(&mut self) -> bool {
        let throttles = if !self.data.rcpt_to.is_empty() {
            &self.core.core.smtp.session.throttle.rcpt_to
        } else if self.data.mail_from.is_some() {
            &self.core.core.smtp.session.throttle.mail_from
        } else {
            &self.core.core.smtp.session.throttle.connect
        };

        for t in throttles {
            if t.expr.is_empty()
                || self
                    .core
                    .core
                    .eval_expr(&t.expr, self, "throttle", self.data.session_id)
                    .await
                    .unwrap_or(false)
            {
                if (t.keys & THROTTLE_RCPT_DOMAIN) != 0 {
                    let d = self
                        .data
                        .rcpt_to
                        .last()
                        .map(|r| r.domain.as_str())
                        .unwrap_or_default();

                    if self.data.rcpt_to.iter().filter(|p| p.domain == d).count() > 1 {
                        continue;
                    }
                }

                // Build throttle key
                let key = t.new_key(self);

                // Check concurrency
                if let Some(concurrency) = &t.concurrency {
                    match self.core.inner.session_throttle.entry(key.clone()) {
                        Entry::Occupied(mut e) => {
                            let limiter = e.get_mut();
                            if let Some(inflight) = limiter.is_allowed() {
                                self.in_flight.push(inflight);
                            } else {
                                tracing::debug!(
                                    
                                    context = "throttle",
                                    event = "too-many-requests",
                                    max_concurrent = limiter.max_concurrent,
                                    "Too many concurrent requests."
                                );
                                return false;
                            }
                        }
                        Entry::Vacant(e) => {
                            let limiter = ConcurrencyLimiter::new(*concurrency);
                            if let Some(inflight) = limiter.is_allowed() {
                                self.in_flight.push(inflight);
                            }
                            e.insert(limiter);
                        }
                    }
                }

                // Check rate
                if let Some(rate) = &t.rate {
                    if self
                        .core
                        .core
                        .storage
                        .lookup
                        .is_rate_allowed(key.hash.as_slice(), rate, false)
                        .await
                        .unwrap_or_default()
                        .is_some()
                    {
                        tracing::debug!(
                            
                            context = "throttle",
                            event = "rate-limit-exceeded",
                            max_requests = rate.requests,
                            max_interval = rate.period.as_secs(),
                            "Rate limit exceeded."
                        );
                        return false;
                    }
                }
            }
        }

        true
    }

    pub async fn throttle_rcpt(&self, rcpt: &str, rate: &Rate, ctx: &str) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(rcpt.as_bytes());
        hasher.update(ctx.as_bytes());
        hasher.update(&rate.period.as_secs().to_ne_bytes()[..]);
        hasher.update(&rate.requests.to_ne_bytes()[..]);

        self.core
            .core
            .storage
            .lookup
            .is_rate_allowed(hasher.finalize().as_bytes(), rate, false)
            .await
            .unwrap_or_default()
            .is_none()
    }
}

impl SMTP {
    pub fn cleanup(&self) {
        for throttle in [&self.inner.session_throttle, &self.inner.queue_throttle] {
            throttle.retain(|_, v| v.concurrent.load(Ordering::Relaxed) > 0);
        }
    }
}
