/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    KV_RATE_LIMIT_SMTP, ThrottleKey,
    config::smtp::*,
    expr::{functions::ResolveVariable, *},
    listener::SessionStream,
};
use queue::QueueQuota;
use trc::SmtpEvent;
use utils::config::Rate;

use super::Session;

pub trait NewKey: Sized {
    fn new_key(&self, e: &impl ResolveVariable, context: &str) -> ThrottleKey;
}

impl NewKey for QueueQuota {
    fn new_key(&self, e: &impl ResolveVariable, _: &str) -> ThrottleKey {
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

impl NewKey for QueueRateLimiter {
    fn new_key(&self, e: &impl ResolveVariable, context: &str) -> ThrottleKey {
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
        hasher.update(&self.rate.period.as_secs().to_be_bytes()[..]);
        hasher.update(&self.rate.requests.to_be_bytes()[..]);
        hasher.update(context.as_bytes());

        ThrottleKey {
            hash: hasher.finalize().into(),
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn is_allowed(&mut self) -> bool {
        let throttles = if !self.data.rcpt_to.is_empty() {
            &self.server.core.smtp.queue.inbound_limiters.rcpt
        } else if self.data.mail_from.is_some() {
            &self.server.core.smtp.queue.inbound_limiters.sender
        } else {
            &self.server.core.smtp.queue.inbound_limiters.remote
        };

        for t in throttles {
            if t.expr.is_empty()
                || self
                    .server
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
                let key = t.new_key(self, "inbound");

                // Check rate
                match self
                    .server
                    .core
                    .storage
                    .lookup
                    .is_rate_allowed(KV_RATE_LIMIT_SMTP, key.hash.as_slice(), &t.rate, false)
                    .await
                {
                    Ok(Some(_)) => {
                        trc::event!(
                            Smtp(SmtpEvent::RateLimitExceeded),
                            SpanId = self.data.session_id,
                            Id = t.id.clone(),
                            Limit = vec![
                                trc::Value::from(t.rate.requests),
                                trc::Value::from(t.rate.period)
                            ],
                        );

                        return false;
                    }
                    Err(err) => {
                        trc::error!(
                            err.span_id(self.data.session_id)
                                .caused_by(trc::location!())
                        );
                    }
                    _ => (),
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

        match self
            .server
            .core
            .storage
            .lookup
            .is_rate_allowed(
                KV_RATE_LIMIT_SMTP,
                hasher.finalize().as_bytes(),
                rate,
                false,
            )
            .await
        {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(err) => {
                trc::error!(
                    err.span_id(self.data.session_id)
                        .caused_by(trc::location!())
                );
                true
            }
        }
    }
}
