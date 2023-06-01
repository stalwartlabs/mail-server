/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use super::{condition::ConfigCondition, *};
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

pub trait ConfigThrottle {
    fn parse_throttle(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_envelope_keys: &[EnvelopeKey],
        available_throttle_keys: u16,
    ) -> super::Result<Vec<Throttle>>;

    fn parse_throttle_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_envelope_keys: &[EnvelopeKey],
        available_throttle_keys: u16,
    ) -> super::Result<Throttle>;
}

impl ConfigThrottle for Config {
    fn parse_throttle(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_envelope_keys: &[EnvelopeKey],
        available_throttle_keys: u16,
    ) -> super::Result<Vec<Throttle>> {
        let prefix_ = prefix.as_key();
        let mut throttles = Vec::new();
        for array_pos in self.sub_keys(prefix) {
            throttles.push(self.parse_throttle_item(
                (&prefix_, array_pos),
                ctx,
                available_envelope_keys,
                available_throttle_keys,
            )?);
        }

        Ok(throttles)
    }

    fn parse_throttle_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_envelope_keys: &[EnvelopeKey],
        available_throttle_keys: u16,
    ) -> super::Result<Throttle> {
        let prefix = prefix.as_key();
        let mut keys = 0;
        for (key_, value) in self.values((&prefix, "key")) {
            let key = value.parse_throttle_key(key_)?;
            if (key & available_throttle_keys) != 0 {
                keys |= key;
            } else {
                return Err(format!(
                    "Throttle key {value:?} is not available in this context for property {key_:?}"
                ));
            }
        }

        let throttle = Throttle {
            conditions: if self.values((&prefix, "match")).next().is_some() {
                self.parse_condition((&prefix, "match"), ctx, available_envelope_keys)?
            } else {
                Conditions {
                    conditions: Vec::with_capacity(0),
                }
            },
            keys,
            concurrency: self
                .property::<u64>((prefix.as_str(), "concurrency"))?
                .filter(|&v| v > 0),
            rate: self
                .property::<Rate>((prefix.as_str(), "rate"))?
                .filter(|v| v.requests > 0),
        };

        // Validate
        if throttle.rate.is_none() && throttle.concurrency.is_none() {
            Err(format!(
                concat!(
                    "Throttle {:?} needs to define a ",
                    "valid 'rate' and/or 'concurrency' property."
                ),
                prefix
            ))
        } else {
            Ok(throttle)
        }
    }
}

impl ParseValue for EnvelopeKey {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            "rcpt" => EnvelopeKey::Recipient,
            "rcpt-domain" => EnvelopeKey::RecipientDomain,
            "sender" => EnvelopeKey::Sender,
            "sender-domain" => EnvelopeKey::SenderDomain,
            "listener" => EnvelopeKey::Listener,
            "remote-ip" => EnvelopeKey::RemoteIp,
            "local-ip" => EnvelopeKey::LocalIp,
            "priority" => EnvelopeKey::Priority,
            "authenticated-as" => EnvelopeKey::AuthenticatedAs,
            "mx" => EnvelopeKey::Mx,
            _ => {
                return Err(format!(
                    "Invalid context key {:?} for property {:?}.",
                    value,
                    key.as_key()
                ))
            }
        })
    }
}

pub trait ParseTrottleKey {
    fn parse_throttle_key(&self, key: &str) -> super::Result<u16>;
}

impl ParseTrottleKey for &str {
    fn parse_throttle_key(&self, key: &str) -> super::Result<u16> {
        match *self {
            "rcpt" => Ok(THROTTLE_RCPT),
            "rcpt-domain" => Ok(THROTTLE_RCPT_DOMAIN),
            "sender" => Ok(THROTTLE_SENDER),
            "sender-domain" => Ok(THROTTLE_SENDER_DOMAIN),
            "authenticated-as" => Ok(THROTTLE_AUTH_AS),
            "listener" => Ok(THROTTLE_LISTENER),
            "mx" => Ok(THROTTLE_MX),
            "remote-ip" => Ok(THROTTLE_REMOTE_IP),
            "local-ip" => Ok(THROTTLE_LOCAL_IP),
            "helo-domain" => Ok(THROTTLE_HELO_DOMAIN),
            _ => Err(format!("Invalid throttle key {self:?} found in {key:?}")),
        }
    }
}
