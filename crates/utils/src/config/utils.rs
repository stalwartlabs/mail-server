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

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};

use mail_auth::{
    common::crypto::{Algorithm, HashAlgorithm},
    dkim::Canonicalization,
    IpLookupStrategy,
};
use smtp_proto::MtPriority;

use super::{Config, ConfigError, Rate};

impl Config {
    pub fn property<T: ParseValue>(&self, key: impl AsKey) -> super::Result<Option<T>> {
        let key = key.as_key();
        if let Some(value) = self.keys.get(&key) {
            T::parse_value(key, value).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn property_<T: ParseValue>(&mut self, key: impl AsKey) -> Option<T> {
        let key = key.as_key();
        if let Some(value) = self.keys.get(&key) {
            match T::parse_value(key.as_str(), value) {
                Ok(value) => Some(value),
                Err(err) => {
                    self.new_parse_error(key, err);
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn property_or_default<T: ParseValue>(
        &self,
        key: impl AsKey,
        default: &str,
    ) -> super::Result<T> {
        let key = key.as_key();
        let value = self.keys.get(&key).map_or(default, |v| v.as_str());
        T::parse_value(key, value)
    }

    pub fn property_or_default_<T: ParseValue>(
        &mut self,
        key: impl AsKey,
        default: &str,
    ) -> Option<T> {
        let key = key.as_key();
        let value = match self.keys.get(&key) {
            Some(value) => value.as_str(),
            None => {
                self.missing.insert(key.clone(), default.to_string().into());
                default
            }
        };
        match T::parse_value(key.as_str(), value) {
            Ok(value) => Some(value),
            Err(err) => {
                self.new_parse_error(key, err);
                None
            }
        }
    }

    pub fn property_or_else<T: ParseValue>(
        &self,
        key: impl AsKey,
        default: impl AsKey,
    ) -> super::Result<Option<T>> {
        match self.property(key) {
            Ok(None) => self.property(default),
            result => result,
        }
    }

    pub fn property_or_else_<T: ParseValue>(
        &mut self,
        key: impl AsKey,
        default: impl AsKey,
    ) -> Option<T> {
        let key = key.as_key();
        let value = match self.value_or_else(key.as_str(), default.clone()) {
            Some(value) => value,
            None => {
                self.missing.insert(default.as_key(), None);
                return None;
            }
        };

        match T::parse_value(key.as_str(), value) {
            Ok(value) => Some(value),
            Err(err) => {
                self.new_parse_error(key, err);
                None
            }
        }
    }

    pub fn property_require<T: ParseValue>(&self, key: impl AsKey) -> super::Result<T> {
        match self.property(key.clone()) {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(format!("Missing property {:?}.", key.as_key())),
            Err(err) => Err(err),
        }
    }

    pub fn property_require_<T: ParseValue>(&mut self, key: impl AsKey) -> Option<T> {
        let key = key.as_key();
        if let Some(value) = self.keys.get(&key) {
            match T::parse_value(key.as_str(), value) {
                Ok(value) => Some(value),
                Err(err) => {
                    self.new_parse_error(key, err);
                    None
                }
            }
        } else {
            self.new_parse_error(key, "Missing property");
            None
        }
    }

    pub fn sub_keys<'x, 'y: 'x>(
        &'y self,
        prefix: impl AsKey,
        suffix: &'y str,
    ) -> impl Iterator<Item = &str> + 'x {
        let mut last_key = "";
        let prefix = prefix.as_prefix();

        self.keys.keys().filter_map(move |key| {
            let key = key.strip_prefix(&prefix)?;
            let key = if !suffix.is_empty() {
                key.strip_suffix(suffix)?
            } else if let Some((key, _)) = key.split_once('.') {
                key
            } else {
                key
            };
            if last_key != key {
                last_key = key;
                Some(key)
            } else {
                None
            }
        })
    }

    pub fn set_values<'x, 'y: 'x>(&'y self, prefix: impl AsKey) -> impl Iterator<Item = &str> + 'x {
        let prefix = prefix.as_prefix();

        self.keys
            .keys()
            .filter_map(move |key| key.strip_prefix(&prefix))
    }

    pub fn set_values_or_else(
        &self,
        prefix: impl AsKey,
        default: impl AsKey,
    ) -> impl Iterator<Item = &str> {
        let mut prefix = prefix.as_prefix();

        self.set_values(if self.keys.keys().any(|k| k.starts_with(&prefix)) {
            prefix.truncate(prefix.len() - 1);
            prefix
        } else {
            default.as_key()
        })
    }

    pub fn properties<T: ParseValue>(
        &self,
        prefix: impl AsKey,
    ) -> impl Iterator<Item = super::Result<(&str, T)>> {
        let full_prefix = prefix.as_key();
        let prefix = prefix.as_prefix();

        self.keys.iter().filter_map(move |(key, value)| {
            if key.starts_with(&prefix) || key == &full_prefix {
                T::parse_value(key.as_str(), value)
                    .map(|value| (key.as_str(), value))
                    .into()
            } else {
                None
            }
        })
    }

    pub fn properties_<T: ParseValue>(&mut self, prefix: impl AsKey) -> Vec<(String, T)> {
        let full_prefix = prefix.as_key();
        let prefix = prefix.as_prefix();
        let mut results = Vec::new();

        for (key, value) in &self.keys {
            if key.starts_with(&prefix) || key == &full_prefix {
                match T::parse_value(key.as_str(), value) {
                    Ok(value) => {
                        results.push((key.to_string(), value));
                    }
                    Err(err) => {
                        self.errors.insert(key.to_string(), ConfigError::Parse(err));
                    }
                }
            }
        }

        results
    }

    pub fn value(&self, key: impl AsKey) -> Option<&str> {
        self.keys.get(&key.as_key()).map(|s| s.as_str())
    }

    pub fn contains_key(&self, key: impl AsKey) -> bool {
        self.keys.contains_key(&key.as_key())
    }

    pub fn value_require(&self, key: impl AsKey) -> super::Result<&str> {
        self.keys
            .get(&key.as_key())
            .map(|s| s.as_str())
            .ok_or_else(|| format!("Missing property {:?}.", key.as_key()))
    }

    pub fn value_require_(&mut self, key: impl AsKey) -> Option<&str> {
        let key = key.as_key();
        if let Some(value) = self.keys.get(&key) {
            Some(value.as_str())
        } else {
            self.errors
                .insert(key, ConfigError::Parse("Missing property".to_string()));
            None
        }
    }

    pub fn try_parse_value<T: ParseValue>(&mut self, key: impl AsKey, value: &str) -> Option<T> {
        match T::parse_value(key.clone(), value) {
            Ok(value) => Some(value),
            Err(err) => {
                self.errors.insert(key.as_key(), ConfigError::Parse(err));
                None
            }
        }
    }

    pub fn value_or_else(&self, key: impl AsKey, default: impl AsKey) -> Option<&str> {
        self.keys
            .get(&key.as_key())
            .or_else(|| self.keys.get(&default.as_key()))
            .map(|s| s.as_str())
    }

    pub fn values(&self, prefix: impl AsKey) -> impl Iterator<Item = (&str, &str)> {
        let full_prefix = prefix.as_key();
        let prefix = prefix.as_prefix();

        self.keys.iter().filter_map(move |(key, value)| {
            if key.starts_with(&prefix) || key == &full_prefix {
                (key.as_str(), value.as_str()).into()
            } else {
                None
            }
        })
    }

    pub fn values_or_else(
        &self,
        prefix: impl AsKey,
        default: impl AsKey,
    ) -> impl Iterator<Item = (&str, &str)> {
        let mut prefix = prefix.as_prefix();

        self.values(if self.keys.keys().any(|k| k.starts_with(&prefix)) {
            prefix.truncate(prefix.len() - 1);
            prefix
        } else {
            default.as_key()
        })
    }

    pub fn has_prefix(&self, prefix: impl AsKey) -> bool {
        let prefix = prefix.as_prefix();
        self.keys.keys().any(|k| k.starts_with(&prefix))
    }

    pub fn take_value(&mut self, key: &str) -> Option<String> {
        self.keys.remove(key)
    }

    pub fn value_or_warn(&mut self, key: impl AsKey) -> Option<&str> {
        let key = key.as_key();
        match self.keys.get(&key) {
            Some(value) => Some(value.as_str()),
            None => {
                self.missing.insert(key, None);
                None
            }
        }
    }

    pub fn new_parse_error(&mut self, key: impl AsKey, details: impl Into<String>) {
        self.errors
            .insert(key.as_key(), ConfigError::Parse(details.into()));
    }

    pub fn new_build_error(&mut self, key: impl AsKey, details: impl Into<String>) {
        self.errors
            .insert(key.as_key(), ConfigError::Build(details.into()));
    }

    pub fn new_missing_property(&mut self, key: impl AsKey) {
        self.missing.insert(key.as_key(), None);
    }
}

pub trait ParseValue: Sized {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self>;
}

pub trait ParseKey<T: ParseValue> {
    fn parse_key(&self, key: impl AsKey) -> super::Result<T>;
}

impl<T: ParseValue> ParseKey<T> for &str {
    fn parse_key(&self, key: impl AsKey) -> super::Result<T> {
        T::parse_value(key, self)
    }
}

impl<T: ParseValue> ParseKey<T> for String {
    fn parse_key(&self, key: impl AsKey) -> super::Result<T> {
        T::parse_value(key, self.as_str())
    }
}

impl<T: ParseValue> ParseKey<T> for &String {
    fn parse_key(&self, key: impl AsKey) -> super::Result<T> {
        T::parse_value(key, self.as_str())
    }
}

impl<T: ParseValue> ParseValue for Option<T> {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if !value.is_empty()
            && !value.eq_ignore_ascii_case("false")
            && !value.eq_ignore_ascii_case("disable")
            && !value.eq_ignore_ascii_case("disabled")
            && !value.eq_ignore_ascii_case("never")
            && !value.eq("0")
        {
            T::parse_value(key, value).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ParseValue for String {
    fn parse_value(_key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(value.to_string())
    }
}

impl ParseValue for u64 {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid integer value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for f64 {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid floating point value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for u16 {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid integer value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for i16 {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid integer value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for u32 {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid integer value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for i32 {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid integer value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for IpAddr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid IP address value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for usize {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid integer value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for bool {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid boolean value {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for Ipv4Addr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IPv4 value {:?} for key {:?}.", value, key.as_key()))
    }
}

impl ParseValue for Ipv6Addr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IPv6 value {:?} for key {:?}.", value, key.as_key()))
    }
}

impl ParseValue for PathBuf {
    fn parse_value(_key: impl AsKey, value: &str) -> super::Result<Self> {
        let path = PathBuf::from(value);

        if path.exists() {
            Ok(path)
        } else {
            Err(format!("Directory {} does not exist.", path.display()))
        }
    }
}

impl ParseValue for MtPriority {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mixer" => Ok(MtPriority::Mixer),
            "stanag4406" => Ok(MtPriority::Stanag4406),
            "nsep" => Ok(MtPriority::Nsep),
            _ => Err(format!(
                "Invalid priority value {:?} for property {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for Canonicalization {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "relaxed" => Ok(Canonicalization::Relaxed),
            "simple" => Ok(Canonicalization::Simple),
            _ => Err(format!(
                "Invalid canonicalization value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for IpLookupStrategy {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value.to_lowercase().as_str() {
            "ipv4_only" => IpLookupStrategy::Ipv4Only,
            "ipv6_only" => IpLookupStrategy::Ipv6Only,
            //"ipv4_and_ipv6" => IpLookupStrategy::Ipv4AndIpv6,
            "ipv6_then_ipv4" => IpLookupStrategy::Ipv6thenIpv4,
            "ipv4_then_ipv6" => IpLookupStrategy::Ipv4thenIpv6,
            _ => {
                return Err(format!(
                    "Invalid IP lookup strategy {:?} for property {:?}.",
                    value,
                    key.as_key()
                ))
            }
        })
    }
}

impl ParseValue for Algorithm {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "ed25519-sha256" | "ed25519-sha-256" => Ok(Algorithm::Ed25519Sha256),
            "rsa-sha-256" | "rsa-sha256" => Ok(Algorithm::RsaSha256),
            "rsa-sha-1" | "rsa-sha1" => Ok(Algorithm::RsaSha1),
            _ => Err(format!(
                "Invalid algorithm {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for HashAlgorithm {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            "sha-1" | "sha1" => Ok(HashAlgorithm::Sha1),
            _ => Err(format!(
                "Invalid hash algorithm {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for Duration {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        let mut digits = String::new();
        let mut multiplier = String::new();

        for ch in value.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
            } else if !ch.is_ascii_whitespace() {
                multiplier.push(ch.to_ascii_lowercase());
            }
        }

        let multiplier = match multiplier.as_str() {
            "d" => 24 * 60 * 60 * 1000,
            "h" => 60 * 60 * 1000,
            "m" => 60 * 1000,
            "s" => 1000,
            "ms" | "" => 1,
            _ => {
                return Err(format!(
                    "Invalid duration value {:?} for property {:?}.",
                    value,
                    key.as_key()
                ))
            }
        };

        digits
            .parse::<u64>()
            .ok()
            .and_then(|num| {
                if num > 0 {
                    Some(Duration::from_millis(num * multiplier))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                format!(
                    "Invalid duration value {:?} for property {:?}.",
                    value,
                    key.as_key()
                )
            })
    }
}

impl ParseValue for Rate {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((requests, period)) = value.split_once('/') {
            Ok(Rate {
                requests: requests
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|r| if r > 0 { Some(r) } else { None })
                    .ok_or_else(|| {
                        format!(
                            "Invalid rate value {:?} for property {:?}.",
                            value,
                            key.as_key()
                        )
                    })?,
                period: std::cmp::max(period.parse_key(key)?, Duration::from_secs(1)),
            })
        } else if ["false", "none", "unlimited"].contains(&value) {
            Ok(Rate::default())
        } else {
            Err(format!(
                "Invalid rate value {:?} for property {:?}.",
                value,
                key.as_key()
            ))
        }
    }
}

pub trait AsKey: Clone {
    fn as_key(&self) -> String;
    fn as_prefix(&self) -> String;
}

impl AsKey for &str {
    fn as_key(&self) -> String {
        self.to_string()
    }

    fn as_prefix(&self) -> String {
        format!("{self}.")
    }
}

impl AsKey for String {
    fn as_key(&self) -> String {
        self.to_string()
    }

    fn as_prefix(&self) -> String {
        format!("{self}.")
    }
}

impl AsKey for &String {
    fn as_key(&self) -> String {
        self.to_string()
    }

    fn as_prefix(&self) -> String {
        format!("{self}.")
    }
}

impl AsKey for (&str, &str) {
    fn as_key(&self) -> String {
        format!("{}.{}", self.0, self.1)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.", self.0, self.1)
    }
}

impl AsKey for (&str, &String) {
    fn as_key(&self) -> String {
        format!("{}.{}", self.0, self.1)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.", self.0, self.1)
    }
}

impl AsKey for (&String, &str) {
    fn as_key(&self) -> String {
        format!("{}.{}", self.0, self.1)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.", self.0, self.1)
    }
}

impl AsKey for (&str, &str, &str) {
    fn as_key(&self) -> String {
        format!("{}.{}.{}", self.0, self.1, self.2)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.{}.", self.0, self.1, self.2)
    }
}

impl AsKey for (&str, &str, &str, &str) {
    fn as_key(&self) -> String {
        format!("{}.{}.{}.{}", self.0, self.1, self.2, self.3)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.{}.{}.", self.0, self.1, self.2, self.3)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::config::Config;

    #[test]
    fn toml_utils() {
        let toml = r#"
[queues."z"]
retry = [0, 1, 15, 60, 90]
value = "hi"

[queues."x"]
retry = [3, 60]
value = "hi 2"

[queues.a]
retry = [1, 2, 3, 4]
value = "hi 3"

[servers."my relay"]
hostname = "mx.example.org"

[[servers."my relay".transaction.auth.limits]]
idle = 10

[[servers."my relay".transaction.auth.limits]]
idle = 20

[servers."submissions"]
hostname = "submit.example.org"
ip = "a:b::1:1"
"#;
        let mut config = Config::default();
        config.parse(toml).unwrap();

        assert_eq!(
            config.sub_keys("queues", "").collect::<Vec<_>>(),
            ["a", "x", "z"]
        );
        assert_eq!(
            config.sub_keys("servers", "").collect::<Vec<_>>(),
            ["my relay", "submissions"]
        );
        assert_eq!(
            config.sub_keys("queues.z.retry", "").collect::<Vec<_>>(),
            ["0000", "0001", "0002", "0003", "0004"]
        );
        assert_eq!(
            config
                .property::<u32>("servers.my relay.transaction.auth.limits.0001.idle")
                .unwrap()
                .unwrap(),
            20
        );
        assert_eq!(
            config
                .property::<IpAddr>(("servers", "submissions", "ip"))
                .unwrap()
                .unwrap(),
            "a:b::1:1".parse::<IpAddr>().unwrap()
        );
    }
}
