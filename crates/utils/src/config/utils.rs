/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use mail_auth::{
    common::crypto::{Algorithm, HashAlgorithm},
    dkim::Canonicalization,
    IpLookupStrategy,
};
use smtp_proto::MtPriority;

use super::{Config, ConfigError, ConfigWarning, Rate};

impl Config {
    pub fn property<T: ParseValue>(&mut self, key: impl AsKey) -> Option<T> {
        let key = key.as_key();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(key.clone());

        if let Some(value) = self.keys.get(&key) {
            match T::parse_value(value) {
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
        &mut self,
        key: impl AsKey,
        default: &str,
    ) -> Option<T> {
        let key = key.as_key();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(key.clone());

        let value = match self.keys.get(&key) {
            Some(value) => value.as_str(),
            None => default,
        };
        match T::parse_value(value) {
            Ok(value) => Some(value),
            Err(err) => {
                self.new_parse_error(key, err);
                None
            }
        }
    }

    pub fn property_or_else<T: ParseValue>(
        &mut self,
        key: impl AsKey,
        or_else: impl AsKey,
        default: &str,
    ) -> Option<T> {
        let key = key.as_key();
        let value = match self.value_or_else(key.as_str(), or_else.clone()) {
            Some(value) => value,
            None => default,
        };

        match T::parse_value(value) {
            Ok(value) => Some(value),
            Err(err) => {
                self.new_parse_error(key, err);
                None
            }
        }
    }

    pub fn property_require<T: ParseValue>(&mut self, key: impl AsKey) -> Option<T> {
        let key = key.as_key();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(key.clone());

        if let Some(value) = self.keys.get(&key) {
            match T::parse_value(value) {
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

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(prefix.clone());

        self.keys
            .keys()
            .filter_map(move |key| key.strip_prefix(&prefix))
    }

    pub fn properties<T: ParseValue>(&mut self, prefix: impl AsKey) -> Vec<(String, T)> {
        let full_prefix = prefix.as_key();
        let prefix = prefix.as_prefix();
        let mut results = Vec::new();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(prefix.clone());

        for (key, value) in &self.keys {
            if key.starts_with(&prefix) || key == &full_prefix {
                match T::parse_value(value) {
                    Ok(value) => {
                        results.push((key.to_string(), value));
                    }
                    Err(error) => {
                        self.errors
                            .insert(key.to_string(), ConfigError::Parse { error });
                    }
                }
            }
        }

        results
    }

    pub fn value(&self, key: impl AsKey) -> Option<&str> {
        let key = key.as_key();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(key.clone());

        self.keys.get(&key).map(|s| s.as_str())
    }

    pub fn contains_key(&self, key: impl AsKey) -> bool {
        self.keys.contains_key(&key.as_key())
    }

    pub fn value_require(&mut self, key: impl AsKey) -> Option<&str> {
        let key = key.as_key();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(key.clone());

        if let Some(value) = self.keys.get(&key) {
            Some(value.as_str())
        } else {
            self.errors.insert(
                key,
                ConfigError::Parse {
                    error: "Missing property".to_string(),
                },
            );
            None
        }
    }

    pub fn try_parse_value<T: ParseValue>(&mut self, key: impl AsKey, value: &str) -> Option<T> {
        match T::parse_value(value) {
            Ok(value) => Some(value),
            Err(error) => {
                self.errors
                    .insert(key.as_key(), ConfigError::Parse { error });
                None
            }
        }
    }

    pub fn value_or_else(&self, key: impl AsKey, or_else: impl AsKey) -> Option<&str> {
        let key = key.as_key();

        #[cfg(debug_assertions)]
        {
            self.keys_read.lock().insert(key.clone());
            self.keys_read.lock().insert(or_else.clone().as_key());
        }

        self.keys
            .get(&key)
            .or_else(|| self.keys.get(&or_else.as_key()))
            .map(|s| s.as_str())
    }

    pub fn values(&self, prefix: impl AsKey) -> impl Iterator<Item = (&str, &str)> {
        let full_prefix = prefix.as_key();
        let prefix = prefix.as_prefix();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(prefix.clone());

        self.keys.iter().filter_map(move |(key, value)| {
            if key.starts_with(&prefix) || key == &full_prefix {
                (key.as_str(), value.as_str()).into()
            } else {
                None
            }
        })
    }

    pub fn iterate_prefix(&self, prefix: impl AsKey) -> impl Iterator<Item = (&str, &str)> {
        let prefix = prefix.as_prefix();

        #[cfg(debug_assertions)]
        self.keys_read.lock().insert(prefix.clone());

        self.keys
            .iter()
            .filter_map(move |(key, value)| Some((key.strip_prefix(&prefix)?, value.as_str())))
    }

    pub fn values_or_else(
        &self,
        prefix: impl AsKey,
        or_else: impl AsKey,
    ) -> impl Iterator<Item = (&str, &str)> {
        let mut prefix = prefix.as_prefix();

        #[cfg(debug_assertions)]
        {
            self.keys_read.lock().insert(prefix.clone());
            self.keys_read.lock().insert(or_else.clone().as_prefix());
        }

        self.values(if self.keys.keys().any(|k| k.starts_with(&prefix)) {
            prefix.truncate(prefix.len() - 1);
            prefix
        } else {
            or_else.as_key()
        })
    }

    pub fn has_prefix(&self, prefix: impl AsKey) -> bool {
        let prefix = prefix.as_prefix();
        self.keys.keys().any(|k| k.starts_with(&prefix))
    }

    pub fn new_parse_error(&mut self, key: impl AsKey, details: impl Into<String>) {
        self.errors.insert(
            key.as_key(),
            ConfigError::Parse {
                error: details.into(),
            },
        );
    }

    pub fn new_build_error(&mut self, key: impl AsKey, details: impl Into<String>) {
        self.errors.insert(
            key.as_key(),
            ConfigError::Build {
                error: details.into(),
            },
        );
    }

    pub fn new_parse_warning(&mut self, key: impl AsKey, details: impl Into<String>) {
        self.warnings.insert(
            key.as_key(),
            ConfigWarning::Parse {
                error: details.into(),
            },
        );
    }

    pub fn new_build_warning(&mut self, key: impl AsKey, details: impl Into<String>) {
        self.warnings.insert(
            key.as_key(),
            ConfigWarning::Build {
                error: details.into(),
            },
        );
    }

    pub fn new_missing_property(&mut self, key: impl AsKey) {
        self.warnings.insert(key.as_key(), ConfigWarning::Missing);
    }

    #[cfg(debug_assertions)]
    pub fn warn_unread_keys(&mut self) {
        let mut keys = self.keys.clone();

        for key in self.keys_read.lock().iter() {
            if let Some(base_key) = key.strip_suffix('.') {
                keys.remove(base_key);
                keys.retain(|k, _| !k.starts_with(key));
            } else {
                keys.remove(key);
            }
        }

        for (key, value) in keys {
            self.warnings.insert(key, ConfigWarning::Unread { value });
        }
    }
}

pub trait ParseValue: Sized {
    fn parse_value(value: &str) -> super::Result<Self>;
}

impl<T: ParseValue> ParseValue for Option<T> {
    fn parse_value(value: &str) -> super::Result<Self> {
        if !value.is_empty()
            && !value.eq_ignore_ascii_case("false")
            && !value.eq_ignore_ascii_case("disable")
            && !value.eq_ignore_ascii_case("disabled")
            && !value.eq_ignore_ascii_case("never")
            && !value.eq("0")
        {
            T::parse_value(value).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ParseValue for String {
    fn parse_value(value: &str) -> super::Result<Self> {
        Ok(value.to_string())
    }
}

impl ParseValue for u64 {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid integer value {:?}.", value,))
    }
}

impl ParseValue for f64 {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid floating point value {:?}.", value))
    }
}

impl ParseValue for u16 {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid integer value {:?}.", value))
    }
}

impl ParseValue for i16 {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid integer value {:?}.", value))
    }
}

impl ParseValue for u32 {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid integer value {:?}.", value))
    }
}

impl ParseValue for i32 {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid integer value {:?}.", value))
    }
}

impl ParseValue for IpAddr {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IP address value {:?}.", value))
    }
}

impl ParseValue for usize {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid integer value {:?}.", value))
    }
}

impl ParseValue for bool {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid boolean value {:?}.", value))
    }
}

impl ParseValue for Ipv4Addr {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IPv4 value {:?}.", value))
    }
}

impl ParseValue for Ipv6Addr {
    fn parse_value(value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IPv6 value {:?}.", value))
    }
}

impl ParseValue for PathBuf {
    fn parse_value(value: &str) -> super::Result<Self> {
        let path = PathBuf::from(value);

        if path.exists() {
            Ok(path)
        } else {
            Err(format!("Directory {} does not exist.", path.display()))
        }
    }
}

impl ParseValue for MtPriority {
    fn parse_value(value: &str) -> super::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mixer" => Ok(MtPriority::Mixer),
            "stanag4406" => Ok(MtPriority::Stanag4406),
            "nsep" => Ok(MtPriority::Nsep),
            _ => Err(format!("Invalid priority value {:?}.", value)),
        }
    }
}

impl ParseValue for Canonicalization {
    fn parse_value(value: &str) -> super::Result<Self> {
        match value {
            "relaxed" => Ok(Canonicalization::Relaxed),
            "simple" => Ok(Canonicalization::Simple),
            _ => Err(format!("Invalid canonicalization value {:?}.", value)),
        }
    }
}

impl ParseValue for IpLookupStrategy {
    fn parse_value(value: &str) -> super::Result<Self> {
        Ok(match value.to_lowercase().as_str() {
            "ipv4_only" => IpLookupStrategy::Ipv4Only,
            "ipv6_only" => IpLookupStrategy::Ipv6Only,
            //"ipv4_and_ipv6" => IpLookupStrategy::Ipv4AndIpv6,
            "ipv6_then_ipv4" => IpLookupStrategy::Ipv6thenIpv4,
            "ipv4_then_ipv6" => IpLookupStrategy::Ipv4thenIpv6,
            _ => return Err(format!("Invalid IP lookup strategy {:?}.", value)),
        })
    }
}

impl ParseValue for Algorithm {
    fn parse_value(value: &str) -> super::Result<Self> {
        match value {
            "ed25519-sha256" | "ed25519-sha-256" => Ok(Algorithm::Ed25519Sha256),
            "rsa-sha-256" | "rsa-sha256" => Ok(Algorithm::RsaSha256),
            "rsa-sha-1" | "rsa-sha1" => Ok(Algorithm::RsaSha1),
            _ => Err(format!("Invalid algorithm {:?}.", value)),
        }
    }
}

impl ParseValue for HashAlgorithm {
    fn parse_value(value: &str) -> super::Result<Self> {
        match value {
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            "sha-1" | "sha1" => Ok(HashAlgorithm::Sha1),
            _ => Err(format!("Invalid hash algorithm {:?}.", value)),
        }
    }
}

impl ParseValue for Duration {
    fn parse_value(value: &str) -> super::Result<Self> {
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
            _ => return Err(format!("Invalid duration value {:?}.", value)),
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
            .ok_or_else(|| format!("Invalid duration value {:?}.", value))
    }
}

impl ParseValue for Rate {
    fn parse_value(value: &str) -> super::Result<Self> {
        if let Some((requests, period)) = value.split_once('/') {
            Ok(Rate {
                requests: requests
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|r| if r > 0 { Some(r) } else { None })
                    .ok_or_else(|| format!("Invalid rate value {:?}.", value))?,
                period: std::cmp::max(Duration::parse_value(period)?, Duration::from_secs(1)),
            })
        } else if ["false", "none", "unlimited"].contains(&value) {
            Ok(Rate::default())
        } else {
            Err(format!("Invalid rate value {:?}.", value))
        }
    }
}

impl ParseValue for trc::Level {
    fn parse_value(value: &str) -> super::Result<Self> {
        trc::Level::from_str(value).map_err(|err| format!("Invalid log level: {err}"))
    }
}

impl ParseValue for trc::EventType {
    fn parse_value(value: &str) -> super::Result<Self> {
        trc::EventType::try_parse(value).ok_or_else(|| format!("Unknown event type: {value}"))
    }
}

impl ParseValue for () {
    fn parse_value(_: &str) -> super::Result<Self> {
        Ok(())
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
                .unwrap(),
            20
        );
        assert_eq!(
            config
                .property::<IpAddr>(("servers", "submissions", "ip"))
                .unwrap(),
            "a:b::1:1".parse::<IpAddr>().unwrap()
        );
    }
}
