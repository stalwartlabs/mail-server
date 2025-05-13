/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Read;

use ahash::AHashSet;
use mail_auth::flate2::read::GzDecoder;

use crate::config::Config;

#[derive(Debug, Clone, Default)]
pub struct PublicSuffix {
    pub suffixes: AHashSet<String>,
    pub exceptions: AHashSet<String>,
    pub wildcards: Vec<String>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DomainPart {
    Sld,
    Tld,
    Host,
}

impl PublicSuffix {
    pub fn contains(&self, suffix: &str) -> bool {
        self.suffixes.contains(suffix)
            || (!self.exceptions.contains(suffix)
                && self.wildcards.iter().any(|w| suffix.ends_with(w)))
    }

    pub fn domain_part(&self, domain: &str, part: DomainPart) -> Option<String> {
        let d = domain.trim().to_lowercase();
        let mut seen_dot = false;
        for (pos, ch) in d.as_bytes().iter().enumerate().rev() {
            if *ch == b'.' {
                if seen_dot {
                    let maybe_domain =
                        std::str::from_utf8(&d.as_bytes()[pos + 1..]).unwrap_or_default();
                    if !self.contains(maybe_domain) {
                        return if part == DomainPart::Sld {
                            maybe_domain
                        } else {
                            std::str::from_utf8(&d.as_bytes()[..pos]).unwrap_or_default()
                        }
                        .to_string()
                        .into();
                    }
                } else if part == DomainPart::Tld {
                    return std::str::from_utf8(&d.as_bytes()[pos + 1..])
                        .unwrap_or_default()
                        .to_string()
                        .into();
                } else {
                    seen_dot = true;
                }
            }
        }

        if seen_dot {
            if part == DomainPart::Sld {
                d.into()
            } else {
                None
            }
        } else if part == DomainPart::Host {
            d.into()
        } else {
            None
        }
    }
}

impl From<&str> for PublicSuffix {
    fn from(list: &str) -> Self {
        let mut ps = PublicSuffix::default();
        for line in list.lines() {
            let line = line.trim().to_lowercase();
            if !line.starts_with("//") {
                if let Some(domain) = line.strip_prefix('*') {
                    ps.wildcards.push(domain.to_string());
                } else if let Some(domain) = line.strip_prefix('!') {
                    ps.exceptions.insert(domain.to_string());
                } else {
                    ps.suffixes.insert(line.to_string());
                }
            }
        }
        ps.suffixes.insert("onion".to_string());
        ps
    }
}

impl PublicSuffix {
    #[allow(unused_variables)]
    pub async fn parse(config: &mut Config, key: &str) -> PublicSuffix {
        let mut values = config
            .values(key)
            .map(|(_, s)| s.to_string())
            .collect::<Vec<_>>();
        if values.is_empty() {
            values = vec![
                "https://publicsuffix.org/list/public_suffix_list.dat".to_string(),
                "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
                    .to_string(),
            ]
        }

        for (idx, value) in values.into_iter().enumerate() {
            let bytes = if value.starts_with("https://") || value.starts_with("http://") {
                let result = match reqwest::get(&value).await {
                    Ok(r) => {
                        if r.status().is_success() {
                            r.bytes().await
                        } else {
                            config.new_build_warning(
                                format!("{value}.{idx}"),
                                format!(
                                    "Failed to fetch public suffixes from {value:?}: Status {status}",
                                    value = value,
                                    status = r.status()
                                ),
                            );
                            continue;
                        }
                    }
                    Err(err) => Err(err),
                };

                match result {
                    Ok(bytes) => bytes.to_vec(),
                    Err(err) => {
                        config.new_build_warning(
                            format!("{value}.{idx}"),
                            format!("Failed to fetch public suffixes from {value:?}: {err}",),
                        );
                        continue;
                    }
                }
            } else if let Some(filename) = value.strip_prefix("file://") {
                match std::fs::read(filename) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        config.new_build_warning(
                            format!("{value}.{idx}"),
                            format!("Failed to read public suffixes from {value:?}: {err}",),
                        );
                        continue;
                    }
                }
            } else {
                config.new_parse_error(key, format!("Invalid public suffix file {value:?}"));
                continue;
            };
            let bytes = if value.ends_with(".gz") {
                match GzDecoder::new(&bytes[..])
                    .bytes()
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        config.new_build_warning(
                            format!("{value}.{idx}"),
                            format!(
                                "Failed to decompress public suffixes from {value:?}: {err}",
                                value = value,
                                err = err
                            ),
                        );
                        continue;
                    }
                }
            } else {
                bytes
            };

            match String::from_utf8(bytes) {
                Ok(list) => {
                    return PublicSuffix::from(list.as_str());
                }
                Err(err) => {
                    config.new_build_warning(
                        format!("{value}.{idx}"),
                        format!(
                            "Failed to parse public suffixes from {value:?}: {err}",
                            value = value,
                            err = err
                        ),
                    );
                }
            }
        }

        #[cfg(not(feature = "test_mode"))]
        config.new_build_warning(key, "Failed to parse public suffixes from any source.");

        PublicSuffix::default()
    }
}
