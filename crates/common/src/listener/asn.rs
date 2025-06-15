/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::IpAddr,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant},
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use mail_auth::common::resolver::ToReverseName;
use store::write::now;
use tokio::sync::Semaphore;

use crate::{Server, config::network::AsnGeoLookupConfig, manager::fetch_resource};

pub struct AsnGeoLookupData {
    pub lock: Semaphore,
    expires: AtomicU64,
    asn: ArcSwap<Data<Arc<AsnData>>>,
    country: ArcSwap<Data<Arc<String>>>,
}

#[derive(Clone, Default, Debug)]
pub struct AsnData {
    pub id: u32,
    pub name: Option<String>,
}

#[derive(Clone, Default, Debug)]
pub struct AsnGeoLookupResult {
    pub asn: Option<Arc<AsnData>>,
    pub country: Option<Arc<String>>,
}

struct Data<T> {
    ip4_ranges: Vec<IpRange<u32, T>>,
    ip6_ranges: Vec<IpRange<u128, T>>,
}

pub struct IpRange<I: Ord, T> {
    pub start: I,
    pub end: I,
    pub data: T,
}

impl Server {
    pub async fn lookup_asn_country(&self, ip: IpAddr) -> AsnGeoLookupResult {
        let mut result = AsnGeoLookupResult::default();

        match &self.core.network.asn_geo_lookup {
            AsnGeoLookupConfig::Resource { .. } if !ip.is_loopback() => {
                let asn_geo = &self.inner.data.asn_geo_data;

                if asn_geo.expires.load(std::sync::atomic::Ordering::Relaxed) <= now()
                    && asn_geo.lock.available_permits() > 0
                {
                    self.refresh_asn_geo_tables();
                }

                result.asn = asn_geo.asn.load().lookup(ip).cloned();
                result.country = asn_geo.country.load().lookup(ip).cloned();
            }
            AsnGeoLookupConfig::Dns {
                zone_ipv4,
                zone_ipv6,
                separator,
                index_asn,
                index_asn_name,
                index_country,
            } if !ip.is_loopback() => {
                let zone = if ip.is_ipv4() { zone_ipv4 } else { zone_ipv6 };
                match self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .txt_raw_lookup(format!("{}.{}.", ip.to_reverse_name(), zone))
                    .await
                    .map(String::from_utf8)
                {
                    Ok(Ok(entry)) => {
                        let mut asn = None;
                        let mut asn_name = None;
                        let mut country = None;

                        for (idx, part) in entry.split(separator).enumerate() {
                            let part = part.trim();
                            if !part.is_empty() {
                                if idx == *index_asn {
                                    asn = part.parse::<u32>().ok();
                                } else if index_asn_name.is_some_and(|i| i == idx) {
                                    asn_name = Some(part.to_string());
                                } else if index_country.is_some_and(|i| i == idx) {
                                    country = Some(part.to_string());
                                }
                            }
                        }

                        if let Some(asn) = asn {
                            result.asn = Some(Arc::new(AsnData {
                                id: asn,
                                name: asn_name,
                            }));
                        }

                        if let Some(country) = country {
                            result.country = Some(Arc::new(country));
                        }
                    }
                    Ok(Err(_)) => {
                        trc::event!(
                            Resource(trc::ResourceEvent::Error),
                            Details = "Failed to UTF-8 decode ASN/Geo data",
                            Hostname = format!("{}.{}.", ip.to_reverse_name(), zone),
                        );
                    }
                    Err(err) => {
                        trc::event!(
                            Resource(trc::ResourceEvent::Error),
                            Details = "Failed to lookup ASN/Geo data",
                            Hostname = format!("{}.{}.", ip.to_reverse_name(), zone),
                            CausedBy = err.to_string()
                        );
                    }
                }
            }
            _ => (),
        }

        result
    }

    fn refresh_asn_geo_tables(&self) {
        let server = self.clone();
        tokio::spawn(async move {
            let asn_geo = &server.inner.data.asn_geo_data;
            let _permit = asn_geo.lock.acquire().await;

            if asn_geo.expires.load(std::sync::atomic::Ordering::Relaxed) > now() {
                return;
            }

            if let AsnGeoLookupConfig::Resource {
                expires,
                timeout,
                max_size,
                asn_resources,
                geo_resources,
                headers,
            } = &server.core.network.asn_geo_lookup
            {
                let mut asn_data = Data::new();
                let mut country_data = Data::new();

                for (is_asn, url) in asn_resources
                    .iter()
                    .map(|url| (true, url))
                    .chain(geo_resources.iter().map(|url| (false, url)))
                {
                    let time = Instant::now();
                    match fetch_resource(url, headers.clone().into(), *timeout, *max_size)
                        .await
                        .map(String::from_utf8)
                    {
                        Ok(Ok(data)) => {
                            let mut has_errors = false;
                            let mut asn_mappings = AHashMap::new();
                            let mut geo_mappings = AHashMap::new();

                            let mut from_ip = None;
                            let mut to_ip = None;
                            let mut asn = None;
                            let mut details = None;

                            let mut in_quote = false;
                            let mut col_num = 0;
                            let mut col_start = 0;
                            let mut line_start = 0;

                            for (idx, ch) in data.char_indices() {
                                match ch {
                                    '"' => in_quote = !in_quote,
                                    ',' | '\n' if !in_quote => {
                                        let column =
                                            data.get(col_start..idx).unwrap_or_default().trim();
                                        match col_num {
                                            0 => from_ip = column.parse::<IpAddr>().ok(),
                                            1 => to_ip = column.parse::<IpAddr>().ok(),
                                            2 if is_asn => asn = column.parse::<u32>().ok(),
                                            2 | 3 => {
                                                let column = column
                                                    .strip_prefix('"')
                                                    .and_then(|s| s.strip_suffix('"'))
                                                    .unwrap_or(column);
                                                if !column.is_empty() || details.is_none() {
                                                    details = Some(column);
                                                }
                                            }
                                            _ => break,
                                        }

                                        if ch == '\n' {
                                            let is_success = match (from_ip, to_ip, asn, details) {
                                                (
                                                    Some(from_ip),
                                                    Some(to_ip),
                                                    Some(asn),
                                                    asn_name,
                                                ) if is_asn => {
                                                    let data = asn_mappings
                                                        .entry(asn)
                                                        .or_insert_with(|| {
                                                            Arc::new(AsnData {
                                                                id: asn,
                                                                name: asn_name.map(String::from),
                                                            })
                                                        })
                                                        .clone();
                                                    asn_data.insert(from_ip, to_ip, data)
                                                }
                                                (Some(from_ip), Some(to_ip), _, Some(code))
                                                    if !is_asn && [2, 3].contains(&code.len()) =>
                                                {
                                                    let code = code.to_uppercase();
                                                    let data = geo_mappings
                                                        .entry(code.clone())
                                                        .or_insert_with(|| Arc::new(code))
                                                        .clone();
                                                    country_data.insert(from_ip, to_ip, data)
                                                }
                                                (None, None, _, _) => true, // Ignore empty rows
                                                _ => false,
                                            };

                                            if !is_success && !has_errors {
                                                trc::event!(
                                                    Resource(trc::ResourceEvent::Error),
                                                    Details = "Invalid ASN/Geo data",
                                                    Url = url.clone(),
                                                    Details = data
                                                        .get(line_start..idx)
                                                        .unwrap_or_default()
                                                        .to_string(),
                                                );
                                                has_errors = true;
                                            }

                                            col_num = 0;
                                            from_ip = None;
                                            to_ip = None;
                                            asn = None;
                                            details = None;
                                            line_start = idx + 1;
                                        } else {
                                            col_num += 1;
                                        }
                                        col_start = idx + 1;
                                    }
                                    _ => {}
                                }
                            }

                            trc::event!(
                                Resource(trc::ResourceEvent::DownloadExternal),
                                Details = "Downloaded ASN/Geo data",
                                Url = url.clone(),
                                Elapsed = time.elapsed()
                            );
                        }
                        Ok(Err(_)) => {
                            trc::event!(
                                Resource(trc::ResourceEvent::Error),
                                Details = "Failed to UTF-8 decode ASN/Geo data",
                                Url = url.clone(),
                            );
                        }
                        Err(err) => {
                            trc::event!(
                                Resource(trc::ResourceEvent::Error),
                                Details = "Failed to download ASN/Geo data",
                                Url = url.clone(),
                                CausedBy = err
                            );
                        }
                    }
                }

                let expires = if !asn_data.is_empty() || !country_data.is_empty() {
                    *expires
                } else {
                    Duration::from_secs(60)
                };

                if !asn_data.is_empty() {
                    asn_geo.asn.store(Arc::new(asn_data.sorted()));
                }
                if !country_data.is_empty() {
                    asn_geo.country.store(Arc::new(country_data.sorted()));
                }

                asn_geo.expires.store(
                    now() + expires.as_secs(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        });
    }
}

impl<T> Data<T> {
    fn new() -> Self {
        Self {
            ip4_ranges: Vec::new(),
            ip6_ranges: Vec::new(),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&T> {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                match self.ip4_ranges.binary_search_by(|range| {
                    if ip < range.start {
                        std::cmp::Ordering::Greater
                    } else if ip > range.end {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                }) {
                    Ok(idx) => Some(&self.ip4_ranges[idx].data),
                    Err(_) => None,
                }
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                match self.ip6_ranges.binary_search_by(|range| {
                    if ip < range.start {
                        std::cmp::Ordering::Greater
                    } else if ip > range.end {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                }) {
                    Ok(idx) => Some(&self.ip6_ranges[idx].data),
                    Err(_) => None,
                }
            }
        }
    }

    pub fn insert(&mut self, from_ip: IpAddr, to_ip: IpAddr, data: T) -> bool {
        match (from_ip, to_ip) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                self.ip4_ranges.push(IpRange {
                    start: u32::from(from),
                    end: u32::from(to),
                    data,
                });
                true
            }
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                self.ip6_ranges.push(IpRange {
                    start: u128::from(from),
                    end: u128::from(to),
                    data,
                });
                true
            }
            _ => false,
        }
    }

    pub fn sorted(mut self) -> Self {
        self.ip4_ranges.sort_unstable_by_key(|range| range.start);
        self.ip6_ranges.sort_unstable_by_key(|range| range.start);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.ip4_ranges.is_empty() && self.ip6_ranges.is_empty()
    }
}

impl Default for AsnGeoLookupData {
    fn default() -> Self {
        Self {
            lock: Semaphore::new(1),
            expires: AtomicU64::new(0),
            asn: ArcSwap::new(Arc::new(Data::new())),
            country: ArcSwap::new(Arc::new(Data::new())),
        }
    }
}
