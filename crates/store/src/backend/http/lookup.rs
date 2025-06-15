/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::{BufRead, BufReader},
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use ahash::AHashMap;
use compact_str::ToCompactString;
use rand::seq::IndexedRandom;
use utils::HttpLimitResponse;

use crate::{Value, backend::http::HttpStoreFormat, write::now};

use super::HttpStore;

const BROWSER_USER_AGENTS: [&str; 5] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

pub(crate) trait HttpStoreGet {
    fn get(&self, key: &str) -> Option<Value<'static>>;
    fn contains(&self, key: &str) -> bool;
    fn refresh(&self);
}

impl HttpStoreGet for Arc<HttpStore> {
    fn get(&self, key: &str) -> Option<Value<'static>> {
        self.refresh();
        self.entries.load().get(key).cloned()
    }

    fn contains(&self, key: &str) -> bool {
        #[cfg(feature = "test_mode")]
        {
            if self.config.url.contains("phishtank.com")
                || self.config.url.contains("openphish.com")
            {
                return (self.config.url.contains("open") && key.contains("open"))
                    || (self.config.url.contains("tank") && key.contains("tank"));
            } else if self.config.url.contains("disposable.github.io") {
                return key.ends_with("guerrillamail.com") || key.ends_with("disposable.org");
            } else if self.config.url.contains("free_email_provider_domains.txt") {
                return key.ends_with("gmail.com")
                    || key.ends_with("googlemail.com")
                    || key.ends_with("yahoomail.com")
                    || key.ends_with("outlook.com")
                    || key.ends_with("freemail.org");
            }
        }

        self.refresh();
        self.entries.load().contains_key(key)
    }

    fn refresh(&self) {
        if self.expires.load(Ordering::Relaxed) <= now() {
            let in_flight = self.in_flight.swap(true, Ordering::Relaxed);
            if !in_flight {
                let this = self.clone();
                tokio::spawn(async move {
                    let expires = match this.try_refresh().await {
                        Ok(list) => {
                            this.entries.store(list.into());
                            this.config.refresh
                        }
                        Err(err) => {
                            trc::error!(err);
                            this.config.retry
                        }
                    };

                    this.expires.store(now() + expires, Ordering::Relaxed);
                    this.in_flight.store(false, Ordering::Relaxed);
                });
            }
        }
    }
}

impl HttpStore {
    async fn try_refresh(&self) -> trc::Result<AHashMap<String, Value<'static>>> {
        let time = Instant::now();
        let agent = BROWSER_USER_AGENTS.choose(&mut rand::rng()).unwrap();
        let response = reqwest::Client::builder()
            .timeout(self.config.timeout)
            .user_agent(*agent)
            .build()
            .unwrap_or_default()
            .get(&self.config.url)
            .send()
            .await
            .map_err(|err| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .details("Failed to build request")
            })?;

        if !response.status().is_success() {
            trc::bail!(
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .ctx(trc::Key::Code, response.status().as_u16())
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Failed to fetch HTTP list")
            );
        }

        let bytes = response
            .bytes_with_limit(self.config.max_size)
            .await
            .map_err(|err| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Failed to fetch resource")
            })?
            .ok_or_else(|| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Resource is too large")
            })?;

        let reader: Box<dyn std::io::Read + Sync + Send> = if self.config.gzipped {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };

        let mut entries = AHashMap::new();
        for (pos, line) in BufReader::new(reader).lines().enumerate() {
            let line_ = line.map_err(|err| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Failed to read line")
            })?;

            match &self.config.format {
                HttpStoreFormat::List => {
                    let line = line_.trim();
                    if !line.is_empty() {
                        entries.insert(line.to_string(), Value::Integer(1));
                    }
                }
                HttpStoreFormat::Csv {
                    index_key,
                    index_value,
                    separator,
                    skip_first,
                } if pos > 0 || !*skip_first => {
                    let mut in_quote = false;
                    let mut col_num = 0;
                    let mut last_ch = ' ';

                    let mut entry_key: String = String::new();
                    let mut entry_value: String = String::new();

                    for ch in line_.chars() {
                        match ch {
                            '"' if last_ch != '\\' => {
                                in_quote = !in_quote;
                            }
                            '\\' if last_ch != '\\' => (),
                            _ => {
                                if ch == *separator && !in_quote {
                                    if col_num == *index_key && index_value.is_none() {
                                        break;
                                    } else {
                                        col_num += 1;
                                    }
                                } else if col_num == *index_key {
                                    entry_key.push(ch);
                                    if entry_key.len() > self.config.max_entry_size {
                                        break;
                                    }
                                } else if index_value.is_some_and(|v| col_num == v) {
                                    entry_value.push(ch);
                                    if entry_value.len() > self.config.max_entry_size {
                                        break;
                                    }
                                }
                            }
                        }

                        last_ch = ch;
                    }

                    if !entry_key.is_empty() {
                        let entry_value = if !entry_value.is_empty() {
                            Value::Text(entry_value.into())
                        } else {
                            Value::Integer(1)
                        };
                        entries.insert(entry_key, entry_value);
                    }
                }
                _ => (),
            }

            if entries.len() == self.config.max_entries {
                break;
            }
        }

        trc::event!(
            Store(trc::StoreEvent::HttpStoreFetch),
            Url = self.config.url.to_compact_string(),
            Total = entries.len(),
            Elapsed = time.elapsed(),
        );

        Ok(entries)
    }
}
