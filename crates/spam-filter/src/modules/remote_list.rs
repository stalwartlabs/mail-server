use std::{
    collections::HashSet,
    io::{BufRead, BufReader},
    time::Instant,
};

use common::{
    config::{
        scripts::RemoteList,
        spamfilter::{RemoteListConfig, RemoteListFormat},
    },
    HttpLimitResponse, Server, USER_AGENT,
};
use mail_auth::flate2;

pub async fn is_in_remote_list(
    server: &Server,
    config: &RemoteListConfig,
    item: &str,
    span_id: u64,
) -> bool {
    match is_in_remote_list_(server, config, item, span_id).await {
        Ok(result) => result,
        Err(err) => {
            let mut _lock = server.inner.data.remote_lists.write();
            let list = _lock
                .entry(config.id.clone())
                .or_insert_with(|| RemoteList {
                    entries: HashSet::new(),
                    expires: Instant::now(),
                });

            if list.expires > Instant::now() {
                list.entries.contains(item)
            } else {
                list.expires = Instant::now() + config.retry;
                trc::error!(err.span_id(span_id));
                false
            }
        }
    }
}

async fn is_in_remote_list_(
    server: &Server,
    config: &RemoteListConfig,
    item: &str,
    span_id: u64,
) -> trc::Result<bool> {
    #[cfg(feature = "test_mode")]
    {
        if (config.url.contains("open") && item.contains("open"))
            || (config.url.contains("tank") && item.contains("tank"))
        {
            return Ok(true);
        }
    }

    let todo = "update RuntimeError with SpamEvent error";

    match server.inner.data.remote_lists.read().get(&config.id) {
        Some(remote_list) if remote_list.expires < Instant::now() => {
            return Ok(remote_list.entries.contains(item))
        }
        _ => {}
    }

    let response = reqwest::Client::builder()
        .timeout(config.timeout)
        .user_agent(USER_AGENT)
        .build()
        .unwrap_or_default()
        .get(&config.url)
        .send()
        .await
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .ctx(trc::Key::Url, config.url.to_string())
                .details("Failed to build request")
        })?;

    if response.status().is_success() {
        let bytes = response
            .bytes_with_limit(config.max_size)
            .await
            .map_err(|err| {
                trc::SieveEvent::RuntimeError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, config.url.to_string())
                    .details("Failed to fetch resource")
            })?
            .ok_or_else(|| {
                trc::SieveEvent::RuntimeError
                    .into_err()
                    .ctx(trc::Key::Url, config.url.to_string())
                    .details("Resource is too large")
            })?;

        let reader: Box<dyn std::io::Read> = if config.url.ends_with(".gz") {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };

        // Lock remote list for writing
        let mut _lock = server.inner.data.remote_lists.write();
        let list = _lock
            .entry(config.id.to_string())
            .or_insert_with(|| RemoteList {
                entries: HashSet::new(),
                expires: Instant::now(),
            });

        // Make sure that the list is still expired
        if list.expires > Instant::now() {
            return Ok(list.entries.contains(item));
        }

        for (pos, line) in BufReader::new(reader).lines().enumerate() {
            let line_ = line.map_err(|err| {
                trc::SieveEvent::RuntimeError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, config.url.to_string())
                    .details("Failed to read line")
            })?;
            // Clear list once the first entry has been successfully fetched, decompressed and UTF8-decoded
            if pos == 0 {
                list.entries.clear();
            }

            match &config.format {
                RemoteListFormat::List => {
                    let line = line_.trim();
                    if !line.is_empty() {
                        list.entries.insert(line.to_string());
                    }
                }
                RemoteListFormat::Csv {
                    column,
                    separator,
                    skip_first,
                } if pos > 0 || !*skip_first => {
                    let mut in_quote = false;
                    let mut col_num = 0;
                    let mut entry = String::new();

                    for ch in line_.chars() {
                        if ch != '"' {
                            if ch == *separator && !in_quote {
                                if col_num == *column {
                                    break;
                                } else {
                                    col_num += 1;
                                }
                            } else if col_num == *column {
                                entry.push(ch);
                                if entry.len() > config.max_entry_size {
                                    break;
                                }
                            }
                        } else {
                            in_quote = !in_quote;
                        }
                    }

                    if !entry.is_empty() {
                        list.entries.insert(entry);
                    }
                }
                _ => (),
            }

            if list.entries.len() == config.max_entries {
                break;
            }
        }

        trc::event!(
            Spam(trc::SpamEvent::ListUpdated),
            Url = config.url.to_string(),
            Total = list.entries.len(),
            SpanId = span_id
        );

        // Update expiration
        list.expires = Instant::now() + config.refresh;
        Ok(list.entries.contains(item))
    } else {
        trc::bail!(trc::SieveEvent::RuntimeError
            .into_err()
            .ctx(trc::Key::Code, response.status().as_u16())
            .ctx(trc::Key::Url, config.url.to_string())
            .details("Failed to fetch remote list"));
    }
}
