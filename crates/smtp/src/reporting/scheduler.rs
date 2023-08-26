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

use ahash::{AHashMap, RandomState};
use mail_auth::{
    common::{
        base32::{Base32Reader, Base32Writer},
        headers::Writer,
    },
    dmarc::Dmarc,
};

use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{hash_map::Entry, BinaryHeap},
    hash::Hash,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::mpsc,
};

use crate::{
    config::AggregateFrequency,
    core::{management::ReportRequest, worker::SpawnCleanup, ReportCore, SMTP},
    queue::{InstantFromTimestamp, RecipientDomain, Schedule},
};

use super::{dmarc::GenerateDmarcReport, tls::GenerateTlsReport, Event};

pub type ReportKey = ReportType<ReportPolicy<String>, String>;
pub type ReportValue = ReportType<ReportPath<PathBuf>, ReportPath<Vec<ReportPolicy<PathBuf>>>>;

pub struct Scheduler {
    short_wait: Duration,
    long_wait: Duration,
    pub main: BinaryHeap<Schedule<ReportKey>>,
    pub reports: AHashMap<ReportKey, ReportValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum ReportType<T, U> {
    Dmarc(T),
    Tls(U),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReportPath<T> {
    pub path: T,
    pub size: usize,
    pub created: u64,
    pub deliver_at: AggregateFrequency,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportPolicy<T> {
    pub inner: T,
    pub policy: u64,
}

impl SpawnReport for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<SMTP>, mut scheduler: Scheduler) {
        tokio::spawn(async move {
            let mut last_cleanup = Instant::now();

            loop {
                match tokio::time::timeout(scheduler.wake_up_time(), self.recv()).await {
                    Ok(Some(event)) => match event {
                        Event::Dmarc(event) => {
                            scheduler.schedule_dmarc(event, &core).await;
                        }
                        Event::Tls(event) => {
                            scheduler.schedule_tls(event, &core).await;
                        }
                        Event::Manage(request) => match request {
                            ReportRequest::List {
                                type_,
                                domain,
                                result_tx,
                            } => {
                                let mut result = Vec::new();
                                for key in scheduler.reports.keys() {
                                    if domain
                                        .as_ref()
                                        .map_or(false, |domain| domain != key.domain())
                                    {
                                        continue;
                                    }
                                    if let Some(type_) = &type_ {
                                        if !matches!(
                                            (key, type_),
                                            (ReportType::Dmarc(_), ReportType::Dmarc(_))
                                                | (ReportType::Tls(_), ReportType::Tls(_))
                                        ) {
                                            continue;
                                        }
                                    }
                                    result.push(key.to_string());
                                }
                                let _ = result_tx.send(result);
                            }
                            ReportRequest::Status {
                                report_ids,
                                result_tx,
                            } => {
                                let mut result = Vec::with_capacity(report_ids.len());
                                for report_id in &report_ids {
                                    result.push(
                                        scheduler
                                            .reports
                                            .get(report_id)
                                            .map(|report_value| (report_id, report_value).into()),
                                    );
                                }
                                let _ = result_tx.send(result);
                            }
                            ReportRequest::Cancel {
                                report_ids,
                                result_tx,
                            } => {
                                let mut result = Vec::with_capacity(report_ids.len());
                                for report_id in &report_ids {
                                    result.push(
                                        if let Some(report) = scheduler.reports.remove(report_id) {
                                            report.delete().await;
                                            true
                                        } else {
                                            false
                                        },
                                    );
                                }
                                let _ = result_tx.send(result);
                            }
                        },
                        Event::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => {
                        while let Some(report) = scheduler.next_due() {
                            match report {
                                (ReportType::Dmarc(domain), ReportType::Dmarc(path)) => {
                                    core.generate_dmarc_report(domain, path);
                                }
                                (ReportType::Tls(domain), ReportType::Tls(path)) => {
                                    core.generate_tls_report(domain, path);
                                }
                                _ => unreachable!(),
                            }
                        }

                        // Cleanup expired throttles
                        if last_cleanup.elapsed().as_secs() >= 86400 {
                            last_cleanup = Instant::now();
                            core.spawn_cleanup();
                        }
                    }
                }
            }
        });
    }
}

impl SMTP {
    pub async fn build_report_path(
        &self,
        domain: ReportType<&str, &str>,
        policy: u64,
        created: u64,
        interval: AggregateFrequency,
    ) -> PathBuf {
        let (ext, domain) = match domain {
            ReportType::Dmarc(domain) => ("d", domain),
            ReportType::Tls(domain) => ("t", domain),
        };

        // Build base path
        let mut path = self
            .report
            .config
            .path
            .eval(&RecipientDomain::new(domain))
            .await
            .clone();
        let hash = *self
            .report
            .config
            .hash
            .eval(&RecipientDomain::new(domain))
            .await;
        if hash > 0 {
            path.push((policy % hash).to_string());
        }
        let _ = fs::create_dir(&path).await;

        // Build filename
        let mut w = Base32Writer::with_capacity(domain.len() + 13);
        w.write(&policy.to_le_bytes()[..]);
        w.write(&(created.saturating_sub(946684800) as u32).to_le_bytes()[..]);
        w.push_byte(
            match interval {
                AggregateFrequency::Hourly => 0,
                AggregateFrequency::Daily => 1,
                AggregateFrequency::Weekly => 2,
                AggregateFrequency::Never => 3,
            },
            false,
        );
        w.write(domain.as_bytes());
        let mut file = w.finalize();
        file.push('.');
        file.push_str(ext);
        path.push(file);
        path
    }
}

impl ReportCore {
    pub async fn read_reports(&self) -> Scheduler {
        let mut scheduler = Scheduler::default();

        for path in self
            .config
            .path
            .if_then
            .iter()
            .map(|t| &t.then)
            .chain([&self.config.path.default])
        {
            let mut dir = match tokio::fs::read_dir(path).await {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            loop {
                match dir.next_entry().await {
                    Ok(Some(file)) => {
                        let file = file.path();
                        if file.is_dir() {
                            match tokio::fs::read_dir(&file).await {
                                Ok(mut dir) => {
                                    let file_ = file;
                                    loop {
                                        match dir.next_entry().await {
                                            Ok(Some(file)) => {
                                                let file = file.path();
                                                if file
                                                    .extension()
                                                    .map_or(false, |e| e == "t" || e == "d")
                                                {
                                                    if let Err(err) = scheduler.add_path(file).await
                                                    {
                                                        tracing::warn!("{}", err);
                                                    }
                                                }
                                            }
                                            Ok(None) => break,
                                            Err(err) => {
                                                tracing::warn!(
                                                    "Failed to read report directory {}: {}",
                                                    file_.display(),
                                                    err
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed to read report directory {}: {}",
                                        file.display(),
                                        err
                                    )
                                }
                            };
                        } else if file.extension().map_or(false, |e| e == "t" || e == "d") {
                            if let Err(err) = scheduler.add_path(file).await {
                                tracing::warn!("{}", err);
                            }
                        }
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to read report directory {}: {}",
                            path.display(),
                            err
                        );
                        break;
                    }
                }
            }
        }

        scheduler
    }
}

impl Scheduler {
    pub fn next_due(&mut self) -> Option<(ReportKey, ReportValue)> {
        let item = self.main.peek()?;
        if item.due <= Instant::now() {
            let item = self.main.pop().unwrap();
            self.reports
                .remove(&item.inner)
                .map(|policy| (item.inner, policy))
        } else {
            None
        }
    }

    pub fn wake_up_time(&self) -> Duration {
        self.main
            .peek()
            .map(|item| {
                item.due
                    .checked_duration_since(Instant::now())
                    .unwrap_or(self.short_wait)
            })
            .unwrap_or(self.long_wait)
    }

    pub async fn add_path(&mut self, path: PathBuf) -> Result<(), String> {
        let (file, ext) = path
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|f| f.rsplit_once('.'))
            .ok_or_else(|| format!("Invalid queue file name {}", path.display()))?;
        let file_size = fs::metadata(&path)
            .await
            .map_err(|err| {
                format!(
                    "Failed to obtain file metadata for {}: {}",
                    path.display(),
                    err
                )
            })?
            .len();
        if file_size == 0 {
            let _ = fs::remove_file(&path).await;
            return Err(format!(
                "Removed zero length report file {}",
                path.display()
            ));
        }

        // Decode domain name
        let mut policy = [0u8; std::mem::size_of::<u64>()];
        let mut created = [0u8; std::mem::size_of::<u32>()];
        let mut deliver_at = AggregateFrequency::Never;
        let mut domain = Vec::new();
        for (pos, byte) in Base32Reader::new(file.as_bytes()).enumerate() {
            match pos {
                0..=7 => {
                    policy[pos] = byte;
                }
                8..=11 => {
                    created[pos - 8] = byte;
                }
                12 => {
                    deliver_at = match byte {
                        0 => AggregateFrequency::Hourly,
                        1 => AggregateFrequency::Daily,
                        2 => AggregateFrequency::Weekly,
                        _ => {
                            return Err(format!(
                                "Failed to base32 decode report file {}",
                                path.display()
                            ));
                        }
                    };
                }
                _ => {
                    domain.push(byte);
                }
            }
        }
        if domain.is_empty() {
            return Err(format!(
                "Failed to base32 decode report file {}",
                path.display()
            ));
        }
        let domain = String::from_utf8(domain).map_err(|err| {
            format!(
                "Failed to base32 decode report file {}: {}",
                path.display(),
                err
            )
        })?;

        // Rebuild parts
        let policy = u64::from_le_bytes(policy);
        let created = u32::from_le_bytes(created) as u64 + 946684800;

        match ext {
            "d" => {
                let key = ReportType::Dmarc(ReportPolicy {
                    inner: domain,
                    policy,
                });
                self.reports.insert(
                    key.clone(),
                    ReportType::Dmarc(ReportPath {
                        path,
                        size: file_size as usize,
                        created,
                        deliver_at,
                    }),
                );
                self.main.push(Schedule {
                    due: (created + deliver_at.as_secs()).to_instant(),
                    inner: key,
                });
            }
            "t" => match self.reports.entry(ReportType::Tls(domain)) {
                Entry::Occupied(mut e) => {
                    if let ReportType::Tls(tls) = e.get_mut() {
                        tls.size += file_size as usize;
                        tls.path.push(ReportPolicy {
                            inner: path,
                            policy,
                        });
                    }
                }
                Entry::Vacant(e) => {
                    self.main.push(Schedule {
                        due: (created + deliver_at.as_secs()).to_instant(),
                        inner: e.key().clone(),
                    });
                    e.insert(ReportType::Tls(ReportPath {
                        path: vec![ReportPolicy {
                            inner: path,
                            policy,
                        }],
                        size: file_size as usize,
                        created,
                        deliver_at,
                    }));
                }
            },
            _ => unreachable!(),
        }

        Ok(())
    }
}

pub async fn json_write(path: &PathBuf, entry: &impl Serialize) -> usize {
    if let Ok(bytes) = serde_json::to_vec(entry) {
        // Save serialized report
        let bytes_written = bytes.len() - 2;
        match fs::File::create(&path).await {
            Ok(mut file) => match file.write_all(&bytes[..bytes_written]).await {
                Ok(_) => bytes_written,
                Err(err) => {
                    tracing::error!(
                        context = "report",
                        event = "error",
                        "Failed to write to report file {}: {}",
                        path.display(),
                        err
                    );
                    0
                }
            },
            Err(err) => {
                tracing::error!(
                    context = "report",
                    event = "error",
                    "Failed to create report file {}: {}",
                    path.display(),
                    err
                );
                0
            }
        }
    } else {
        0
    }
}

pub async fn json_append(path: &PathBuf, entry: &impl Serialize, bytes_left: usize) -> usize {
    let mut bytes = Vec::with_capacity(128);
    bytes.push(b',');
    if serde_json::to_writer(&mut bytes, entry).is_ok() && bytes.len() <= bytes_left {
        let err = match OpenOptions::new().append(true).open(&path).await {
            Ok(mut file) => match file.write_all(&bytes).await {
                Ok(_) => return bytes.len(),
                Err(err) => err,
            },
            Err(err) => err,
        };
        tracing::error!(
            context = "report",
            event = "error",
            "Failed to append report to {}: {}",
            path.display(),
            err
        );
    }
    0
}

pub async fn json_read<T: DeserializeOwned>(path: &PathBuf, span: &tracing::Span) -> Option<T> {
    match fs::read_to_string(&path).await {
        Ok(mut json) => {
            json.push_str("]}");
            match serde_json::from_str(&json) {
                Ok(report) => Some(report),
                Err(err) => {
                    tracing::error!(
                        parent: span,
                        context = "deserialize",
                        event = "error",
                        "Failed to deserialize report file {}: {}",
                        path.display(),
                        err
                    );
                    None
                }
            }
        }
        Err(err) => {
            tracing::error!(
                parent: span,
                context = "io",
                event = "error",
                "Failed to read report file {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}

pub fn json_read_blocking<T: DeserializeOwned>(path: &PathBuf, span: &tracing::Span) -> Option<T> {
    match std::fs::read_to_string(path) {
        Ok(mut json) => {
            json.push_str("]}");
            match serde_json::from_str(&json) {
                Ok(report) => Some(report),
                Err(err) => {
                    tracing::error!(
                        parent: span,
                        context = "deserialize",
                        event = "error",
                        "Failed to deserialize report file {}: {}",
                        path.display(),
                        err
                    );
                    None
                }
            }
        }
        Err(err) => {
            tracing::error!(
                parent: span,
                context = "io",
                event = "error",
                "Failed to read report file {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self {
            short_wait: Duration::from_millis(1),
            long_wait: Duration::from_secs(86400 * 365),
            main: BinaryHeap::with_capacity(128),
            reports: AHashMap::with_capacity(128),
        }
    }
}

impl ReportKey {
    pub fn domain_name(&self) -> &str {
        match self {
            ReportType::Dmarc(domain) => domain.inner.as_str(),
            ReportType::Tls(domain) => domain.as_str(),
        }
    }
}

impl ReportValue {
    pub fn dmarc_path(&mut self) -> &mut ReportPath<PathBuf> {
        match self {
            ReportType::Dmarc(path) => path,
            ReportType::Tls(_) => unreachable!(),
        }
    }

    pub fn tls_path(&mut self) -> &mut ReportPath<Vec<ReportPolicy<PathBuf>>> {
        match self {
            ReportType::Tls(path) => path,
            ReportType::Dmarc(_) => unreachable!(),
        }
    }
}

pub trait ToHash {
    fn to_hash(&self) -> u64;
}

impl ToHash for Dmarc {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

impl ToHash for super::PolicyType {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

pub trait ToTimestamp {
    fn to_timestamp(&self) -> u64;
}

impl ToTimestamp for Duration {
    fn to_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + self.as_secs()
    }
}

pub trait SpawnReport {
    fn spawn(self, core: Arc<SMTP>, scheduler: Scheduler);
}
