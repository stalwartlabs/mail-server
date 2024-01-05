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

pub mod cache;
pub mod directory;
pub mod jose;
pub mod order;
pub mod resolver;

use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustls::sign::CertifiedKey;
use tokio::sync::watch;

use crate::config::tls::build_self_signed_cert;

use self::{
    directory::Account,
    order::{CertParseError, OrderError},
};

pub struct AcmeManager {
    pub(crate) directory_url: String,
    pub(crate) domains: Vec<String>,
    contact: Vec<String>,
    renew_before: chrono::Duration,
    cache_path: PathBuf,
    account_key: ArcSwap<Vec<u8>>,
    auth_keys: Mutex<AHashMap<String, Arc<CertifiedKey>>>,
    order_in_progress: AtomicBool,
    cert: ArcSwap<CertifiedKey>,
}

#[derive(Debug)]
pub enum AcmeError {
    CertCacheLoad(std::io::Error),
    AccountCacheLoad(std::io::Error),
    CertCacheStore(std::io::Error),
    AccountCacheStore(std::io::Error),
    CachedCertParse(CertParseError),
    Order(OrderError),
    NewCertParse(CertParseError),
}

impl AcmeManager {
    pub fn new(
        directory_url: String,
        domains: Vec<String>,
        contact: Vec<String>,
        renew_before: Duration,
        cache_path: PathBuf,
    ) -> crate::config::Result<Self> {
        Ok(AcmeManager {
            directory_url,
            contact: contact
                .into_iter()
                .map(|c| {
                    if !c.starts_with("mailto:") {
                        format!("mailto:{}", c)
                    } else {
                        c
                    }
                })
                .collect(),
            renew_before: chrono::Duration::from_std(renew_before).unwrap(),
            cache_path,
            account_key: ArcSwap::from_pointee(Vec::new()),
            auth_keys: Mutex::new(AHashMap::new()),
            order_in_progress: false.into(),
            cert: ArcSwap::from_pointee(build_self_signed_cert(&domains)?),
            domains,
        })
    }

    pub async fn init(&self) -> Result<Duration, AcmeError> {
        // Load account key from cache or generate a new one
        if let Some(account_key) = self.load_account().await? {
            self.account_key.store(Arc::new(account_key));
        } else {
            let account_key = Account::generate_key_pair();
            self.store_account(&account_key).await?;
            self.account_key.store(Arc::new(account_key));
        }

        // Load certificate from cache or request a new one
        Ok(if let Some(pem) = self.load_cert().await? {
            self.process_cert(pem, true).await?
        } else {
            Duration::from_millis(1000)
        })
    }

    pub fn has_order_in_progress(&self) -> bool {
        self.order_in_progress.load(Ordering::Relaxed)
    }
}

pub trait SpawnAcme {
    fn spawn(self, shutdown_rx: watch::Receiver<bool>);
}

impl SpawnAcme for Arc<AcmeManager> {
    fn spawn(self, mut shutdown_rx: watch::Receiver<bool>) {
        tokio::spawn(async move {
            let acme = self;
            let mut renew_at = match acme.init().await {
                Ok(renew_at) => renew_at,
                Err(err) => {
                    tracing::error!(
                        context = "acme",
                        event = "error",
                        error = ?err,
                        "Failed to initialize ACME certificate manager.");

                    return;
                }
            };

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(renew_at) => {
                        tracing::info!(
                            context = "acme",
                            event = "order",
                            domains = ?acme.domains,
                            "Ordering certificates.");

                        match acme.renew().await {
                            Ok(renew_at_) => {
                                renew_at = renew_at_;
                                tracing::info!(
                                    context = "acme",
                                    event = "success",
                                    domains = ?acme.domains,
                                    next_renewal = ?renew_at,
                                    "Certificates renewed.");
                            },
                            Err(err) => {
                                tracing::error!(
                                    context = "acme",
                                    event = "error",
                                    error = ?err,
                                    "Failed to renew certificates.");

                                renew_at = Duration::from_secs(3600);
                            },
                        }

                    },
                    _ = shutdown_rx.changed() => {
                        tracing::debug!(
                            context = "acme",
                            event = "shutdown",
                            domains = ?acme.domains,
                            "ACME certificate manager shutting down.");

                        break;
                    }
                };
            }
        });
    }
}

impl Debug for AcmeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeManager")
            .field("directory_url", &self.directory_url)
            .field("domains", &self.domains)
            .field("contact", &self.contact)
            .field("cache_path", &self.cache_path)
            .field("account_key", &self.account_key)
            .finish()
    }
}
