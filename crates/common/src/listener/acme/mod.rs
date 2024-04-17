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

use std::{fmt::Debug, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use dns_update::DnsUpdater;
use rustls::sign::CertifiedKey;

use crate::Core;

use self::{
    directory::{Account, ChallengeType},
    order::{CertParseError, OrderError},
};

pub struct AcmeProvider {
    pub id: String,
    pub directory_url: String,
    pub domains: Vec<String>,
    pub contact: Vec<String>,
    pub challenge: ChallengeSettings,
    renew_before: chrono::Duration,
    account_key: ArcSwap<Vec<u8>>,
    default: bool,
}

#[derive(Clone)]
pub enum ChallengeSettings {
    Http01,
    TlsAlpn01,
    Dns01 {
        updater: DnsUpdater,
        origin: Option<String>,
        polling_interval: Duration,
        propagation_timeout: Duration,
        ttl: u32,
    },
}

pub struct StaticResolver {
    pub key: Option<Arc<CertifiedKey>>,
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

impl AcmeProvider {
    pub fn new(
        id: String,
        directory_url: String,
        domains: Vec<String>,
        contact: Vec<String>,
        challenge: ChallengeSettings,
        renew_before: Duration,
        default: bool,
    ) -> utils::config::Result<Self> {
        Ok(AcmeProvider {
            id,
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
            domains,
            account_key: Default::default(),
            challenge,
            default,
        })
    }
}

impl Core {
    pub async fn init_acme(&self, provider: &AcmeProvider) -> Result<Duration, AcmeError> {
        // Load account key from cache or generate a new one
        if let Some(account_key) = self.load_account(provider).await? {
            provider.account_key.store(Arc::new(account_key));
        } else {
            let account_key = Account::generate_key_pair();
            self.store_account(provider, &account_key).await?;
            provider.account_key.store(Arc::new(account_key));
        }

        // Load certificate from cache or request a new one
        Ok(if let Some(pem) = self.load_cert(provider).await? {
            self.process_cert(provider, pem, true).await?
        } else {
            Duration::from_millis(1000)
        })
    }

    pub fn has_acme_tls_providers(&self) -> bool {
        self.tls
            .acme_providers
            .values()
            .any(|p| matches!(p.challenge, ChallengeSettings::TlsAlpn01))
    }

    pub fn has_acme_http_providers(&self) -> bool {
        self.tls
            .acme_providers
            .values()
            .any(|p| matches!(p.challenge, ChallengeSettings::Http01))
    }
}

impl ChallengeSettings {
    pub fn challenge_type(&self) -> ChallengeType {
        match self {
            ChallengeSettings::Http01 => ChallengeType::Http01,
            ChallengeSettings::TlsAlpn01 => ChallengeType::TlsAlpn01,
            ChallengeSettings::Dns01 { .. } => ChallengeType::Dns01,
        }
    }
}

impl Debug for StaticResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticResolver").finish()
    }
}

impl Clone for AcmeProvider {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            directory_url: self.directory_url.clone(),
            domains: self.domains.clone(),
            contact: self.contact.clone(),
            challenge: self.challenge.clone(),
            renew_before: self.renew_before,
            account_key: ArcSwap::from_pointee(self.account_key.load().as_ref().clone()),
            default: self.default,
        }
    }
}
