/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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

use self::directory::{Account, ChallengeType};

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

impl AcmeProvider {
    pub fn new(
        id: String,
        directory_url: String,
        domains: Vec<String>,
        contact: Vec<String>,
        challenge: ChallengeSettings,
        renew_before: Duration,
        default: bool,
    ) -> trc::Result<Self> {
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
    pub async fn init_acme(&self, provider: &AcmeProvider) -> trc::Result<Duration> {
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
