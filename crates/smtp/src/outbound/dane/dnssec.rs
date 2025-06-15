/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::smtp::resolver::{Tlsa, TlsaEntry},
};
use mail_auth::{
    common::resolver::IntoFqdn,
    hickory_resolver::{
        Name,
        proto::rr::rdata::tlsa::{CertUsage, Matching, Selector},
    },
};
use std::{future::Future, sync::Arc};

pub trait TlsaLookup: Sync + Send {
    fn tlsa_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x> + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<Option<Arc<Tlsa>>>> + Send;
}

impl TlsaLookup for Server {
    async fn tlsa_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x> + Sync + Send,
    ) -> mail_auth::Result<Option<Arc<Tlsa>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.inner.cache.dns_tlsa.get(key.as_ref()) {
            return Ok(Some(value));
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let mut entries = Vec::new();
        let tlsa_lookup = self
            .core
            .smtp
            .resolvers
            .dnssec
            .resolver
            .tlsa_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;

        let mut has_end_entities = false;
        let mut has_intermediates = false;
        let mut found_insecure = false;

        for record in tlsa_lookup.as_lookup().record_iter() {
            if let Some(tlsa) = record.data().as_tlsa() {
                if record.proof().is_secure() {
                    let is_end_entity = match tlsa.cert_usage() {
                        CertUsage::DaneEe => true,
                        CertUsage::DaneTa => false,
                        _ => continue,
                    };
                    if is_end_entity {
                        has_end_entities = true;
                    } else {
                        has_intermediates = true;
                    }
                    entries.push(TlsaEntry {
                        is_end_entity,
                        is_sha256: match tlsa.matching() {
                            Matching::Sha256 => true,
                            Matching::Sha512 => false,
                            _ => continue,
                        },
                        is_spki: match tlsa.selector() {
                            Selector::Spki => true,
                            Selector::Full => false,
                            _ => continue,
                        },
                        data: tlsa.cert_data().to_vec(),
                    });
                } else {
                    found_insecure = true;
                }
            }
        }

        if !entries.is_empty() || !found_insecure {
            let tlsa = Arc::new(Tlsa {
                entries,
                has_end_entities,
                has_intermediates,
            });

            self.inner.cache.dns_tlsa.insert_with_expiry(
                key.into_owned(),
                tlsa.clone(),
                tlsa_lookup.valid_until(),
            );

            Ok(Some(tlsa))
        } else {
            Ok(None)
        }
    }
}
