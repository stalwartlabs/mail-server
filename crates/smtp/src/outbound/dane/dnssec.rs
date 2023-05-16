/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use mail_auth::{
    common::{lru::DnsCache, resolver::IntoFqdn},
    trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        error::{ResolveError, ResolveErrorKind},
        proto::{
            error::ProtoErrorKind,
            rr::rdata::tlsa::{CertUsage, Matching, Selector},
        },
        AsyncResolver,
    },
};
use std::sync::Arc;

use crate::core::Resolvers;

use super::{DnssecResolver, Tlsa, TlsaEntry};

impl DnssecResolver {
    pub fn with_capacity(
        config: ResolverConfig,
        options: ResolverOpts,
    ) -> Result<Self, ResolveError> {
        Ok(Self {
            resolver: AsyncResolver::tokio(config, options)?,
        })
    }
}

impl Resolvers {
    pub async fn tlsa_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> mail_auth::Result<Option<Arc<Tlsa>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache.tlsa.get(key.as_ref()) {
            return Ok(Some(value));
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let mut entries = Vec::new();
        let tlsa_lookup = match self.dnssec.resolver.tlsa_lookup(key.as_ref()).await {
            Ok(tlsa_lookup) => tlsa_lookup,
            Err(err) => {
                return match &err.kind() {
                    ResolveErrorKind::Proto(proto_err)
                        if matches!(proto_err.kind(), ProtoErrorKind::RrsigsNotPresent { .. }) =>
                    {
                        Ok(None)
                    }
                    _ => Err(err.into()),
                };
            }
        };

        let mut has_end_entities = false;
        let mut has_intermediates = false;

        for record in tlsa_lookup.as_lookup().record_iter() {
            if let Some(tlsa) = record.data().and_then(|r| r.as_tlsa()) {
                let is_end_entity = match tlsa.cert_usage() {
                    CertUsage::DomainIssued => true,
                    CertUsage::TrustAnchor => false,
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
            }
        }

        Ok(Some(self.cache.tlsa.insert(
            key.into_owned(),
            Arc::new(Tlsa {
                entries,
                has_end_entities,
                has_intermediates,
            }),
            tlsa_lookup.valid_until(),
        )))
    }

    #[cfg(feature = "test_mode")]
    pub fn tlsa_add<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        value: impl Into<Arc<Tlsa>>,
        valid_until: std::time::Instant,
    ) {
        self.cache
            .tlsa
            .insert(key.into_fqdn().into_owned(), value.into(), valid_until);
    }
}
